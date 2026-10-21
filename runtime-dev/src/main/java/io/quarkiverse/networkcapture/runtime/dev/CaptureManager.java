package io.quarkiverse.networkcapture.runtime.dev;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.jboss.logging.Logger;

import io.quarkiverse.networkcapture.ApplicationTrafficFilter;
import io.quarkiverse.networkcapture.Capture;
import io.quarkiverse.networkcapture.CaptureException;
import io.quarkiverse.networkcapture.CaptureHandle;
import io.quarkiverse.networkcapture.CaptureInterface;
import io.quarkiverse.networkcapture.CaptureInterfaces;
import io.quarkiverse.networkcapture.CaptureOptions;
import io.quarkiverse.networkcapture.CapturePermissionException;
import io.quarkiverse.networkcapture.CaptureSession;
import io.quarkiverse.networkcapture.PacketFilter;
import io.quarkiverse.networkcapture.internal.decode.HttpRequestFilter;
import io.quarkiverse.networkcapture.internal.decode.TransportSegment;

/**
 * Holds the one capture session of the application. It is a static singleton rather than a CDI bean so that a
 * running capture survives dev mode restarts, which lets you capture the restart itself.
 */
public final class CaptureManager {

    private static final Logger LOG = Logger.getLogger(CaptureManager.class);

    public static final CaptureManager INSTANCE = new CaptureManager();

    private CaptureSession session;
    private ApplicationTrafficFilter applicationFilter;
    private Map<String, String> skipped = Map.of();
    private PacketRows rows;

    private CaptureManager() {
        // A live reload restarts the application inside the same JVM and must not stop the capture, so the
        // application's own shutdown events are of no use; only the JVM's exit is, and it ends the capture cleanly
        // so that the packets still held in the queue reach the file.
        Runtime.getRuntime().addShutdownHook(new Thread(this::stop, "network-capture-shutdown"));
    }

    // The rows of the running or last capture for the live list, after packet number after.
    public Messages.PacketBatch rows(long after, boolean hideDevUi, int max) {
        PacketRows current;
        boolean running;
        synchronized (this) {
            current = rows;
            running = isRunning();
        }
        return current == null ? new Messages.PacketBatch(running, 0, List.of()) : current.since(after, hideDevUi, max, running);
    }

    /**
     * Starts a capture on every interface that is up. Which interface carries the application's traffic depends on
     * the peer (loopback, a container bridge, the LAN), so all of them are captured and the filters decide.
     * Interfaces that cannot be opened for a reason other than privilege are skipped and reported in the status.
     *
     * @param applicationOnly keep only packets to or from a socket of this process
     * @param excludeDevUi leave out the Dev UI's websocket connections
     * @param names the interfaces to capture on, by name; empty for every interface that is up
     * @throws CapturePermissionException when the direct open was refused and the options name no elevation
     */
    public synchronized void start(CaptureOptions options, Path directory, boolean applicationOnly, boolean excludeDevUi,
            List<String> names) {
        if (session != null && session.isRunning()) {
            throw new CaptureException("A capture is already running");
        }
        List<CaptureInterface> interfaces = names.isEmpty() ? CaptureInterfaces.listUp() : select(names);
        if (interfaces.isEmpty()) {
            throw new CaptureException("No network interface is up");
        }
        Capture.Result opened = Capture.open(interfaces, options);
        List<CaptureHandle> handles = opened.handles();
        skipped = opened.skipped();
        try {
            Files.createDirectories(directory);
        } catch (IOException e) {
            handles.forEach(CaptureHandle::close);
            throw new UncheckedIOException(e);
        }
        Path file = CaptureSession.defaultFile(directory);
        PacketFilter filter = null;
        if (applicationOnly) {
            applicationFilter = ApplicationTrafficFilter.forCurrentProcess();
            filter = applicationFilter;
        }
        if (excludeDevUi) {
            // the Dev UI's websocket connections, and its HTTP exchanges on connections shared with the application
            PacketFilter notDevUiWebSocket = packet -> {
                TransportSegment segment = TransportSegment.of(packet.linkType(), packet.packet().data());
                return segment == null || !segment.tcp()
                        || !DevUiConnections.isDevUiConnection(segment.sourcePort(), segment.destinationPort());
            };
            PacketFilter notDevUi = notDevUiWebSocket.and(new HttpRequestFilter(DevUiConnections::isDevUiPath));
            filter = filter == null ? notDevUi : filter.and(notDevUi);
        }
        session = CaptureSession.start(handles, file, filter);
        rows = new PacketRows(session.startedAt());
        session.addListener(rows);
        LOG.infof("Capture started on %s, writing to %s%s",
                handles.stream().map(h -> h.networkInterface().name()).collect(Collectors.joining(", ")), file,
                skipped.isEmpty() ? "" : "; not opened: " + skipped);
    }

    // The named interfaces, in the OS's order. A name the OS does not report is an error rather than skipped, since
    // it is most likely a typo and the capture would silently miss what the user asked for.
    private static List<CaptureInterface> select(List<String> names) {
        List<CaptureInterface> all = CaptureInterfaces.list();
        List<String> unknown = names.stream().filter(n -> all.stream().noneMatch(i -> i.name().equals(n))).toList();
        if (!unknown.isEmpty()) {
            throw new CaptureException("No such network interface: " + String.join(", ", unknown));
        }
        return all.stream().filter(i -> names.contains(i.name())).toList();
    }

    public synchronized void stop() {
        if (session != null && session.isRunning()) {
            session.stop();
            LOG.infof("Capture stopped after %d packets: %s",
                    session.stats().stream().mapToLong(CaptureSession.InterfaceStats::packets).sum(), session.file());
        }
    }

    public synchronized boolean isRunning() {
        return session != null && session.isRunning();
    }

    public synchronized Messages.CaptureStatus status() {
        if (session == null) {
            return Messages.CaptureStatus.NONE;
        }
        List<Messages.InterfaceStatus> interfaces = new ArrayList<>();
        long packets = 0;
        long bytes = 0;
        long filtered = 0;
        long dropped = 0;
        for (CaptureSession.InterfaceStats i : session.stats()) {
            interfaces.add(new Messages.InterfaceStatus(i.name(), i.packets(), i.bytes(), i.filtered(), i.error()));
            packets += i.packets();
            bytes += i.bytes();
            filtered += i.filtered();
            dropped += i.dropped();
        }
        return new Messages.CaptureStatus(isRunning(), session.file().toAbsolutePath().toString(),
                session.file().getFileName().toString(), session.startedAt().toString(), packets, bytes, filtered, dropped,
                applicationFilter == null ? null : applicationFilter.error(), skipped, interfaces);
    }


    public List<Messages.CaptureFile> files(Path directory) {
        if (!Files.isDirectory(directory)) {
            return List.of();
        }
        List<Messages.CaptureFile> files = new ArrayList<>();
        try (Stream<Path> stream = Files.list(directory)) {
            for (Path p : stream.filter(p -> p.getFileName().toString().endsWith(".pcapng")).toList()) {
                files.add(new Messages.CaptureFile(p.getFileName().toString(), Files.size(p),
                        Files.getLastModifiedTime(p).toInstant().toString()));
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        files.sort((a, b) -> b.modified().compareTo(a.modified()));
        return files;
    }

    // Resolves a capture file name inside directory, refusing anything that is not a plain file name.
    public static Path resolveFile(Path directory, String name) {
        if (name == null || name.isEmpty() || name.contains("/") || name.contains("\\") || name.startsWith(".")) {
            throw new IllegalArgumentException("Invalid capture file name");
        }
        return directory.resolve(name);
    }

    public synchronized boolean delete(Path directory, String name) {
        Path file = resolveFile(directory, name);
        if (isRunning() && session.file().toAbsolutePath().equals(file.toAbsolutePath())) {
            throw new CaptureException("Cannot delete the file of the running capture");
        }
        try {
            return Files.deleteIfExists(file);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
