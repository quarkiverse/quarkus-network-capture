package io.quarkiverse.networkcapture.runtime.dev;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Hides credentials in the rows handed to the Dev MCP {@code packets} tool, whose output goes into an AI agent's
 * conversation: the values of sensitive HTTP headers, and the values of sensitive query parameters wherever a URL
 * appears (the request line, the summary, the exchange, and headers such as {@code Location} and {@code Referer}).
 * What helps debugging is kept: the scheme of an authorization header, since "Bearer" or "Basic" is often what a
 * failing call is about, and the names and attributes of cookies. Bodies are not redacted.
 */
final class Redaction {

    static final String REDACTED = "[redacted]";

    private static final Set<String> KEEP_SCHEME = Set.of("authorization", "proxy-authorization");

    private final Set<String> headers;
    private final Pattern parameters;

    Redaction(List<String> headers, List<String> parameters) {
        this.headers = names(headers);
        Set<String> names = names(parameters);
        // a parameter after ? or & (or ; in old style URLs), or first in the fragment, where the OAuth implicit flow
        // puts the access token; its value runs up to the next separator, the fragment or white space
        this.parameters = names.isEmpty() ? null
                : Pattern.compile("([?&;#](?:" + names.stream().map(Pattern::quote).collect(Collectors.joining("|"))
                        + ")=)[^&;#\\s]*", Pattern.CASE_INSENSITIVE);
    }

    private static Set<String> names(List<String> names) {
        return names.stream().map(n -> n.trim().toLowerCase(Locale.ROOT)).filter(n -> !n.isEmpty())
                .filter(n -> !n.equals("none")).collect(Collectors.toUnmodifiableSet());
    }

    Messages.PacketRow apply(Messages.PacketRow row) {
        if (headers.isEmpty() && parameters == null) {
            return row;
        }
        Messages.HttpDetails http = switch (row.http()) {
            case Messages.MessageDetails m -> new Messages.MessageDetails(m.request(), m.method(), url(m.url()),
                    url(m.target()), m.version(), m.status(), m.reason(), m.headers().stream().map(this::header).toList(),
                    m.bodyBytes(), m.contentLength(), m.bodyComplete(), m.bodyText(), m.bodyTextTruncated());
            case Messages.BodyPartDetails b -> new Messages.BodyPartDetails(b.bodyPart(), url(b.message()), b.chunked(),
                    b.offset(), b.total(), b.last(), b.remaining(), b.bodyBytes(), b.bodyText(), b.bodyTextTruncated());
            case null -> null;
        };
        Messages.ExchangeRef x = row.exchange();
        Messages.ExchangeRef exchange = x == null ? null
                : new Messages.ExchangeRef(x.id(), url(x.request()), x.isRequest(), x.requestNo());
        return new Messages.PacketRow(row.no(), row.time(), row.interfaceName(), row.source(), row.destination(),
                row.protocol(), row.length(), url(row.info()), http, row.tls(), exchange, row.devUi());
    }

    // The text with the values of sensitive query parameters replaced.
    String url(String text) {
        if (parameters == null || text == null) {
            return text;
        }
        return parameters.matcher(text).replaceAll("$1" + Matcher.quoteReplacement(REDACTED));
    }

    private Messages.Header header(Messages.Header header) {
        String name = header.name().toLowerCase(Locale.ROOT);
        String value = header.value().trim();
        if (!headers.contains(name)) {
            return new Messages.Header(header.name(), url(header.value()));
        }
        String redacted = switch (name) {
            case "cookie" -> cookies(value, "; ");
            case "set-cookie" -> setCookie(value);
            default -> {
                int space = value.indexOf(' ');
                yield KEEP_SCHEME.contains(name) && space > 0 ? value.substring(0, space) + " " + REDACTED : REDACTED;
            }
        };
        return new Messages.Header(header.name(), redacted);
    }

    // "a=1; b=2" becomes "a=[redacted]; b=[redacted]"
    private static String cookies(String value, String separator) {
        return Arrays.stream(value.split(";")).map(String::trim).filter(c -> !c.isEmpty())
                .map(c -> c.contains("=") ? c.substring(0, c.indexOf('=')) + "=" + REDACTED : REDACTED)
                .collect(Collectors.joining(separator));
    }

    // "id=abc; Path=/; HttpOnly" becomes "id=[redacted]; Path=/; HttpOnly": only the first pair is the cookie
    private static String setCookie(String value) {
        int semicolon = value.indexOf(';');
        String cookie = semicolon < 0 ? value : value.substring(0, semicolon);
        return cookies(cookie, "; ") + (semicolon < 0 ? "" : value.substring(semicolon));
    }
}
