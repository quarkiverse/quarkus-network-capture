import { QwcHotReloadElement, html, css } from 'qwc-hot-reload-element';
import { JsonRpc } from 'jsonrpc';
import '@vaadin/button';
import '@vaadin/checkbox';
import '@vaadin/grid';
import '@vaadin/icon';
import '@vaadin/multi-select-combo-box';
import '@vaadin/progress-bar';
import 'qui-alert';
import { columnBodyRenderer } from '@vaadin/grid/lit.js';
import './qwc-network-capture-packets.js';

/**
 * The capture page: start and stop, status, the files, and the two streams (status and packets) that feed the
 * packet list component.
 */
export class QwcNetworkCapture extends QwcHotReloadElement {

    static MAX_ROWS = 2000;

    jsonRpc = new JsonRpc(this);

    static styles = css`
        :host {
            display: flex;
            flex-direction: column;
            gap: 20px;
            padding: 10px 20px;
        }
        .section {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        h3 {
            margin: 0;
        }
        .row {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
        }
        .muted {
            color: var(--lumo-secondary-text-color);
            font-size: var(--lumo-font-size-s);
        }
        .stats {
            display: flex;
            gap: 30px;
        }
        .stat .value {
            font-size: var(--lumo-font-size-xl);
            font-weight: bold;
        }
        code {
            user-select: all;
        }
        a {
            color: var(--lumo-primary-text-color);
        }
    `;

    static properties = {
        _settings: { state: true },
        _status: { state: true },
        _files: { state: true },
        _permission: { state: true },
        _error: { state: true },
        _busy: { state: true },
        _packets: { state: true },
        _dropped: { state: true },
        _paused: { state: true },
        _hideDevUi: { state: true },
        _applicationOnly: { state: true },
        _excludeDevUi: { state: true },
        _interfaces: { state: true },
        _selectedInterfaces: { state: true }
    };

    constructor() {
        super();
        this._files = [];
        this._status = { running: false };
        this._packets = [];
        this._dropped = 0;
        this._paused = false;
        this._hideDevUi = true;
        this._applicationOnly = true;
        this._excludeDevUi = true;
        this._interfaces = [];
        this._selectedInterfaces = [];
        this._interfacesLoaded = false;
    }

    connectedCallback() {
        super.connectedCallback();
        this._load();
    }

    disconnectedCallback() {
        this._unsubscribe();
        this._unsubscribePackets();
        super.disconnectedCallback();
    }

    /**
     * Called by the Dev UI whenever the backend connection is (re)established, which includes every live reload.
     * A restart drops the server side of the streams, so they are re-created; the capture itself keeps running.
     */
    hotReload() {
        this._unsubscribe();
        this._unsubscribePackets();
        this._load();
    }

    _load() {
        this.jsonRpc.settings().then(r => {
            this._settings = r.result;
            if (!this._status.running) {
                this._applicationOnly = r.result.applicationOnly;
                this._excludeDevUi = r.result.excludeDevUi;
                this._selectedInterfaces = r.result.interfaces;
            }
        });
        this._refreshInterfaces();
        this._refreshFiles();
        this.jsonRpc.status().then(r => {
            this._status = r.result;
            if (this._status.running) {
                this._subscribe();
            } else if (this._status.file) {
                // the rows of the last capture are still on the server
                this._subscribePackets();
            }
        });
    }

    _subscribe() {
        if (!this._observer) {
            this._observer = this.jsonRpc.streamStatus().onNext(r => {
                this._status = r.result;
                if (!this._status.running) {
                    this._unsubscribe();
                    this._unsubscribePackets();
                    this._refreshFiles();
                }
            });
        }
        if (!this._paused) {
            this._subscribePackets();
        }
    }

    _subscribePackets() {
        if (!this._packetObserver) {
            const after = this._packets.length ? this._packets[this._packets.length - 1].no : 0;
            this._packetObserver = this.jsonRpc.streamPackets({ hideDevUi: this._hideDevUi, after: after }).onNext(r => {
                const batch = r.result;
                this._dropped = batch.dropped;
                if (batch.packets.length > 0) {
                    const merged = this._packets.concat(batch.packets);
                    this._packets = merged.length > QwcNetworkCapture.MAX_ROWS ? merged.slice(merged.length - QwcNetworkCapture.MAX_ROWS) : merged;
                }
                if (!batch.running && batch.packets.length === 0 && !this._status.running) {
                    this._unsubscribePackets(); // the last capture's rows are all here
                }
            });
        }
    }

    _unsubscribePackets() {
        if (this._packetObserver) {
            this._packetObserver.cancel();
            this._packetObserver = null;
        }
    }

    _unsubscribe() {
        if (this._observer) {
            this._observer.cancel();
            this._observer = null;
        }
    }

    _togglePause() {
        this._paused = !this._paused;
        if (this._paused) {
            this._unsubscribePackets();
        } else {
            this._subscribePackets();
        }
    }

    _hideDevUiChanged(hide) {
        this._hideDevUi = hide;
        if (this._packetObserver) {
            this._unsubscribePackets();
            this._subscribePackets();
        }
    }

    // Containers starting add interfaces, so the list is refreshed whenever the picker opens.
    _refreshInterfaces() {
        this.jsonRpc.interfaces().then(r => {
            this._interfaces = r.result;
            this._interfacesLoaded = true;
        });
    }

    // Only interfaces that are up can carry traffic, so only those are offered, plus any selected one that is not up
    // or no longer exists, marked as such: a selection must never be hidden, or the page would capture on interfaces
    // it does not show. Before the list has loaded, the selection (such as the configured default) is shown by name.
    _interfaceItems() {
        const items = this._interfaces.filter(i => i.up || this._selectedInterfaces.includes(i.name)).map(i => ({
            name: i.name,
            label: [i.name, i.loopback ? 'loopback' : null, i.up ? null : 'down', i.addresses.join(', ') || null]
                .filter(p => p).join(' · ')
        }));
        for (const name of this._selectedInterfaces) {
            if (!items.some(i => i.name === name)) {
                items.push({ name: name, label: this._interfacesLoaded ? name + ' · not found' : name });
            }
        }
        return items;
    }

    // The combo box also reports the selection it is handed on every render; only a real change may update the
    // state, or each render would trigger the next.
    _interfacesChanged(items) {
        const names = items.map(i => i.name);
        if (names.join(',') !== this._selectedInterfaces.join(',')) {
            this._selectedInterfaces = names;
        }
    }

    _refreshFiles() {
        this.jsonRpc.listFiles().then(r => this._files = r.result);
    }

    // The download route lives next to the Dev UI under the non-application root path.
    _downloadPath() {
        return window.location.pathname.split('/dev-ui/')[0] + '/network-capture/download';
    }

    render() {
        return html`
            ${this._renderMessages()}
            ${this._status.running ? this._renderRunning() : this._renderStart()}
            ${this._status.running || this._packets.length > 0 ? html`
                <div class="section">
                    <h3>${this._status.running ? 'Live packets' : 'Packets of the last capture'}</h3>
                    <qwc-network-capture-packets .packets=${this._packets} .running=${this._status.running} .paused=${this._paused}
                        .hideDevUi=${this._hideDevUi} .dropped=${this._dropped} .maxRows=${QwcNetworkCapture.MAX_ROWS}
                        @clear=${() => this._packets = []}
                        @toggle-pause=${this._togglePause}
                        @hide-dev-ui-changed=${e => this._hideDevUiChanged(e.detail)}></qwc-network-capture-packets>
                </div>` : ''}
            ${this._renderFiles()}
            ${this._renderSettings()}
        `;
    }

    _renderMessages() {
        return html`
            ${this._error ? html`<qui-alert level="error" showIcon><span>${this._error}</span></qui-alert>` : ''}
            ${this._permission ? html`
                <qui-alert level="warning" showIcon>
                    <div class="section">
                        <span>${this._permission.message}</span>
                        <span>The application cannot open a capture itself. A small helper process can open it with
                            elevated privileges (${this._permission.elevation.toLowerCase()}) and hand the descriptor back;
                            you may be prompted for your password.</span>
                        <div class="row">
                            <vaadin-button theme="primary" ?disabled=${this._busy} @click=${() => this._start(true)}>
                                <vaadin-icon icon="font-awesome-solid:user-shield" slot="prefix"></vaadin-icon>
                                Start with ${this._permission.elevation.toLowerCase()}
                            </vaadin-button>
                        </div>
                        <span class="muted">${this._permission.setupHint}</span>
                    </div>
                </qui-alert>` : ''}
        `;
    }

    _renderStart() {
        return html`
            <div class="section">
                <h3>Options</h3>
                <vaadin-checkbox label="Only this application's traffic (packets to or from this process's sockets)"
                    .checked=${this._applicationOnly} @checked-changed=${e => this._applicationOnly = e.detail.value}></vaadin-checkbox>
                <vaadin-checkbox label="Exclude the Dev UI's and Dev MCP's own traffic"
                    .checked=${this._excludeDevUi} @checked-changed=${e => this._excludeDevUi = e.detail.value}></vaadin-checkbox>
                <vaadin-multi-select-combo-box label="Interfaces" placeholder="All interfaces that are up" clear-button-visible
                    style="width: 100%; max-width: 640px"
                    .items=${this._interfaceItems()} item-label-path="label" item-id-path="name"
                    .selectedItems=${this._interfaceItems().filter(i => this._selectedInterfaces.includes(i.name))}
                    @opened-changed=${e => e.detail.value && this._refreshInterfaces()}
                    @selected-items-changed=${e => this._interfacesChanged(e.detail.value)}></vaadin-multi-select-combo-box>
                <div class="row">
                    <vaadin-button theme="primary" ?disabled=${this._busy} @click=${() => this._start(false)}>
                        <vaadin-icon icon="font-awesome-solid:play" slot="prefix"></vaadin-icon>
                        Start capture
                    </vaadin-button>
                    ${this._busy ? html`<vaadin-progress-bar indeterminate style="width: 200px"></vaadin-progress-bar>` : ''}
                </div>
                <span class="muted">${this._selectedInterfaces.length === 0
                    ? "Captures on every network interface that is up. The application's traffic is kept whichever interface carries it."
                    : 'Captures only on ' + this._selectedInterfaces.join(', ') + '. Traffic over any other interface, such as a container bridge or the LAN, is not captured.'}</span>
            </div>
        `;
    }

    _renderRunning() {
        const s = this._status;
        return html`
            <div class="section">
                <h3>Capturing</h3>
                <div class="stats">
                    <div class="stat"><div class="value">${s.packets}</div><div class="muted">packets</div></div>
                    <div class="stat"><div class="value">${this._formatBytes(s.bytes)}</div><div class="muted">captured</div></div>
                    <div class="stat"><div class="value">${this._elapsed(s.startedAt)}</div><div class="muted">elapsed</div></div>
                    <div class="stat"><div class="value">${s.filtered}</div><div class="muted">filtered out</div></div>
                </div>
                ${s.filterError ? html`<qui-alert level="warning" showIcon><span>Socket scanning stopped: ${s.filterError}. Nothing is being written any more.</span></qui-alert>` : ''}
                ${s.dropped > 0 ? html`<qui-alert level="warning" showIcon><span>${s.dropped} packets were dropped because the writer could not keep up.</span></qui-alert>` : ''}
                ${s.skipped && Object.keys(s.skipped).length > 0 ? html`<qui-alert level="info" showIcon><span>Not captured: ${Object.entries(s.skipped).map(([name, reason]) => `${name} (${reason})`).join(', ')}</span></qui-alert>` : ''}
                <vaadin-grid .items=${s.interfaces} all-rows-visible theme="no-border">
                    <vaadin-grid-column header="Interface" path="name" auto-width></vaadin-grid-column>
                    <vaadin-grid-column header="Packets" path="packets" auto-width></vaadin-grid-column>
                    <vaadin-grid-column header="Bytes" path="bytes" auto-width></vaadin-grid-column>
                    <vaadin-grid-column header="Filtered out" path="filtered" auto-width></vaadin-grid-column>
                    <vaadin-grid-column header="Error" path="error"></vaadin-grid-column>
                </vaadin-grid>
                <span class="muted">Writing to <code>${s.file}</code>. The file can be opened in Wireshark while capturing.</span>
                <div class="row">
                    <vaadin-button theme="primary error" @click=${this._stop}>
                        <vaadin-icon icon="font-awesome-solid:stop" slot="prefix"></vaadin-icon>
                        Stop capture
                    </vaadin-button>
                    <a href="${this._downloadPath()}/${s.fileName}" download>Download current file</a>
                </div>
            </div>
        `;
    }

    _renderFiles() {
        return html`
            <div class="section">
                <h3>Capture files</h3>
                ${this._files.length === 0 ? html`<span class="muted">No capture files yet.</span>` : html`
                <vaadin-grid .items=${this._files} all-rows-visible theme="no-border">
                    <vaadin-grid-column header="File" auto-width ${columnBodyRenderer(f => html`
                        <a href="${this._downloadPath()}/${f.name}" download>${f.name}</a>`, [])}></vaadin-grid-column>
                    <vaadin-grid-column header="Size" auto-width ${columnBodyRenderer(f => html`${this._formatBytes(f.size)}`, [])}>
                    </vaadin-grid-column>
                    <vaadin-grid-column header="Modified" auto-width ${columnBodyRenderer(f => html`${new Date(f.modified).toLocaleString()}`, [])}>
                    </vaadin-grid-column>
                    <vaadin-grid-column header="" auto-width ${columnBodyRenderer(f => html`
                        <vaadin-button theme="small error tertiary" ?disabled=${this._status.running && this._status.fileName === f.name}
                            @click=${() => this._delete(f)}>
                            <vaadin-icon icon="font-awesome-solid:trash"></vaadin-icon>
                        </vaadin-button>`, [])}></vaadin-grid-column>
                </vaadin-grid>`}
            </div>
        `;
    }

    _renderSettings() {
        if (!this._settings) {
            return '';
        }
        return html`
            <div class="section muted">
                <span>Directory: <code>${this._settings.directory}</code> (quarkus.network-capture.directory)</span>
                <span>Elevation: ${this._settings.elevation.toLowerCase()} (quarkus.network-capture.elevation)</span>
                <span>${this._settings.setupHint}</span>
            </div>
        `;
    }

    _start(elevate) {
        this._error = null;
        this._permission = null;
        this._busy = true;
        this.jsonRpc.startFromDevUi({ elevate: elevate, applicationOnly: this._applicationOnly, excludeDevUi: this._excludeDevUi,
            interfaces: this._selectedInterfaces }).then(r => {
            this._busy = false;
            const result = r.result;
            if (result.status === 'started') {
                this._packets = [];
                this._dropped = 0;
                // the stream of the previous capture, if its rows were still coming in, would keep its cursor
                this._unsubscribePackets();
                this.jsonRpc.status().then(s => this._status = s.result);
                this._subscribe();
            } else if (result.status === 'permission-required') {
                this._permission = result;
            } else {
                this._error = result.message;
            }
        }).catch(e => {
            this._busy = false;
            this._error = String(e);
        });
    }

    _stop() {
        this.jsonRpc.stop().then(r => {
            this._status = r.result;
            this._unsubscribe();
            this._unsubscribePackets();
            this._refreshFiles();
        });
    }

    _delete(file) {
        this.jsonRpc.deleteFile({ name: file.name }).then(() => this._refreshFiles());
    }

    _formatBytes(n) {
        if (n < 1024) return n + ' B';
        if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KiB';
        return (n / (1024 * 1024)).toFixed(1) + ' MiB';
    }

    _elapsed(startedAt) {
        const seconds = Math.max(0, Math.floor((Date.now() - new Date(startedAt).getTime()) / 1000));
        const m = Math.floor(seconds / 60);
        const s = seconds % 60;
        return m + ':' + (s < 10 ? '0' : '') + s;
    }
}
customElements.define('qwc-network-capture', QwcNetworkCapture);
