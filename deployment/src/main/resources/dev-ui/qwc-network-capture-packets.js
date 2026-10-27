import { LitElement, html, css } from 'lit';
import '@vaadin/button';
import '@vaadin/checkbox';
import '@vaadin/grid';
import '@vaadin/icon';
import 'qui-themed-code-block';
import { columnBodyRenderer } from '@vaadin/grid/lit.js';

/**
 * The packet list with its details panel. Receives the rows from the capture page and only decides how to show them:
 * selection, the Only HTTP filter, following the tail, and the links between requests and responses.
 *
 * Events: `clear` (drop all rows), `toggle-pause`, `hide-dev-ui-changed` (detail: boolean).
 */
export class QwcNetworkCapturePackets extends LitElement {

    static styles = css`
        :host {
            display: flex;
            flex-direction: column;
            gap: 10px;
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
        .packets {
            height: 420px;
            font-family: var(--lumo-font-family-monospace, monospace);
            font-size: var(--lumo-font-size-s);
        }
        .details {
            border: 1px solid var(--lumo-contrast-20pct);
            border-radius: var(--lumo-border-radius-m);
            padding: 10px 15px;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        .details h4 {
            margin: 8px 0 0 0;
        }
        .details table {
            border-collapse: collapse;
            font-size: var(--lumo-font-size-s);
        }
        .details td {
            padding: 2px 12px 2px 0;
            vertical-align: top;
            font-family: var(--lumo-font-family-monospace, monospace);
        }
        .details td:first-child {
            color: var(--lumo-secondary-text-color);
            white-space: nowrap;
        }
        .badge {
            display: inline-block;
            padding: 1px 8px;
            border-radius: var(--lumo-border-radius-m);
            font-size: var(--lumo-font-size-xs);
            font-weight: 600;
            white-space: nowrap;
            color: var(--lumo-primary-contrast-color);
        }
        .badge.safe {
            background: var(--lumo-success-color);
        }
        .badge.unsafe {
            background: var(--lumo-error-color);
        }
        .details pre {
            margin: 0;
            max-height: 300px;
            overflow: auto;
            white-space: pre-wrap;
            word-break: break-all;
            font-size: var(--lumo-font-size-s);
            background: var(--lumo-contrast-5pct);
            padding: 8px;
        }
        .link {
            cursor: pointer;
            color: var(--lumo-primary-text-color);
            text-decoration: underline;
        }
    `;

    static properties = {
        packets: { type: Array },
        running: { type: Boolean },
        paused: { type: Boolean },
        hideDevUi: { type: Boolean },
        dropped: { type: Number },
        maxRows: { type: Number },
        _selected: { state: true },
        _follow: { state: true },
        _onlyHttp: { state: true }
    };

    constructor() {
        super();
        this.packets = [];
        this.running = false;
        this.paused = false;
        this.hideDevUi = true;
        this.dropped = 0;
        this.maxRows = 2000;
        this._follow = true;
        this._onlyHttp = false;
        this._responses = new Map();
    }

    willUpdate(changed) {
        if (changed.has('packets')) {
            // response rows (not body parts) by exchange id, so request rows can point at them
            this._responses = new Map();
            for (const p of this.packets) {
                if (p.exchange && !p.exchange.isRequest && !p.http?.bodyPart) {
                    this._responses.set(p.exchange.id, p);
                }
            }
            if (this._selected && !this.packets.includes(this._selected)) {
                this._selected = null;
            }
        }
    }

    updated(changed) {
        if (changed.has('packets') && this._follow && this.running) {
            this._scrollTo(this._visible().length - 1);
        }
    }

    _visible() {
        return this._onlyHttp ? this.packets.filter(p => p.protocol === 'HTTP' || p.protocol === 'HTTP2' || p.protocol === 'HTTPS') : this.packets;
    }

    _scrollTo(index) {
        const grid = this.shadowRoot.querySelector('#packets');
        if (grid && index >= 0) grid.scrollToIndex(index);
    }

    _jumpTo(no) {
        const target = this.packets.find(p => p.no === no);
        if (target) {
            this._selected = target;
            this.updateComplete.then(() => this._scrollTo(this._visible().indexOf(target)));
        }
    }

    _emit(name, detail) {
        this.dispatchEvent(new CustomEvent(name, { detail }));
    }

    render() {
        const running = this.running;
        return html`
            <div class="row">
                ${running ? html`
                <vaadin-button theme="small" @click=${() => this._emit('toggle-pause')}>
                    <vaadin-icon icon="font-awesome-solid:${this.paused ? 'play' : 'pause'}" slot="prefix"></vaadin-icon>
                    ${this.paused ? 'Resume' : 'Pause'}
                </vaadin-button>` : ''}
                <vaadin-button theme="small" @click=${() => { this._selected = null; this._emit('clear'); }}>
                    <vaadin-icon icon="font-awesome-solid:broom" slot="prefix"></vaadin-icon>
                    Clear
                </vaadin-button>
                ${running ? html`
                <vaadin-checkbox label="Follow" .checked=${this._follow} @checked-changed=${e => this._follow = e.detail.value}></vaadin-checkbox>
                <vaadin-checkbox label="Hide Dev UI traffic" .checked=${this.hideDevUi} @change=${e => this._emit('hide-dev-ui-changed', e.target.checked)}></vaadin-checkbox>` : ''}
                <vaadin-checkbox label="Only HTTP" .checked=${this._onlyHttp} @checked-changed=${e => this._onlyHttp = e.detail.value}></vaadin-checkbox>
                <span class="muted">${running ? `Last ${this.maxRows} packets are kept` : `${this.packets.length} packets shown; the complete capture is in the file below`}${this.dropped > 0 ? `, ${this.dropped} not shown because the browser could not keep up` : ''}.</span>
            </div>
            <vaadin-grid id="packets" class="packets" .items=${this._visible()} theme="compact no-border row-stripes"
                .selectedItems=${this._selected ? [this._selected] : []}
                @active-item-changed=${e => this._selected = e.detail.value}>
                <vaadin-grid-column header="No." path="no" width="90px" flex-grow="0"></vaadin-grid-column>
                <vaadin-grid-column header="Time" path="time" width="120px" flex-grow="0"></vaadin-grid-column>
                <vaadin-grid-column header="Interface" path="interfaceName" width="100px" flex-grow="0"></vaadin-grid-column>
                <vaadin-grid-column header="Source" path="source" width="200px" flex-grow="0"></vaadin-grid-column>
                <vaadin-grid-column header="Destination" path="destination" width="200px" flex-grow="0"></vaadin-grid-column>
                <vaadin-grid-column header="Protocol" path="protocol" width="90px" flex-grow="0"></vaadin-grid-column>
                <vaadin-grid-column header="Length" path="length" width="80px" flex-grow="0"></vaadin-grid-column>
                <vaadin-grid-column header="Exchange" width="90px" flex-grow="0" ${columnBodyRenderer(p => this._renderExchangeCell(p), [])}></vaadin-grid-column>
                <vaadin-grid-column header="Info" ${columnBodyRenderer(p => this._renderInfoCell(p), [])}></vaadin-grid-column>
            </vaadin-grid>
            ${this._selected ? this._renderDetails(this._selected) : html`<span class="muted">Click a packet to see its details.</span>`}
        `;
    }

    _responseOf(p) {
        return p.exchange?.isRequest ? this._responses.get(p.exchange.id) : null;
    }

    _renderExchangeCell(p) {
        const x = p.exchange;
        if (!x) return html``;
        if (x.isRequest) {
            const response = this._responseOf(p);
            return response
                ? html`<span class="link" @click=${e => { e.stopPropagation(); this._jumpTo(response.no); }}>→ #${response.no}</span>`
                : html`<span class="muted">→ …</span>`;
        }
        return x.requestNo ? html`<span class="link" @click=${e => { e.stopPropagation(); this._jumpTo(x.requestNo); }}>↩ #${x.requestNo}</span>` : html``;
    }

    // The Server Hello row wears the verdict on its key exchange; the other rows of the connection carry it in their details
    _renderInfoCell(p) {
        return html`${p.tls?.serverHello && p.tls.quantumSafety ? this._renderVerdictBadge(p.tls.quantumSafety) : ''}${p.info}`;
    }

    _renderVerdictBadge(q) {
        return html`<span class="badge ${q.safe ? 'safe' : 'unsafe'}">${q.safe ? 'Quantum safe' : 'Not quantum safe'}</span> `;
    }

    _renderExchangeLine(p) {
        const x = p.exchange;
        if (!x) return '';
        if (x.isRequest) {
            const response = this._responseOf(p);
            return response
                ? html`<span>Answered by packet <span class="link" @click=${() => this._jumpTo(response.no)}>#${response.no}</span>: ${response.info}</span>`
                : html`<span class="muted">No response seen yet.</span>`;
        }
        return x.requestNo
            ? html`<span>${p.http?.bodyPart ? 'Part of the response' : 'Response'} to packet <span class="link" @click=${() => this._jumpTo(x.requestNo)}>#${x.requestNo}</span>: ${x.request}</span>`
            : html`<span>Response to <strong>${x.request}</strong>, whose packet is no longer in the list.</span>`;
    }

    _renderDetails(p) {
        const h = p.http;
        return html`
            <div class="details">
                <div class="row">
                    <strong>Packet ${p.no}</strong>
                    <span class="muted">${p.time}s on ${p.interfaceName}, ${p.source} → ${p.destination}, ${p.protocol}, ${p.length} bytes</span>
                    <vaadin-button theme="tertiary small" @click=${() => this._selected = null}>Close</vaadin-button>
                </div>
                ${this._renderExchangeLine(p)}
                ${h && h.bodyPart ? html`
                    <span>${h.chunked ? (h.last ? 'Last chunk' : 'Chunk') : 'Part'} of the body of <strong>${h.message}</strong>, whose headers are in an earlier packet.</span>
                    <h4>Body <span class="muted">(${h.chunked ? `${h.bodyBytes} bytes in this chunk` : `bytes ${h.offset + 1}-${h.offset + h.bodyBytes} of ${h.total}`}${h.remaining > 0 ? `, ${h.remaining} still to come` : ''}${h.bodyTextTruncated ? ', display truncated' : ''})</span></h4>
                    ${this._renderBody(h)}
                ` : h ? html`
                    <table>
                        ${h.request ? html`
                            <tr><td>Method</td><td>${h.method}</td></tr>
                            <tr><td>URL</td><td>${h.url}</td></tr>` : html`
                            <tr><td>Status</td><td>${h.status} ${h.reason}</td></tr>`}
                        <tr><td>Version</td><td>${h.version}</td></tr>
                    </table>
                    <h4>Headers</h4>
                    ${h.headers.length === 0 ? html`<span class="muted">none</span>` : html`
                    <table>${h.headers.map(x => html`<tr><td>${x.name}</td><td>${x.value}</td></tr>`)}</table>`}
                    <h4>Body <span class="muted">${this._bodyNote(h)}</span></h4>
                    ${h.bodyBytes === 0 ? '' : this._renderBody(h)}
                ` : p.tls ? this._renderTls(p) : html`<span class="muted">${p.info}${p.protocol === 'HTTP2'
                    ? html`<br>HTTP/2 headers are compressed on the wire, so only frame types can be shown.`
                    : p.protocol === 'HTTPS' || p.protocol === 'TLS'
                    ? html`<br>TLS traffic is encrypted, so only the record types and the Client Hello and Server Hello can be shown.`
                    : html`<br>Headers and body are shown for HTTP/1.x messages.`}</span>`}
            </div>
        `;
    }

    /** The handshake details of a TLS packet, the verdict on the key exchange first. */
    _renderTls(p) {
        const t = p.tls;
        const c = t.clientHello;
        const s = t.serverHello;
        const q = t.quantumSafety;
        const list = values => values.length === 0 ? html`<span class="muted">none</span>` : values.join(', ');
        return html`
            <span class="muted">${p.info}</span>
            ${q ? html`<div class="row">${this._renderVerdictBadge(q)}<span>${q.reason}${s ? '' : ', decided by the Server Hello of this connection'}.</span></div>` : ''}
            ${c ? html`
                <span>${c.postQuantumGroups.length > 0
                    ? html`The client offered the post-quantum group${c.postQuantumGroups.length > 1 ? 's' : ''} <strong>${c.postQuantumGroups.join(', ')}</strong>; the Server Hello of this connection shows whether the server picked one.`
                    : html`The client offered <strong>no post-quantum group</strong>, so this connection cannot have a quantum-safe key exchange.`}</span>
                <h4>Client Hello ${c.truncated ? html`<span class="muted">(cut by the packet, the lists may be incomplete)</span>` : ''}</h4>
                <table>
                    <tr><td>Server name</td><td>${c.serverName ?? html`<span class="muted">none</span>`}</td></tr>
                    <tr><td>ALPN</td><td>${list(c.protocols)}</td></tr>
                    <tr><td>Versions</td><td>${list(c.versions)}</td></tr>
                    <tr><td>Key shares</td><td>${list(c.keyShares)}</td></tr>
                    <tr><td>Supported groups</td><td>${list(c.groups)}</td></tr>
                    <tr><td>Cipher suites</td><td>${list(c.cipherSuites)}</td></tr>
                    <tr><td>Signature algorithms</td><td>${list(c.signatureAlgorithms)}</td></tr>
                </table>` : ''}
            ${s ? html`
                <h4>${s.retryRequest ? 'Hello Retry Request' : 'Server Hello'} ${s.truncated ? html`<span class="muted">(cut by the packet)</span>` : ''}</h4>
                <table>
                    <tr><td>Version</td><td>${s.version ?? html`<span class="muted">unknown</span>`}</td></tr>
                    <tr><td>Cipher suite</td><td>${s.cipherSuite ?? html`<span class="muted">unknown</span>`}</td></tr>
                    <tr><td>${s.retryRequest ? 'Asks for key share' : 'Key share'}</td><td>${s.keyShareGroup ?? html`<span class="muted">none</span>`}</td></tr>
                </table>
                ${s.retryRequest ? html`<span class="muted">The client sent no key share for this group; its next Client Hello will, and the Server Hello that follows decides.</span>` : ''}` : ''}
            ${!c && !s ? html`<span class="muted">TLS traffic is encrypted; the handshake details are on the Client Hello and Server Hello packets of this connection.</span>` : ''}
        `;
    }

    _bodyNote(h) {
        if (h.bodyBytes === 0) return h.contentLength > 0 ? `(${h.contentLength} bytes, sent in later packets)` : '(empty)';
        let note = h.contentLength >= 0 ? `(${h.bodyBytes} of ${h.contentLength} bytes in this packet` : `(${h.bodyBytes} bytes in this packet`;
        if (h.bodyTextTruncated) note += ', display truncated';
        return note + ')';
    }

    /** Pretty prints and highlights JSON bodies; everything else is shown as text. */
    _renderBody(h) {
        if (h.bodyText === null) {
            return html`<span class="muted">binary content</span>`;
        }
        const json = this._asJson(h.bodyText);
        if (json !== null) {
            return html`<qui-themed-code-block mode="json" content="${json}"></qui-themed-code-block>`;
        }
        return html`<pre>${h.bodyText}</pre>`;
    }

    _asJson(text) {
        const trimmed = text.trim();
        if (!(trimmed.startsWith('{') || trimmed.startsWith('['))) {
            return null;
        }
        try {
            return JSON.stringify(JSON.parse(trimmed), null, 2);
        } catch (e) {
            return null;
        }
    }
}
customElements.define('qwc-network-capture-packets', QwcNetworkCapturePackets);
