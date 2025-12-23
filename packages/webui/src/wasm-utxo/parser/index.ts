/**
 * PSBT/Transaction Parser Demo
 *
 * Parses PSBTs and transactions and displays them as collapsible trees.
 */

import { BaseComponent, defineComponent, h, css, fragment, type Child } from "../../lib/html";
import { setParams } from "../../lib/router";
import { commonStyles } from "../../index";
import { parseNode } from "@bitgo/wasm-utxo";
import { samples, type Sample } from "./samples";

const {
  parsePsbtToNode,
  parseTxToNode,
  parsePsbtRawToNode,
  isParseNodeEnabled,
  tryParsePsbt,
  tryParseTx,
  tryParsePsbtRaw,
  allNetworks,
} = parseNode;
type Node = parseNode.Node;
type Primitive = parseNode.Primitive;
type CoinName = parseNode.CoinName;

type ParseMode = "psbt" | "tx" | "psbt-raw";

// PSBT magic bytes: "psbt" followed by 0xff
const PSBT_MAGIC = "70736274ff";

// Network display names
const networkLabels: Record<CoinName, string> = {
  btc: "Bitcoin",
  tbtc: "Bitcoin Testnet",
  tbtc4: "Bitcoin Testnet4",
  tbtcsig: "Bitcoin Signet",
  tbtcbgsig: "Bitcoin BitGo Signet",
  ltc: "Litecoin",
  tltc: "Litecoin Testnet",
  bch: "Bitcoin Cash",
  tbch: "Bitcoin Cash Testnet",
  bcha: "eCash",
  tbcha: "eCash Testnet",
  btg: "Bitcoin Gold",
  tbtg: "Bitcoin Gold Testnet",
  bsv: "Bitcoin SV",
  tbsv: "Bitcoin SV Testnet",
  dash: "Dash",
  tdash: "Dash Testnet",
  doge: "Dogecoin",
  tdoge: "Dogecoin Testnet",
  zec: "Zcash",
  tzec: "Zcash Testnet",
};

/**
 * Decode hex or base64 input to bytes.
 */
function decodeInput(input: string): Uint8Array {
  const trimmed = input.trim();

  // Try hex first
  if (/^[0-9a-fA-F]+$/.test(trimmed)) {
    const bytes = new Uint8Array(trimmed.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(trimmed.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  // Try base64
  const binary = atob(trimmed);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Convert bytes to hex string.
 */
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Detect if input is a PSBT based on magic bytes.
 */
function isPsbt(bytes: Uint8Array): boolean {
  if (bytes.length < 5) return false;
  const magic = toHex(bytes.slice(0, 5));
  return magic === PSBT_MAGIC;
}

/**
 * Format a primitive value for display.
 */
function formatPrimitive(primitive: Primitive): string {
  if (primitive.type === "None") return "";
  if (primitive.type === "Buffer") {
    const hex = String(primitive.value ?? "");
    if (hex.length > 64) {
      return hex.slice(0, 32) + "..." + hex.slice(-32);
    }
    return hex;
  }
  if (primitive.type === "Boolean") {
    return primitive.value ? "true" : "false";
  }
  return String(primitive.value ?? "");
}

/**
 * Get full value for copying.
 */
function getFullValue(primitive: Primitive): string {
  if (primitive.type === "None") return "";
  if (primitive.type === "Boolean") {
    return primitive.value ? "true" : "false";
  }
  return String(primitive.value ?? "");
}

/**
 * Copy text to clipboard and show feedback.
 */
async function copyToClipboard(text: string, button: HTMLElement): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    const original = button.textContent;
    button.textContent = "Copied!";
    setTimeout(() => {
      button.textContent = original;
    }, 1500);
  } catch (e) {
    console.error("Failed to copy:", e);
  }
}

/**
 * Tree Node component for recursive rendering.
 */
function renderTreeNode(
  node: Node,
  expandedPaths: Set<string>,
  onToggle: (path: string) => void,
  path: string = "root",
): HTMLElement {
  const hasChildren = node.children.length > 0;
  const isExpanded = expandedPaths.has(path);
  const hasValue = node.value.type !== "None";

  const toggleExpand = () => {
    onToggle(path);
  };

  // Leaf node - just show label: value
  if (!hasChildren) {
    return h(
      "div",
      { class: "tree-leaf" },
      h("span", { class: "tree-label" }, node.label),
      hasValue
        ? [
            h("span", { class: "tree-separator" }, ": "),
            h(
              "span",
              {
                class: `tree-value tree-value-${node.value.type.toLowerCase()}`,
                title: getFullValue(node.value),
              },
              formatPrimitive(node.value),
            ),
            h(
              "button",
              {
                class: "copy-btn",
                onclick: (e: Event) => {
                  e.stopPropagation();
                  copyToClipboard(getFullValue(node.value), e.target as HTMLElement);
                },
              },
              "Copy",
            ),
          ]
        : null,
    );
  }

  // Branch node - collapsible
  const childCount = node.children.length;
  const labelText = hasValue
    ? `${node.label}: ${formatPrimitive(node.value)}`
    : `${node.label} [${childCount}]`;

  return h(
    "div",
    { class: "tree-branch" },
    h(
      "div",
      {
        class: "tree-branch-header",
        onclick: toggleExpand,
      },
      h("span", { class: `tree-chevron ${isExpanded ? "expanded" : ""}` }, isExpanded ? "▼" : "►"),
      h("span", { class: "tree-label" }, labelText),
    ),
    isExpanded
      ? h(
          "div",
          { class: "tree-children" },
          ...node.children.map((child, i) =>
            renderTreeNode(child, expandedPaths, onToggle, `${path}.${i}`),
          ),
        )
      : null,
  );
}

/**
 * Parser Web Component
 */
class PsbtTxParser extends BaseComponent {
  private debounceTimer: number | null = null;
  private expandedPaths: Set<string> = new Set(["root"]);
  private currentMode: ParseMode = "psbt";
  private currentNode: Node | null = null;
  private currentNetwork: CoinName = "btc";
  private autoDetectNetwork: boolean = true;

  render() {
    const featureEnabled = isParseNodeEnabled();

    return fragment(
      css(`
        ${commonStyles}

        .parser {
          max-width: none;
          width: 100%;
        }

        .parser-layout {
          display: grid;
          grid-template-columns: 400px 1fr;
          gap: 1.5rem;
          align-items: start;
        }

        @media (max-width: 900px) {
          .parser-layout {
            grid-template-columns: 1fr;
          }
        }

        .controls-panel {
          position: sticky;
          top: 1rem;
        }

        .results-panel {
          min-width: 0;
        }

        .input-section {
          margin-bottom: 0;
        }

        .input-row {
          display: flex;
          gap: 0.5rem;
          margin-bottom: 0.75rem;
        }

        textarea {
          width: 100%;
          font-family: inherit;
          font-size: 0.875rem;
          padding: 0.75rem 1rem;
          background: var(--surface, #161b22);
          border: 1px solid var(--border, #30363d);
          border-radius: 6px;
          color: var(--fg, #c9d1d9);
          resize: vertical;
          min-height: 200px;
        }

        textarea:focus {
          outline: none;
          border-color: var(--accent, #58a6ff);
        }

        textarea::placeholder {
          color: var(--muted, #8b949e);
        }

        .btn {
          padding: 0.5rem 1rem;
          font-family: inherit;
          font-size: 0.875rem;
          background: var(--surface, #161b22);
          border: 1px solid var(--border, #30363d);
          border-radius: 6px;
          color: var(--fg, #c9d1d9);
          cursor: pointer;
          transition: border-color 0.15s, background 0.15s;
          white-space: nowrap;
        }

        .btn:hover {
          border-color: var(--accent, #58a6ff);
          background: var(--surface-hover, #1c2128);
        }

        .btn-group {
          display: flex;
          gap: 0;
        }

        .btn-group .btn {
          border-radius: 0;
        }

        .btn-group .btn:first-child {
          border-radius: 6px 0 0 6px;
        }

        .btn-group .btn:last-child {
          border-radius: 0 6px 6px 0;
        }

        .btn-group .btn:not(:first-child) {
          margin-left: -1px;
        }

        .btn-group .btn.active {
          background: var(--accent, #58a6ff);
          border-color: var(--accent, #58a6ff);
          color: var(--bg, #0d1117);
        }

        .controls-row {
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
          align-items: stretch;
        }

        .controls-row-group {
          display: flex;
          gap: 0.5rem;
          align-items: center;
          flex-wrap: wrap;
        }

        .mode-label {
          font-size: 0.75rem;
          color: var(--muted, #8b949e);
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }

        .error-message {
          padding: 1rem;
          background: rgba(248, 81, 73, 0.1);
          border: 1px solid rgba(248, 81, 73, 0.4);
          border-radius: 6px;
          color: #f85149;
          margin-bottom: 1.5rem;
          font-size: 0.875rem;
        }

        .feature-disabled {
          padding: 1rem;
          background: rgba(207, 172, 83, 0.1);
          border: 1px solid rgba(207, 172, 83, 0.4);
          border-radius: 6px;
          color: var(--warning, #CFAC53);
          margin-bottom: 1.5rem;
        }

        .tree-container {
          background: var(--surface, #161b22);
          border: 1px solid var(--border, #30363d);
          border-radius: 6px;
          padding: 1rem;
          overflow-x: auto;
        }

        .tree-branch {
          margin-left: 0;
        }

        .tree-branch .tree-branch,
        .tree-branch .tree-leaf {
          margin-left: 1.25rem;
          border-left: 1px solid var(--border-subtle, #21262d);
          padding-left: 0.75rem;
        }

        .tree-branch-header {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          padding: 0.25rem 0;
          cursor: pointer;
          user-select: none;
        }

        .tree-branch-header:hover {
          background: var(--surface-hover, #1c2128);
          margin: 0 -0.5rem;
          padding: 0.25rem 0.5rem;
          border-radius: 4px;
        }

        .tree-chevron {
          font-size: 0.75rem;
          color: var(--muted, #8b949e);
          width: 1rem;
          text-align: center;
        }

        .tree-leaf {
          display: flex;
          align-items: center;
          gap: 0;
          padding: 0.25rem 0;
          flex-wrap: wrap;
        }

        .tree-label {
          color: var(--accent, #58a6ff);
          font-weight: 500;
        }

        .tree-separator {
          color: var(--muted, #8b949e);
        }

        .tree-value {
          color: var(--fg, #c9d1d9);
          word-break: break-all;
          max-width: 600px;
        }

        .tree-value-buffer {
          color: var(--green, #7ACC8F);
          font-family: inherit;
        }

        .tree-value-string {
          color: var(--yellow, #EBC55E);
        }

        .tree-value-integer,
        .tree-value-u8,
        .tree-value-u16,
        .tree-value-u32,
        .tree-value-u64,
        .tree-value-i8,
        .tree-value-i16,
        .tree-value-i32,
        .tree-value-i64 {
          color: var(--lavender, #8780FF);
        }

        .tree-value-boolean {
          color: var(--orange, #FF704C);
        }

        .tree-children {
          margin-top: 0.25rem;
        }

        .copy-btn {
          padding: 0.125rem 0.375rem;
          font-size: 0.625rem;
          background: transparent;
          border: 1px solid var(--border, #30363d);
          border-radius: 3px;
          color: var(--muted, #8b949e);
          cursor: pointer;
          margin-left: 0.5rem;
          opacity: 0;
          transition: opacity 0.15s, border-color 0.15s, color 0.15s;
        }

        .tree-leaf:hover .copy-btn {
          opacity: 1;
        }

        .copy-btn:hover {
          border-color: var(--accent, #58a6ff);
          color: var(--accent, #58a6ff);
        }

        .empty-state {
          text-align: center;
          padding: 3rem 1rem;
          color: var(--muted, #8b949e);
        }

        .detected-type {
          font-size: 0.75rem;
          color: var(--muted, #8b949e);
          padding: 0.5rem 0;
        }

        .expand-controls {
          display: flex;
          gap: 0.5rem;
        }

        .action-buttons {
          display: flex;
          gap: 0.5rem;
          flex-wrap: wrap;
        }

        .expand-controls .btn {
          padding: 0.25rem 0.5rem;
          font-size: 0.75rem;
        }

        .modal-overlay {
          display: none;
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(0, 0, 0, 0.7);
          z-index: 1000;
          align-items: center;
          justify-content: center;
        }

        .modal-overlay.open {
          display: flex;
        }

        .modal {
          background: var(--bg, #0d1117);
          border: 1px solid var(--border, #30363d);
          border-radius: 8px;
          max-width: 500px;
          width: 90%;
          max-height: 80vh;
          display: flex;
          flex-direction: column;
          box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
        }

        .modal-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 1rem 1.25rem;
          border-bottom: 1px solid var(--border, #30363d);
        }

        .modal-header h2 {
          margin: 0;
          font-size: 1rem;
          font-weight: 600;
        }

        .modal-close {
          background: none;
          border: none;
          color: var(--muted, #8b949e);
          cursor: pointer;
          font-size: 1.25rem;
          padding: 0.25rem;
          line-height: 1;
        }

        .modal-close:hover {
          color: var(--fg, #c9d1d9);
        }

        .modal-body {
          padding: 0.5rem;
          overflow-y: auto;
          flex: 1;
        }

        .sample-list {
          list-style: none;
          margin: 0;
          padding: 0;
        }

        .sample-list li {
          margin: 0;
        }

        .sample-item {
          display: block;
          width: 100%;
          padding: 0.625rem 0.75rem;
          background: none;
          border: none;
          color: var(--fg, #c9d1d9);
          text-align: left;
          cursor: pointer;
          font-family: inherit;
          font-size: 0.875rem;
          border-radius: 4px;
          transition: background 0.15s;
        }

        .sample-item:hover {
          background: var(--surface, #161b22);
        }

        .sample-item .sample-type {
          font-size: 0.625rem;
          text-transform: uppercase;
          color: var(--muted, #8b949e);
          margin-left: 0.5rem;
        }

        .load-sample-btn {
          width: 100%;
          margin-top: 1rem;
        }

        .network-select {
          font-family: inherit;
          font-size: 0.875rem;
          padding: 0.375rem 0.75rem;
          background: var(--surface, #161b22);
          border: 1px solid var(--border, #30363d);
          border-radius: 6px;
          color: var(--fg, #c9d1d9);
          cursor: pointer;
        }

        .network-select:focus {
          outline: none;
          border-color: var(--accent, #58a6ff);
        }

        .network-select option {
          background: var(--surface, #161b22);
          color: var(--fg, #c9d1d9);
        }
      `),
      h(
        "div",
        { class: "parser" },
        h(
          "nav",
          { class: "breadcrumb" },
          h("a", { href: "#/" }, "Home"),
          " / ",
          h("span", {}, "UTXO PSBT/TX Parser"),
        ),
        h("h1", {}, "UTXO PSBT/TX Parser"),
        !featureEnabled
          ? h(
              "div",
              { class: "feature-disabled" },
              "⚠ The parse_node feature is not enabled in this WASM build.",
            )
          : null,
        h(
          "div",
          { class: "parser-layout" },
          // Left panel: Controls
          h(
            "div",
            { class: "controls-panel" },
            h(
              "section",
              { class: "input-section" },
              h(
                "div",
                { class: "input-row" },
                h("textarea", {
                  id: "data-input",
                  placeholder: "Paste a PSBT or transaction (hex or base64)...",
                  rows: "6",
                  spellcheck: "false",
                  autocomplete: "off",
                  oninput: (e: Event) => this.handleInput(e),
                }),
              ),
              h(
                "div",
                { class: "controls-row" },
                h(
                  "div",
                  { class: "controls-row-group" },
                  h("span", { class: "mode-label" }, "Mode:"),
                  h(
                    "div",
                    { class: "btn-group" },
                    h(
                      "button",
                      {
                        id: "mode-psbt",
                        class: "btn active",
                        onclick: () => this.setMode("psbt"),
                      },
                      "PSBT",
                    ),
                    h(
                      "button",
                      {
                        id: "mode-psbt-raw",
                        class: "btn",
                        onclick: () => this.setMode("psbt-raw"),
                      },
                      "PSBT Raw",
                    ),
                    h(
                      "button",
                      {
                        id: "mode-tx",
                        class: "btn",
                        onclick: () => this.setMode("tx"),
                      },
                      "Transaction",
                    ),
                  ),
                ),
                h(
                  "div",
                  { class: "controls-row-group" },
                  h("span", { class: "mode-label" }, "Network:"),
                  h(
                    "select",
                    {
                      id: "network-select",
                      class: "network-select",
                      onchange: (e: Event) => this.setNetwork(e),
                    },
                    h("option", { value: "auto", selected: true }, "Auto-detect"),
                    ...allNetworks.map((network) =>
                      h("option", { value: network }, networkLabels[network]),
                    ),
                  ),
                ),
                h("span", { id: "detected-type", class: "detected-type" }),
                h(
                  "div",
                  { class: "action-buttons" },
                  h(
                    "div",
                    { class: "expand-controls" },
                    h(
                      "button",
                      {
                        class: "btn",
                        onclick: () => this.expandAll(),
                      },
                      "Expand All",
                    ),
                    h(
                      "button",
                      {
                        class: "btn",
                        onclick: () => this.collapseAll(),
                      },
                      "Collapse All",
                    ),
                  ),
                  h(
                    "button",
                    {
                      class: "btn",
                      onclick: () => this.share(),
                    },
                    "Share",
                  ),
                  h(
                    "button",
                    {
                      class: "btn",
                      onclick: () => this.clear(),
                    },
                    "Clear",
                  ),
                ),
              ),
            ),
            h("div", { id: "error-message" }),
            h(
              "button",
              {
                class: "btn load-sample-btn",
                onclick: () => this.openSampleModal(),
              },
              "Load Sample",
            ),
          ),
          // Right panel: Results
          h(
            "div",
            { class: "results-panel" },
            h(
              "div",
              { id: "results" },
              h(
                "div",
                { class: "empty-state" },
                h("p", {}, "Enter a PSBT or transaction to parse it"),
              ),
            ),
          ),
        ),
        // Sample modal
        h(
          "div",
          {
            id: "sample-modal",
            class: "modal-overlay",
            onclick: (e: Event) => {
              // Close modal when clicking on overlay (not the modal itself)
              if ((e.target as HTMLElement).classList.contains("modal-overlay")) {
                this.closeSampleModal();
              }
            },
          },
          h(
            "div",
            { class: "modal" },
            h(
              "div",
              { class: "modal-header" },
              h("h2", {}, "Load Sample"),
              h(
                "button",
                {
                  class: "modal-close",
                  onclick: () => this.closeSampleModal(),
                },
                "×",
              ),
            ),
            h(
              "div",
              { class: "modal-body" },
              h(
                "ul",
                { class: "sample-list" },
                ...samples.map((sample: Sample, index: number) =>
                  h(
                    "li",
                    {},
                    h(
                      "button",
                      {
                        class: "sample-item",
                        onclick: () => this.selectSample(index),
                      },
                      sample.name,
                      h(
                        "span",
                        { class: "sample-type" },
                        sample.type === "tx" ? "TX" : "PSBT",
                      ),
                    ),
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  onParamsChange(params: URLSearchParams): void {
    const data = params.get("data");
    const mode = params.get("mode") as ParseMode | null;
    const network = params.get("network");
    const input = this.$<HTMLTextAreaElement>("#data-input");

    if (mode && ["psbt", "psbt-raw", "tx"].includes(mode)) {
      this.currentMode = mode;
      this.updateModeButtons();
    }

    if (network) {
      if (network === "auto") {
        this.autoDetectNetwork = true;
      } else if (allNetworks.includes(network as CoinName)) {
        this.autoDetectNetwork = false;
        this.currentNetwork = network as CoinName;
      }
      this.updateNetworkSelect();
    }

    if (input && data) {
      input.value = data;
      this.parse(data);
    } else if (input && !data) {
      input.value = "";
      this.showEmpty();
    }
  }

  private handleInput(e: Event): void {
    const value = (e.target as HTMLTextAreaElement).value.trim();

    // Debounce URL updates
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
    }

    const networkParam = this.autoDetectNetwork ? "auto" : this.currentNetwork;
    this.debounceTimer = window.setTimeout(() => {
      setParams({ data: value, mode: this.currentMode, network: networkParam });
    }, 300);

    // Update results immediately
    if (value) {
      this.parse(value);
    } else {
      this.showEmpty();
    }
  }

  private openSampleModal(): void {
    const modal = this.$("#sample-modal");
    if (modal) {
      modal.classList.add("open");
    }
  }

  private closeSampleModal(): void {
    const modal = this.$("#sample-modal");
    if (modal) {
      modal.classList.remove("open");
    }
  }

  private selectSample(index: number): void {
    if (index < 0 || index >= samples.length) {
      return;
    }

    const sample = samples[index];
    const input = this.$<HTMLTextAreaElement>("#data-input");

    if (input) {
      input.value = sample.data;

      // Set mode based on sample type
      const mode: ParseMode = sample.type === "tx" ? "tx" : "psbt";
      this.currentMode = mode;
      this.updateModeButtons();

      // Reset to auto-detect for samples
      this.autoDetectNetwork = true;
      this.updateNetworkSelect();

      // Update URL and parse
      setParams({ data: sample.data, mode, network: "auto" });
      this.parse(sample.data);
    }

    this.closeSampleModal();
  }

  private setMode(mode: ParseMode): void {
    this.currentMode = mode;
    this.updateModeButtons();

    const input = this.$<HTMLTextAreaElement>("#data-input");
    const value = input?.value.trim();

    if (value) {
      setParams({ mode });
      this.parse(value);
    }
  }

  private setNetwork(e: Event): void {
    const select = e.target as HTMLSelectElement;
    const value = select.value;

    if (value === "auto") {
      this.autoDetectNetwork = true;
    } else {
      this.autoDetectNetwork = false;
      this.currentNetwork = value as CoinName;
    }

    const input = this.$<HTMLTextAreaElement>("#data-input");
    const inputValue = input?.value.trim();

    if (inputValue) {
      setParams({ network: value });
      this.parse(inputValue);
    }
  }

  private updateModeButtons(): void {
    const modes: ParseMode[] = ["psbt", "psbt-raw", "tx"];
    for (const m of modes) {
      const btn = this.$(`#mode-${m}`);
      if (btn) {
        btn.classList.toggle("active", m === this.currentMode);
      }
    }
  }

  private updateNetworkSelect(): void {
    const select = this.$<HTMLSelectElement>("#network-select");
    if (select) {
      select.value = this.autoDetectNetwork ? "auto" : this.currentNetwork;
    }
  }

  private parse(input: string): void {
    const errorEl = this.$("#error-message");
    const resultsEl = this.$("#results");
    const detectedEl = this.$("#detected-type");

    if (!errorEl || !resultsEl || !detectedEl) return;

    // Clear previous state
    errorEl.innerHTML = "";
    this.expandedPaths = new Set(["root"]);

    let bytes: Uint8Array;
    try {
      bytes = decodeInput(input);
    } catch (e) {
      errorEl.replaceChildren(h("div", { class: "error-message" }, `Failed to decode input: ${e}`));
      resultsEl.replaceChildren(
        h("div", { class: "empty-state" }, h("p", {}, "Enter valid hex or base64 data")),
      );
      return;
    }

    // Auto-detect type (PSBT vs TX)
    const detectedPsbt = isPsbt(bytes);

    // Parse based on mode with network handling
    let node: Node;
    let detectedNetwork: CoinName | null = null;

    try {
      if (this.autoDetectNetwork) {
        // Try all networks and pick the first one that works
        if (this.currentMode === "psbt") {
          const result = tryParsePsbt(bytes);
          if (result) {
            detectedNetwork = result.network;
            this.currentNetwork = result.network;
            node = result.node;
          } else {
            throw new Error("Failed to parse PSBT with any known network");
          }
        } else if (this.currentMode === "psbt-raw") {
          const result = tryParsePsbtRaw(bytes);
          if (result) {
            detectedNetwork = result.network;
            this.currentNetwork = result.network;
            node = result.node;
          } else {
            throw new Error("Failed to parse raw PSBT with any known network");
          }
        } else {
          const result = tryParseTx(bytes);
          if (result) {
            detectedNetwork = result.network;
            this.currentNetwork = result.network;
            node = result.node;
          } else {
            throw new Error("Failed to parse transaction with any known network");
          }
        }
      } else {
        // Use the specified network
        switch (this.currentMode) {
          case "psbt":
            node = parsePsbtToNode(bytes, this.currentNetwork);
            break;
          case "psbt-raw":
            node = parsePsbtRawToNode(bytes, this.currentNetwork);
            break;
          case "tx":
            node = parseTxToNode(bytes, this.currentNetwork);
            break;
        }
      }
    } catch (e) {
      errorEl.replaceChildren(h("div", { class: "error-message" }, `Parse error: ${e}`));
      resultsEl.replaceChildren(
        h("div", { class: "empty-state" }, h("p", {}, "Failed to parse data")),
      );
      return;
    }

    // Update detected type display
    const typeStr = detectedPsbt ? "PSBT" : "Transaction";
    const networkStr = detectedNetwork
      ? ` · Network: ${networkLabels[detectedNetwork]}`
      : ` · Network: ${networkLabels[this.currentNetwork]}`;
    detectedEl.textContent = `Detected: ${typeStr}${networkStr}`;

    this.currentNode = node;
    this.renderTree();
  }

  private renderTree(): void {
    const resultsEl = this.$("#results");
    if (!resultsEl || !this.currentNode) return;

    const treeEl = renderTreeNode(this.currentNode, this.expandedPaths, (path) => {
      if (this.expandedPaths.has(path)) {
        this.expandedPaths.delete(path);
      } else {
        this.expandedPaths.add(path);
      }
      this.renderTree();
    });

    resultsEl.replaceChildren(h("div", { class: "tree-container" }, treeEl));
  }

  private expandAll(): void {
    if (!this.currentNode) return;

    // Collect all paths
    const collectPaths = (node: Node, path: string): void => {
      this.expandedPaths.add(path);
      node.children.forEach((child, i) => {
        collectPaths(child, `${path}.${i}`);
      });
    };

    collectPaths(this.currentNode, "root");
    this.renderTree();
  }

  private collapseAll(): void {
    this.expandedPaths = new Set(["root"]);
    this.renderTree();
  }

  private showEmpty(): void {
    const errorEl = this.$("#error-message");
    const resultsEl = this.$("#results");
    const detectedEl = this.$("#detected-type");

    if (errorEl) errorEl.innerHTML = "";
    if (detectedEl) detectedEl.textContent = "";
    if (resultsEl) {
      resultsEl.replaceChildren(
        h(
          "div",
          { class: "empty-state" },
          h("p", {}, "Enter a PSBT or transaction above to parse it"),
        ),
      );
    }
    this.currentNode = null;
  }

  private share(): void {
    copyToClipboard(location.href, this.$(".btn")!);
  }

  private clear(): void {
    const input = this.$<HTMLTextAreaElement>("#data-input");
    if (input) {
      input.value = "";
      setParams({ data: "", mode: "" });
      this.showEmpty();
    }
  }
}

defineComponent("psbt-tx-parser", PsbtTxParser);
