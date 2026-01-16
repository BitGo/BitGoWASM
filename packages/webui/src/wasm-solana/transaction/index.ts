/**
 * Solana Transaction Parser Demo
 *
 * Parses Solana transactions and displays decoded instruction data.
 * Accepts base64-encoded transaction bytes.
 */

import { BaseComponent, defineComponent, h, css, fragment, type Child } from "../../lib/html";
import { setParams } from "../../lib/router";
import { commonStyles } from "../../index";
import {
  parseTransaction,
  type ParsedTransaction,
  type InstructionParams,
} from "@bitgo/wasm-solana";

/**
 * Decode base64 to Uint8Array
 */
function base64ToBytes(base64: string): Uint8Array {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
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
 * Format instruction type for display
 */
function formatInstructionType(type: string): string {
  // Add spaces before capital letters for readability
  return type.replace(/([A-Z])/g, " $1").trim();
}

/**
 * Get instruction type color
 */
function getTypeColor(type: string): string {
  const colors: Record<string, string> = {
    Transfer: "var(--green)",
    NonceAdvance: "var(--purple)",
    Memo: "var(--yellow)",
    TokenTransfer: "var(--sky-blue)",
    CreateAccount: "var(--teal)",
    StakingActivate: "var(--orange)",
    StakingDeactivate: "var(--orange)",
    StakingWithdraw: "var(--orange)",
    StakingDelegate: "var(--orange)",
    StakingAuthorize: "var(--orange)",
    SetComputeUnitLimit: "var(--lavender)",
    SetPriorityFee: "var(--lavender)",
    CreateAssociatedTokenAccount: "var(--teal)",
    CloseAssociatedTokenAccount: "var(--red)",
    Unknown: "var(--muted)",
  };
  return colors[type] || "var(--fg)";
}

/**
 * Solana Transaction Parser Web Component
 */
class SolanaTransactionParser extends BaseComponent {
  private debounceTimer: number | null = null;

  render() {
    return fragment(
      css(`
        ${commonStyles}

        .parser {
          max-width: 1000px;
        }

        .input-section {
          margin-bottom: 2rem;
        }

        .input-row {
          display: flex;
          gap: 0.5rem;
        }

        textarea {
          flex: 1;
          font-family: inherit;
          font-size: 0.875rem;
          padding: 0.75rem 1rem;
          background: var(--surface, #161b22);
          border: 1px solid var(--border, #30363d);
          border-radius: 6px;
          color: var(--fg, #c9d1d9);
          resize: vertical;
          min-height: 80px;
        }

        textarea:focus {
          outline: none;
          border-color: var(--accent, #58a6ff);
        }

        textarea::placeholder {
          color: var(--muted, #8b949e);
        }

        .btn {
          padding: 0.75rem 1rem;
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

        .error-message {
          padding: 1rem;
          background: rgba(248, 81, 73, 0.1);
          border: 1px solid rgba(248, 81, 73, 0.4);
          border-radius: 6px;
          color: #f85149;
          margin-bottom: 2rem;
        }

        .tx-info {
          margin-bottom: 2rem;
          padding: 1rem;
          background: var(--surface, #161b22);
          border: 1px solid var(--border, #30363d);
          border-radius: 6px;
        }

        .tx-info-grid {
          display: grid;
          grid-template-columns: 140px 1fr;
          gap: 0.5rem 1rem;
        }

        .tx-info-label {
          font-size: 0.8125rem;
          color: var(--muted, #8b949e);
        }

        .tx-info-value {
          font-size: 0.8125rem;
          word-break: break-all;
          color: var(--fg, #c9d1d9);
        }

        .tx-info-value.mono {
          font-family: var(--mono);
        }

        .instructions-section h2 {
          font-size: 1rem;
          margin-bottom: 1rem;
          color: var(--muted, #8b949e);
        }

        .instruction-card {
          margin-bottom: 1rem;
          padding: 1rem;
          background: var(--surface, #161b22);
          border: 1px solid var(--border, #30363d);
          border-radius: 6px;
        }

        .instruction-header {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          margin-bottom: 0.75rem;
        }

        .instruction-index {
          font-size: 0.75rem;
          padding: 0.125rem 0.5rem;
          background: var(--border, #30363d);
          border-radius: 4px;
          color: var(--muted, #8b949e);
        }

        .instruction-type {
          font-weight: 500;
          font-size: 0.9375rem;
        }

        .instruction-params {
          display: grid;
          grid-template-columns: 140px 1fr;
          gap: 0.25rem 1rem;
          font-size: 0.8125rem;
        }

        .param-name {
          color: var(--muted, #8b949e);
        }

        .param-value {
          word-break: break-all;
          color: var(--fg, #c9d1d9);
        }

        .copy-btn {
          padding: 0.25rem 0.5rem;
          font-size: 0.75rem;
          background: transparent;
          border: 1px solid var(--border, #30363d);
          border-radius: 4px;
          color: var(--muted, #8b949e);
          cursor: pointer;
          transition: all 0.15s;
          margin-left: 0.5rem;
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

        .empty-state p {
          margin: 0;
        }

        .durable-nonce-badge {
          font-size: 0.75rem;
          padding: 0.125rem 0.5rem;
          background: var(--purple);
          color: var(--bg);
          border-radius: 4px;
        }

        .account-keys-section {
          margin-bottom: 2rem;
        }

        .account-keys-section h2 {
          font-size: 1rem;
          margin-bottom: 1rem;
          color: var(--muted, #8b949e);
        }

        .account-keys-list {
          padding: 1rem;
          background: var(--surface, #161b22);
          border: 1px solid var(--border, #30363d);
          border-radius: 6px;
        }

        .account-key-item {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          padding: 0.375rem 0;
          font-size: 0.8125rem;
        }

        .account-key-item:not(:last-child) {
          border-bottom: 1px solid var(--border, #30363d);
        }

        .account-key-index {
          font-size: 0.75rem;
          padding: 0.125rem 0.5rem;
          background: var(--border, #30363d);
          border-radius: 4px;
          color: var(--muted, #8b949e);
          min-width: 2rem;
          text-align: center;
        }

        .account-key-address {
          font-family: var(--mono);
          word-break: break-all;
          color: var(--fg, #c9d1d9);
        }

        .account-key-item.fee-payer .account-key-address {
          color: var(--green);
        }

        .account-key-badge {
          font-size: 0.625rem;
          padding: 0.125rem 0.375rem;
          border-radius: 3px;
          text-transform: uppercase;
          font-weight: 500;
        }

        .account-key-badge.fee-payer {
          background: var(--green);
          color: var(--bg);
        }

        @media (max-width: 768px) {
          .tx-info-grid,
          .instruction-params {
            grid-template-columns: 1fr;
            gap: 0.125rem;
          }

          .tx-info-label,
          .param-name {
            font-weight: 500;
          }
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
          h("span", {}, "Solana Transaction Parser"),
        ),
        h("h1", {}, "Solana Transaction Parser"),
        h(
          "section",
          { class: "input-section" },
          h(
            "div",
            { class: "input-row" },
            h("textarea", {
              id: "tx-input",
              placeholder: "Paste a base64-encoded Solana transaction...",
              rows: "3",
              oninput: (e: Event) => this.handleInput(e),
            }),
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
        h("div", { id: "error-message" }),
        h("div", { id: "tx-info" }),
        h("div", { id: "account-keys" }),
        h(
          "div",
          { id: "results" },
          h(
            "div",
            { class: "empty-state" },
            h("p", {}, "Enter a base64-encoded Solana transaction above to parse it"),
          ),
        ),
      ),
    );
  }

  onParamsChange(params: URLSearchParams): void {
    const data = params.get("data");
    const input = this.$<HTMLTextAreaElement>("#tx-input");

    if (input && data) {
      // URL decode the data parameter
      const decoded = decodeURIComponent(data);
      input.value = decoded;
      this.parse(decoded);
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

    this.debounceTimer = window.setTimeout(() => {
      setParams({ data: value ? encodeURIComponent(value) : "" });
    }, 300);

    // Update results immediately
    if (value) {
      this.parse(value);
    } else {
      this.showEmpty();
    }
  }

  private parse(txData: string): void {
    const errorEl = this.$("#error-message");
    const txInfoEl = this.$("#tx-info");
    const accountKeysEl = this.$("#account-keys");
    const resultsEl = this.$("#results");

    if (!errorEl || !txInfoEl || !accountKeysEl || !resultsEl) return;

    // Clear previous state
    errorEl.innerHTML = "";
    txInfoEl.innerHTML = "";
    accountKeysEl.innerHTML = "";

    try {
      // Parse the transaction
      const bytes = base64ToBytes(txData);
      const parsed = parseTransaction(bytes);

      // Render transaction info
      txInfoEl.replaceChildren(this.renderTxInfo(parsed));

      // Render account keys
      accountKeysEl.replaceChildren(this.renderAccountKeys(parsed));

      // Render instructions
      resultsEl.replaceChildren(
        h(
          "section",
          { class: "instructions-section" },
          h("h2", {}, `Instructions (${parsed.instructionsData.length})`),
          ...parsed.instructionsData.map((instr, idx) => this.renderInstruction(instr, idx)),
        ),
      );
    } catch (e) {
      errorEl.replaceChildren(
        h("div", { class: "error-message" }, `Failed to parse transaction: ${String(e)}`),
      );
      resultsEl.replaceChildren(
        h(
          "div",
          { class: "empty-state" },
          h("p", {}, "Enter a valid Solana transaction to see parsed data"),
        ),
      );
    }
  }

  private renderTxInfo(parsed: ParsedTransaction): HTMLElement {
    const children: Child[] = [
      h("span", { class: "tx-info-label" }, "Fee Payer"),
      h("span", { class: "tx-info-value mono" }, parsed.feePayer),
      h("span", { class: "tx-info-label" }, "Blockhash/Nonce"),
      h("span", { class: "tx-info-value mono" }, parsed.nonce),
      h("span", { class: "tx-info-label" }, "Signatures"),
      h("span", { class: "tx-info-value" }, String(parsed.numSignatures)),
    ];

    if (parsed.durableNonce) {
      children.push(
        h("span", { class: "tx-info-label" }, "Durable Nonce"),
        h("span", { class: "tx-info-value" }, h("span", { class: "durable-nonce-badge" }, "Yes")),
        h("span", { class: "tx-info-label" }, "Nonce Account"),
        h("span", { class: "tx-info-value mono" }, parsed.durableNonce.walletNonceAddress),
        h("span", { class: "tx-info-label" }, "Nonce Authority"),
        h("span", { class: "tx-info-value mono" }, parsed.durableNonce.authWalletAddress),
      );
    }

    return h("div", { class: "tx-info" }, h("div", { class: "tx-info-grid" }, ...children));
  }

  private renderAccountKeys(parsed: ParsedTransaction): HTMLElement {
    const feePayer = parsed.feePayer;

    return h(
      "section",
      { class: "account-keys-section" },
      h("h2", {}, `Account Keys (${parsed.accountKeys.length})`),
      h(
        "div",
        { class: "account-keys-list" },
        ...parsed.accountKeys.map((key, idx) => {
          const isFeePayer = key === feePayer;
          return h(
            "div",
            { class: `account-key-item${isFeePayer ? " fee-payer" : ""}` },
            h("span", { class: "account-key-index" }, String(idx)),
            h("span", { class: "account-key-address" }, key),
            isFeePayer ? h("span", { class: "account-key-badge fee-payer" }, "Fee Payer") : null,
          );
        }),
      ),
    );
  }

  private renderInstruction(instr: InstructionParams, index: number): HTMLElement {
    const type = instr.type;
    const typeColor = getTypeColor(type);

    // Extract params (everything except 'type')
    const params = Object.entries(instr).filter(([key]) => key !== "type");

    return h(
      "div",
      { class: "instruction-card" },
      h(
        "div",
        { class: "instruction-header" },
        h("span", { class: "instruction-index" }, `#${index}`),
        h(
          "span",
          { class: "instruction-type", style: `color: ${typeColor}` },
          formatInstructionType(type),
        ),
      ),
      params.length > 0
        ? h(
            "div",
            { class: "instruction-params" },
            ...params.flatMap(([key, value]) => [
              h("span", { class: "param-name" }, key),
              h("span", { class: "param-value" }, this.formatParamValue(value)),
            ]),
          )
        : null,
    );
  }

  private formatParamValue(value: unknown): string {
    if (typeof value === "string") {
      return value;
    }
    if (typeof value === "number" || typeof value === "bigint") {
      return String(value);
    }
    if (Array.isArray(value)) {
      return JSON.stringify(value);
    }
    if (value && typeof value === "object") {
      return JSON.stringify(value);
    }
    return String(value);
  }

  private showEmpty(): void {
    const errorEl = this.$("#error-message");
    const txInfoEl = this.$("#tx-info");
    const accountKeysEl = this.$("#account-keys");
    const resultsEl = this.$("#results");

    if (errorEl) errorEl.innerHTML = "";
    if (txInfoEl) txInfoEl.innerHTML = "";
    if (accountKeysEl) accountKeysEl.innerHTML = "";
    if (resultsEl) {
      resultsEl.replaceChildren(
        h(
          "div",
          { class: "empty-state" },
          h("p", {}, "Enter a base64-encoded Solana transaction above to parse it"),
        ),
      );
    }
  }

  private share(): void {
    copyToClipboard(location.href, this.$(".btn")!);
  }

  private clear(): void {
    const input = this.$<HTMLTextAreaElement>("#tx-input");
    if (input) {
      input.value = "";
      setParams({ data: "" });
      this.showEmpty();
    }
  }
}

defineComponent("solana-transaction-parser", SolanaTransactionParser);
