/**
 * Address Converter Demo
 *
 * Converts cryptocurrency addresses between different networks and formats.
 * Supports base58, bech32, and cashaddr encodings.
 */

import { BaseComponent, defineComponent, h, css, fragment, type Child } from "../../lib/html";
import { setParams } from "../../lib/router";
import { commonStyles } from "../../index";
import { address, type CoinName, type AddressFormat } from "@bitgo/wasm-utxo";

const { toOutputScriptWithCoin, fromOutputScriptWithCoin } = address;

// All supported coins
const ALL_COINS: CoinName[] = [
  "btc",
  "tbtc",
  "tbtc4",
  "tbtcsig",
  "tbtcbgsig",
  "bch",
  "tbch",
  "bcha",
  "tbcha",
  "btg",
  "tbtg",
  "bsv",
  "tbsv",
  "dash",
  "tdash",
  "doge",
  "tdoge",
  "ltc",
  "tltc",
  "zec",
  "tzec",
];

// Coins that support cashaddr format
const CASHADDR_COINS: CoinName[] = ["bch", "tbch", "bcha", "tbcha"];

// Coin display names
const COIN_NAMES: Record<CoinName, string> = {
  btc: "Bitcoin",
  tbtc: "Bitcoin Testnet",
  tbtc4: "Bitcoin Testnet4",
  tbtcsig: "Bitcoin Signet",
  tbtcbgsig: "Bitcoin BitGo Signet",
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
  ltc: "Litecoin",
  tltc: "Litecoin Testnet",
  zec: "Zcash",
  tzec: "Zcash Testnet",
};

interface ConversionResult {
  coin: CoinName;
  address: string;
  format: AddressFormat;
}

interface ConversionError {
  coin: CoinName;
  error: string;
  format: AddressFormat;
}

type ConversionOutcome = ConversionResult | ConversionError;

function isError(outcome: ConversionOutcome): outcome is ConversionError {
  return "error" in outcome;
}

/**
 * Try to decode an address with any coin and return the output script.
 */
function decodeAddress(address: string): { script: Uint8Array; coin: CoinName } | null {
  for (const coin of ALL_COINS) {
    try {
      const script = toOutputScriptWithCoin(address, coin);
      return { script, coin };
    } catch {
      // Try next coin
    }
  }
  return null;
}

/**
 * Convert an output script to addresses for all networks and formats.
 */
function convertToAllNetworks(script: Uint8Array): ConversionOutcome[] {
  const results: ConversionOutcome[] = [];

  for (const coin of ALL_COINS) {
    // Try default format
    try {
      const address = fromOutputScriptWithCoin(script, coin);
      results.push({ coin, address, format: "default" });
    } catch (e) {
      results.push({ coin, error: String(e), format: "default" });
    }

    // Try cashaddr format for BCH/eCash
    if (CASHADDR_COINS.includes(coin)) {
      try {
        const address = fromOutputScriptWithCoin(script, coin, "cashaddr");
        results.push({ coin, address, format: "cashaddr" });
      } catch (e) {
        results.push({ coin, error: String(e), format: "cashaddr" });
      }
    }
  }

  return results;
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
 * Address Converter Web Component
 */
class AddressConverter extends BaseComponent {
  private debounceTimer: number | null = null;

  render() {
    return fragment(
      css(`
        ${commonStyles}

        .converter {
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
          font-size: 0.9375rem;
          padding: 0.75rem 1rem;
          background: var(--surface, #161b22);
          border: 1px solid var(--border, #30363d);
          border-radius: 6px;
          color: var(--fg, #c9d1d9);
          resize: vertical;
          min-height: 60px;
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

        .btn-primary {
          background: var(--accent, #58a6ff);
          border-color: var(--accent, #58a6ff);
          color: var(--bg, #0d1117);
        }

        .btn-primary:hover {
          background: var(--accent-hover, #79b8ff);
          border-color: var(--accent-hover, #79b8ff);
        }

        .script-info {
          margin-bottom: 2rem;
          padding: 1rem;
          background: var(--surface, #161b22);
          border: 1px solid var(--border, #30363d);
          border-radius: 6px;
        }

        .script-info h3 {
          font-size: 0.875rem;
          color: var(--muted, #8b949e);
          margin-bottom: 0.5rem;
        }

        .script-hex {
          font-size: 0.8125rem;
          word-break: break-all;
          color: var(--fg, #c9d1d9);
        }

        .error-message {
          padding: 1rem;
          background: rgba(248, 81, 73, 0.1);
          border: 1px solid rgba(248, 81, 73, 0.4);
          border-radius: 6px;
          color: #f85149;
          margin-bottom: 2rem;
        }

        .results-section h2 {
          font-size: 1rem;
          margin-bottom: 1rem;
          color: var(--muted, #8b949e);
        }

        .results-group {
          margin-bottom: 2rem;
        }

        .results-group-title {
          font-size: 0.75rem;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          color: var(--muted, #8b949e);
          margin-bottom: 0.75rem;
          padding-bottom: 0.5rem;
          border-bottom: 1px solid var(--border, #30363d);
        }

        .result-row {
          display: grid;
          grid-template-columns: 140px 80px 1fr auto;
          gap: 0.75rem;
          align-items: center;
          padding: 0.5rem 0;
          border-bottom: 1px solid var(--border-subtle, #21262d);
        }

        .result-row:last-child {
          border-bottom: none;
        }

        .result-coin {
          font-size: 0.8125rem;
          color: var(--muted, #8b949e);
        }

        .result-format {
          font-size: 0.75rem;
          color: var(--muted, #8b949e);
          opacity: 0.7;
        }

        .result-address {
          font-size: 0.8125rem;
          word-break: break-all;
          color: var(--fg, #c9d1d9);
        }

        .result-error {
          font-size: 0.75rem;
          color: var(--muted, #8b949e);
          opacity: 0.5;
          font-style: italic;
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

        @media (max-width: 768px) {
          .result-row {
            grid-template-columns: 1fr auto;
            gap: 0.25rem;
          }

          .result-coin {
            grid-column: 1 / -1;
          }

          .result-format {
            grid-column: 1;
          }

          .result-address {
            grid-column: 1 / -1;
            font-size: 0.75rem;
          }
        }
      `),
      h(
        "div",
        { class: "converter" },
        h(
          "nav",
          { class: "breadcrumb" },
          h("a", { href: "#/" }, "Home"),
          " / ",
          h("span", {}, "UTXO Address Converter"),
        ),
        h("h1", {}, "UTXO Address Converter"),
        h(
          "section",
          { class: "input-section" },
          h(
            "div",
            { class: "input-row" },
            h("textarea", {
              id: "address-input",
              placeholder: "Paste a utxo address...",
              rows: "2",
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
        h("div", { id: "script-info" }),
        h("div", { id: "error-message" }),
        h(
          "div",
          { id: "results" },
          h(
            "div",
            { class: "empty-state" },
            h("p", {}, "Enter an address above to convert it across networks"),
          ),
        ),
      ),
    );
  }

  onParamsChange(params: URLSearchParams): void {
    const address = params.get("a");
    const input = this.$<HTMLTextAreaElement>("#address-input");

    if (input && address) {
      input.value = address;
      this.convert(address);
    } else if (input && !address) {
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
      setParams({ a: value });
    }, 300);

    // Update results immediately
    if (value) {
      this.convert(value);
    } else {
      this.showEmpty();
    }
  }

  private convert(address: string): void {
    const scriptInfoEl = this.$("#script-info");
    const errorEl = this.$("#error-message");
    const resultsEl = this.$("#results");

    if (!scriptInfoEl || !errorEl || !resultsEl) return;

    // Clear previous state
    scriptInfoEl.innerHTML = "";
    errorEl.innerHTML = "";

    // Try to decode the address
    const decoded = decodeAddress(address);

    if (!decoded) {
      errorEl.replaceChildren(
        h(
          "div",
          { class: "error-message" },
          "Could not decode address. Please check it's a valid cryptocurrency address.",
        ),
      );
      resultsEl.replaceChildren(
        h("div", { class: "empty-state" }, h("p", {}, "Enter a valid address to see conversions")),
      );
      return;
    }

    // Show script info
    const hexString = toHex(decoded.script);
    scriptInfoEl.replaceChildren(
      h(
        "div",
        { class: "script-info" },
        h("h3", {}, `Output Script (decoded as ${decoded.coin})`),
        h("code", { class: "script-hex" }, hexString),
        h(
          "button",
          {
            class: "copy-btn",
            style: "margin-left: 0.5rem",
            onclick: (e: Event) => copyToClipboard(hexString, e.target as HTMLElement),
          },
          "Copy",
        ),
      ),
    );

    // Convert to all networks
    const outcomes = convertToAllNetworks(decoded.script);

    // Group results by mainnet/testnet
    const mainnetResults = outcomes.filter((r) => !r.coin.startsWith("t"));
    const testnetResults = outcomes.filter((r) => r.coin.startsWith("t"));

    resultsEl.replaceChildren(
      h(
        "section",
        { class: "results-section" },
        this.renderResultGroup("Mainnet", mainnetResults),
        this.renderResultGroup("Testnet", testnetResults),
      ),
    );
  }

  private renderResultGroup(title: string, outcomes: ConversionOutcome[]): HTMLElement {
    return h(
      "div",
      { class: "results-group" },
      h("div", { class: "results-group-title" }, title),
      ...outcomes.map((outcome) => this.renderResult(outcome)),
    );
  }

  private renderResult(outcome: ConversionOutcome): Child {
    const coinName = COIN_NAMES[outcome.coin];
    const formatLabel = outcome.format === "cashaddr" ? "cashaddr" : "default";

    if (isError(outcome)) {
      // Don't show errors for cashaddr on non-cashaddr coins
      if (outcome.format === "cashaddr") {
        return null;
      }
      return h(
        "div",
        { class: "result-row" },
        h("span", { class: "result-coin" }, coinName),
        h("span", { class: "result-format" }, formatLabel),
        h("span", { class: "result-error" }, "Not supported"),
        h("span", {}),
      );
    }

    return h(
      "div",
      { class: "result-row" },
      h("span", { class: "result-coin" }, coinName),
      h("span", { class: "result-format" }, formatLabel),
      h("span", { class: "result-address" }, outcome.address),
      h(
        "button",
        {
          class: "copy-btn",
          onclick: (e: Event) => copyToClipboard(outcome.address, e.target as HTMLElement),
        },
        "Copy",
      ),
    );
  }

  private showEmpty(): void {
    const scriptInfoEl = this.$("#script-info");
    const errorEl = this.$("#error-message");
    const resultsEl = this.$("#results");

    if (scriptInfoEl) scriptInfoEl.innerHTML = "";
    if (errorEl) errorEl.innerHTML = "";
    if (resultsEl) {
      resultsEl.replaceChildren(
        h(
          "div",
          { class: "empty-state" },
          h("p", {}, "Enter an address above to convert it across networks"),
        ),
      );
    }
  }

  private share(): void {
    copyToClipboard(location.href, this.$(".btn")!);
  }

  private clear(): void {
    const input = this.$<HTMLTextAreaElement>("#address-input");
    if (input) {
      input.value = "";
      setParams({ a: "" });
      this.showEmpty();
    }
  }
}

defineComponent("address-converter", AddressConverter);
