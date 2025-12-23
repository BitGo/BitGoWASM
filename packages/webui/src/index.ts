/**
 * BitGoWASM WebUI - Entry Point
 *
 * Initializes the router and registers all demo components.
 */

import { BaseComponent, defineComponent, h, css, fragment } from "./lib/html";
import { initRouter, type Route } from "./lib/router";

// Import demo components (registers them as custom elements)
import "./wasm-utxo/addresses";
import "./wasm-utxo/parser";

// Common styles used across components
export const commonStyles = `
  * {
    box-sizing: border-box;
  }

  :host {
    display: block;
    font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
    color: var(--fg, #c9d1d9);
    line-height: 1.5;
  }

  a {
    color: var(--accent, #58a6ff);
    text-decoration: none;
  }

  a:hover {
    text-decoration: underline;
  }

  button, input, textarea, select {
    font-family: inherit;
  }

  h1, h2, h3 {
    margin: 0 0 1rem;
    font-weight: 500;
  }

  h1 {
    font-size: 1.5rem;
    color: var(--fg, #c9d1d9);
  }

  h2 {
    font-size: 1.25rem;
  }

  .breadcrumb {
    font-size: 0.875rem;
    margin-bottom: 1.5rem;
    color: var(--muted, #8b949e);
  }

  .breadcrumb a {
    color: var(--accent, #58a6ff);
  }

  .breadcrumb span {
    color: var(--fg, #c9d1d9);
  }
`;

/**
 * Home page component - navigation hub for all demos.
 */
class HomePage extends BaseComponent {
  render() {
    return fragment(
      css(`
        ${commonStyles}

        .home {
          max-width: 800px;
        }

        .demo-list {
          list-style: none;
          padding: 0;
          margin: 2rem 0;
        }

        .demo-list li {
          margin-bottom: 1rem;
        }

        .demo-link {
          display: block;
          padding: 1rem 1.25rem;
          background: var(--surface, #161b22);
          border: 1px solid var(--border, #30363d);
          border-radius: 6px;
          transition: border-color 0.15s, background 0.15s;
        }

        .demo-link:hover {
          border-color: var(--accent, #58a6ff);
          background: var(--surface-hover, #1c2128);
          text-decoration: none;
        }

        .demo-title {
          font-weight: 500;
          margin-bottom: 0.25rem;
        }

        .demo-desc {
          font-size: 0.875rem;
          color: var(--muted, #8b949e);
        }

        .subtitle {
          color: var(--muted, #8b949e);
          margin-bottom: 2rem;
        }
      `),
      h(
        "div",
        { class: "home" },
        h("h1", {}, "BitGoWASM Demos"),
        h("p", { class: "subtitle" }, "Developer tools for BitGoWASM libraries"),
        h(
          "ul",
          { class: "demo-list" },
          h(
            "li",
            {},
            h(
              "a",
              { class: "demo-link", href: "#/wasm-utxo/addresses" },
              h("div", { class: "demo-title" }, "UTXO Address Converter"),
              h(
                "div",
                { class: "demo-desc" },
                "Convert utxo addresses between different networks and formats",
              ),
            ),
          ),
          h(
            "li",
            {},
            h(
              "a",
              { class: "demo-link", href: "#/wasm-utxo/parser" },
              h("div", { class: "demo-title" }, "UTXO PSBT/TX Parser"),
              h(
                "div",
                { class: "demo-desc" },
                "Parse and inspect PSBTs and transactions as collapsible trees",
              ),
            ),
          ),
        ),
      ),
    );
  }
}

defineComponent("home-page", HomePage);

// Route configuration
const routes: Route[] = [
  { path: "/", component: "home-page" },
  { path: "/wasm-utxo/addresses", component: "address-converter" },
  { path: "/wasm-utxo/parser", component: "psbt-tx-parser" },
];

// Initialize router when DOM is ready
function init() {
  const app = document.getElementById("app");
  if (!app) {
    throw new Error("Could not find #app container");
  }
  initRouter(app, routes);
}

// Handle both cases: DOMContentLoaded already fired or not yet
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
