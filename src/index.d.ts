/**
 * BitGoWASM WebUI - Entry Point
 *
 * Initializes the router and registers all demo components.
 */
import "./wasm-utxo/addresses";
import "./wasm-utxo/parser";
export declare const commonStyles = "\n  * {\n    box-sizing: border-box;\n  }\n\n  :host {\n    display: block;\n    font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;\n    color: var(--fg, #c9d1d9);\n    line-height: 1.5;\n  }\n\n  a {\n    color: var(--accent, #58a6ff);\n    text-decoration: none;\n  }\n\n  a:hover {\n    text-decoration: underline;\n  }\n\n  button, input, textarea, select {\n    font-family: inherit;\n  }\n\n  h1, h2, h3 {\n    margin: 0 0 1rem;\n    font-weight: 500;\n  }\n\n  h1 {\n    font-size: 1.5rem;\n    color: var(--fg, #c9d1d9);\n  }\n\n  h2 {\n    font-size: 1.25rem;\n  }\n\n  .breadcrumb {\n    font-size: 0.875rem;\n    margin-bottom: 1.5rem;\n    color: var(--muted, #8b949e);\n  }\n\n  .breadcrumb a {\n    color: var(--accent, #58a6ff);\n  }\n\n  .breadcrumb span {\n    color: var(--fg, #c9d1d9);\n  }\n";
