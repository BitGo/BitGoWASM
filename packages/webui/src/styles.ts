/** Common styles shared across all web components. */
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
