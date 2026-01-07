/**
 * Minimal hyperscript-style HTML helper library with Web Component base class.
 * No dependencies, no virtual DOM - just real DOM nodes.
 */

// Types for the h() function
export type Child = Node | string | number | null | undefined | false | Child[];
export type EventHandler<E extends Event = Event> = (event: E) => void;

export type Props = {
  [key: string]: string | number | boolean | EventHandler | undefined;
};

/**
 * Flatten nested arrays of children, filtering out nullish values.
 */
function flattenChildren(children: Child[]): (Node | string)[] {
  const result: (Node | string)[] = [];
  for (const child of children) {
    if (child === null || child === undefined || child === false) {
      continue;
    }
    if (Array.isArray(child)) {
      result.push(...flattenChildren(child));
    } else if (child instanceof Node) {
      result.push(child);
    } else {
      result.push(String(child));
    }
  }
  return result;
}

/**
 * Hyperscript-style element creation.
 *
 * @example
 * h('div', { class: 'container', onclick: () => console.log('clicked') },
 *   h('span', {}, 'Hello'),
 *   ' World'
 * )
 */
export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props?: Props | null,
  ...children: Child[]
): HTMLElementTagNameMap[K];
export function h(tag: string, props?: Props | null, ...children: Child[]): HTMLElement;
export function h(tag: string, props?: Props | null, ...children: Child[]): HTMLElement {
  const element = document.createElement(tag);

  if (props) {
    for (const [key, value] of Object.entries(props)) {
      if (value === undefined || value === false) {
        continue;
      }

      // Event handlers: onclick, oninput, etc.
      if (key.startsWith("on") && typeof value === "function") {
        const eventName = key.slice(2).toLowerCase();
        element.addEventListener(eventName, value as EventListener);
      }
      // Boolean attributes
      else if (value === true) {
        element.setAttribute(key, "");
      }
      // Regular attributes
      else {
        element.setAttribute(key, String(value));
      }
    }
  }

  const flatChildren = flattenChildren(children);
  for (const child of flatChildren) {
    if (typeof child === "string") {
      element.appendChild(document.createTextNode(child));
    } else {
      element.appendChild(child);
    }
  }

  return element;
}

/**
 * Create a text node.
 */
export function text(content: string): Text {
  return document.createTextNode(content);
}

/**
 * Base class for Web Components with common patterns.
 */
export abstract class BaseComponent extends HTMLElement {
  protected shadow: ShadowRoot;

  constructor() {
    super();
    this.shadow = this.attachShadow({ mode: "open" });
  }

  /**
   * Called when the element is added to the DOM.
   */
  connectedCallback(): void {
    this.update();
  }

  /**
   * Re-render the component by replacing shadow root contents.
   */
  protected update(): void {
    const content = this.render();
    this.shadow.replaceChildren(content);
  }

  /**
   * Override to define the component's content.
   */
  abstract render(): HTMLElement | DocumentFragment;

  /**
   * Called by the router when URL params change.
   * Override to react to URL state changes.
   */
  onParamsChange?(params: URLSearchParams): void;

  /**
   * Query an element within the shadow root.
   */
  protected $<T extends HTMLElement>(selector: string): T | null {
    return this.shadow.querySelector<T>(selector);
  }

  /**
   * Query all elements within the shadow root.
   */
  protected $$<T extends HTMLElement>(selector: string): NodeListOf<T> {
    return this.shadow.querySelectorAll<T>(selector);
  }

  /**
   * Set text content of an element by selector.
   */
  protected setText(selector: string, content: string): void {
    const el = this.$(selector);
    if (el) {
      el.textContent = content;
    }
  }

  /**
   * Set innerHTML of an element by selector (use with caution).
   */
  protected setHtml(selector: string, html: string): void {
    const el = this.$(selector);
    if (el) {
      el.innerHTML = html;
    }
  }

  /**
   * Replace children of an element by selector.
   */
  protected setChildren(selector: string, ...children: Child[]): void {
    const el = this.$(selector);
    if (el) {
      const flat = flattenChildren(children);
      el.replaceChildren(
        ...flat.map((c) => (typeof c === "string" ? document.createTextNode(c) : c)),
      );
    }
  }
}

/**
 * Define and register a custom element.
 */
export function defineComponent(name: string, component: CustomElementConstructor): void {
  if (!customElements.get(name)) {
    customElements.define(name, component);
  }
}

/**
 * Create a style element for use in shadow DOM.
 */
export function css(styles: string): HTMLStyleElement {
  const style = document.createElement("style");
  style.textContent = styles;
  return style;
}

/**
 * Create a document fragment from multiple children.
 */
export function fragment(...children: Child[]): DocumentFragment {
  const frag = document.createDocumentFragment();
  const flat = flattenChildren(children);
  for (const child of flat) {
    if (typeof child === "string") {
      frag.appendChild(document.createTextNode(child));
    } else {
      frag.appendChild(child);
    }
  }
  return frag;
}
