/**
 * Minimal hyperscript-style HTML helper library with Web Component base class.
 * No dependencies, no virtual DOM - just real DOM nodes.
 */
export type Child = Node | string | number | null | undefined | false | Child[];
export type EventHandler<E extends Event = Event> = (event: E) => void;
export type Props = {
    [key: string]: string | number | boolean | EventHandler | undefined;
};
/**
 * Hyperscript-style element creation.
 *
 * @example
 * h('div', { class: 'container', onclick: () => console.log('clicked') },
 *   h('span', {}, 'Hello'),
 *   ' World'
 * )
 */
export declare function h<K extends keyof HTMLElementTagNameMap>(tag: K, props?: Props | null, ...children: Child[]): HTMLElementTagNameMap[K];
export declare function h(tag: string, props?: Props | null, ...children: Child[]): HTMLElement;
/**
 * Create a text node.
 */
export declare function text(content: string): Text;
/**
 * Base class for Web Components with common patterns.
 */
export declare abstract class BaseComponent extends HTMLElement {
    protected shadow: ShadowRoot;
    constructor();
    /**
     * Called when the element is added to the DOM.
     */
    connectedCallback(): void;
    /**
     * Re-render the component by replacing shadow root contents.
     */
    protected update(): void;
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
    protected $<T extends HTMLElement>(selector: string): T | null;
    /**
     * Query all elements within the shadow root.
     */
    protected $$<T extends HTMLElement>(selector: string): NodeListOf<T>;
    /**
     * Set text content of an element by selector.
     */
    protected setText(selector: string, content: string): void;
    /**
     * Set innerHTML of an element by selector (use with caution).
     */
    protected setHtml(selector: string, html: string): void;
    /**
     * Replace children of an element by selector.
     */
    protected setChildren(selector: string, ...children: Child[]): void;
}
/**
 * Define and register a custom element.
 */
export declare function defineComponent(name: string, component: CustomElementConstructor): void;
/**
 * Create a style element for use in shadow DOM.
 */
export declare function css(styles: string): HTMLStyleElement;
/**
 * Create a document fragment from multiple children.
 */
export declare function fragment(...children: Child[]): DocumentFragment;
