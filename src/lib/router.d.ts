/**
 * Hash-based router for GitHub Pages compatibility.
 * Supports URL state sharing via query parameters after the hash.
 *
 * URL format: #/path?param1=value1&param2=value2
 */
export interface Route {
    path: string;
    component: string;
}
interface ParsedHash {
    path: string;
    params: URLSearchParams;
}
/**
 * Parse the current hash into path and query params.
 *
 * Examples:
 * - "#/foo/bar" -> { path: "/foo/bar", params: URLSearchParams{} }
 * - "#/foo?a=1&b=2" -> { path: "/foo", params: URLSearchParams{a=1, b=2} }
 * - "" or "#" or "#/" -> { path: "/", params: URLSearchParams{} }
 */
export declare function parseHash(hash?: string): ParsedHash;
/**
 * Navigate to a new route, optionally with params.
 */
export declare function navigate(path: string, params?: Record<string, string>): void;
/**
 * Update just the params without changing the current route.
 * Empty string values are removed from the URL.
 */
export declare function setParams(params: Record<string, string>): void;
/**
 * Get current params without navigation.
 */
export declare function getParams(): URLSearchParams;
/**
 * Get current path without navigation.
 */
export declare function getPath(): string;
/**
 * Register routes with the router.
 */
export declare function registerRoutes(newRoutes: Route[]): void;
/**
 * Initialize the router and start listening to hash changes.
 */
export declare function initRouter(containerElement: HTMLElement, routeConfig: Route[]): void;
/**
 * Clean up router listeners (useful for testing).
 */
export declare function destroyRouter(): void;
export {};
