/**
 * Hash-based router for GitHub Pages compatibility.
 * Supports URL state sharing via query parameters after the hash.
 *
 * URL format: #/path?param1=value1&param2=value2
 */

import type { BaseComponent } from "./html";

export interface Route {
  path: string;
  component: string; // Custom element tag name
}

interface ParsedHash {
  path: string;
  params: URLSearchParams;
}

let routes: Route[] = [];
let container: HTMLElement | null = null;
let currentComponent: BaseComponent | null = null;
let currentPath: string | null = null;

/**
 * Parse the current hash into path and query params.
 *
 * Examples:
 * - "#/foo/bar" -> { path: "/foo/bar", params: URLSearchParams{} }
 * - "#/foo?a=1&b=2" -> { path: "/foo", params: URLSearchParams{a=1, b=2} }
 * - "" or "#" or "#/" -> { path: "/", params: URLSearchParams{} }
 */
export function parseHash(hash: string = location.hash): ParsedHash {
  // Remove leading # if present
  let hashContent = hash.startsWith("#") ? hash.slice(1) : hash;

  // Default to root path
  if (!hashContent || hashContent === "/") {
    return { path: "/", params: new URLSearchParams() };
  }

  // Split path and query string
  const questionIndex = hashContent.indexOf("?");
  if (questionIndex === -1) {
    return { path: hashContent, params: new URLSearchParams() };
  }

  const path = hashContent.slice(0, questionIndex);
  const queryString = hashContent.slice(questionIndex + 1);
  return { path: path || "/", params: new URLSearchParams(queryString) };
}

/**
 * Build a hash string from path and params.
 */
function buildHash(path: string, params?: Record<string, string>): string {
  const searchParams = new URLSearchParams();

  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value) {
        searchParams.set(key, value);
      }
    }
  }

  const queryString = searchParams.toString();
  return queryString ? `#${path}?${queryString}` : `#${path}`;
}

/**
 * Navigate to a new route, optionally with params.
 */
export function navigate(path: string, params?: Record<string, string>): void {
  location.hash = buildHash(path, params);
}

/**
 * Update just the params without changing the current route.
 * Empty string values are removed from the URL.
 */
export function setParams(params: Record<string, string>): void {
  const { path, params: currentParams } = parseHash();

  // Merge with current params
  for (const [key, value] of Object.entries(params)) {
    if (value) {
      currentParams.set(key, value);
    } else {
      currentParams.delete(key);
    }
  }

  const queryString = currentParams.toString();
  location.hash = queryString ? `${path}?${queryString}` : path;
}

/**
 * Get current params without navigation.
 */
export function getParams(): URLSearchParams {
  return parseHash().params;
}

/**
 * Get current path without navigation.
 */
export function getPath(): string {
  return parseHash().path;
}

/**
 * Find the matching route for a path.
 */
function findRoute(path: string): Route | undefined {
  return routes.find((r) => r.path === path);
}

/**
 * Handle route changes.
 */
function handleRouteChange(): void {
  if (!container) return;

  const { path, params } = parseHash();
  const route = findRoute(path);

  if (!route) {
    // Show 404 or redirect to home
    console.warn(`No route found for path: ${path}`);
    if (path !== "/") {
      navigate("/");
    }
    return;
  }

  // If same path, just update params on existing component
  if (currentPath === path && currentComponent) {
    if (currentComponent.onParamsChange) {
      currentComponent.onParamsChange(params);
    }
    return;
  }

  // Different route - create new component
  currentPath = path;

  // Create the component element
  const element = document.createElement(route.component) as BaseComponent;
  currentComponent = element;

  // Replace container contents
  container.replaceChildren(element);

  // Notify component of initial params (after it's connected to DOM)
  // Use microtask to ensure connectedCallback has run
  queueMicrotask(() => {
    if (element.onParamsChange) {
      element.onParamsChange(params);
    }
  });
}

/**
 * Register routes with the router.
 */
export function registerRoutes(newRoutes: Route[]): void {
  routes = newRoutes;
}

/**
 * Initialize the router and start listening to hash changes.
 */
export function initRouter(containerElement: HTMLElement, routeConfig: Route[]): void {
  container = containerElement;
  routes = routeConfig;

  // Listen for hash changes
  window.addEventListener("hashchange", handleRouteChange);

  // Handle initial route
  handleRouteChange();
}

/**
 * Clean up router listeners (useful for testing).
 */
export function destroyRouter(): void {
  window.removeEventListener("hashchange", handleRouteChange);
  container = null;
  currentComponent = null;
  currentPath = null;
  routes = [];
}
