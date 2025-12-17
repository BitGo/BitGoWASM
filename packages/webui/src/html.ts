export function getElement<T extends HTMLElement>(id: string, type: { new (): T }): T {
  const element = document.getElementById(id);
  if (!element) {
    throw new Error(`Element with id "${id}" not found`);
  }
  if (!(element instanceof type)) {
    throw new Error(`Element with id "${id}" is not a ${type.name}`);
  }
  return element;
}
