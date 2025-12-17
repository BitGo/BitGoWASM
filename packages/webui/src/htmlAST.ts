function nodeErr(message: string): HTMLElement {
  const node = document.createElement("div");
  node.innerText = message;
  return node;
}

function nodeText(text: string): HTMLElement {
  const node = document.createElement("span");
  node.innerText = text;
  return node;
}

function nodeArray(array: unknown[]): HTMLElement {
  const node = document.createElement("ul");
  array.forEach((item) => {
    const itemNode = document.createElement("li");
    itemNode.appendChild(getHtmlForAst(item));
    node.appendChild(itemNode);
  });
  return node;
}

function nodeObject(obj: Record<string, unknown>): HTMLElement {
  const node = document.createElement("ul");
  Object.entries(obj).forEach(([key, value]) => {
    const keyNode = document.createElement("li");
    keyNode.innerText = key;
    node.appendChild(keyNode);
    node.appendChild(getHtmlForAst(value));
  });
  return node;
}

export function getHtmlForAst(ast: unknown): HTMLElement {
  if (
    ast === null ||
    ast === undefined ||
    typeof ast === "string" ||
    typeof ast === "boolean" ||
    typeof ast === "bigint" ||
    typeof ast === "symbol" ||
    typeof ast === "number"
  ) {
    return nodeText(String(ast));
  }
  if (Array.isArray(ast)) {
    return nodeArray(ast);
  }
  if (typeof ast === "object") {
    return nodeObject(ast as Record<string, unknown>);
  }
  throw new Error(`unknown ast type ${JSON.stringify(ast)}`);
}
