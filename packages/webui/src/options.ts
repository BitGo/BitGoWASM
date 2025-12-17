import * as t from "io-ts";
import * as tt from "io-ts-types";
import { fixtures } from "./descriptorFixtures";
import { getElement } from "./html";
import { decodeOrThrow, ScriptContext } from "./codec";

function getOption(id: string): unknown {
  const el = getElement(id, HTMLElement);
  if (el instanceof HTMLSelectElement) {
    return el.value;
  }
  if (el instanceof HTMLInputElement) {
    return el.value;
  }
  throw new Error(`element with id ${id} is not a select or input`);
}

function showOutput(output: string) {
  const outputElement = document.getElementById("output");
  if (!outputElement) {
    throw new Error("output element not found");
  }
  outputElement.innerText = output;
}

type DropdownItem = {
  label: string;
  value: string;
};

export function getExampleOptions(index: number | undefined = undefined): DropdownItem[] {
  let valid = fixtures.valid;
  if (index !== undefined) {
    valid = [valid[index]];
  }
  return valid.map((fixture, i) => {
    return {
      label: `Example ${i}: ${fixture.descriptor.slice(0, 16)}...`,
      value: fixture.descriptor,
    };
  });
}

function buildSelect(elSelect: HTMLSelectElement, options: DropdownItem[]): void {
  options.forEach((option) => {
    const optionElement = document.createElement("option");
    optionElement.value = option.value;
    optionElement.innerText = option.label;
    elSelect.appendChild(optionElement);
  });
}

function getOptionsFromUnion(u: t.UnionType<t.Any[]>): DropdownItem[] {
  return u.types.map((e) => {
    if (e instanceof t.LiteralType) {
      return { label: e.value, value: e.value };
    }
    throw new Error(`unexpected type ${t}`);
  });
}

export function getOptionsFromType(c: t.Type<any>): DropdownItem[] {
  if (c instanceof t.UnionType) {
    return getOptionsFromUnion(c);
  }
  throw new Error(`unexpected type ${c}`);
}

export const Options = t.type({
  scriptContext: ScriptContext,
  example: t.string,
  derivationIndex: tt.NumberFromString,
});

export type Options = t.TypeOf<typeof Options>;

export function buildOptions(): void {
  buildSelect(
    getElement("input-script-context", HTMLSelectElement),
    getOptionsFromType(ScriptContext),
  );
  buildSelect(getElement("input-example", HTMLSelectElement), getExampleOptions());
}

export function getOptions(): Options {
  return decodeOrThrow(Options, {
    scriptContext: getOption("input-script-context"),
    example: getOption("input-example"),
    derivationIndex: getOption("input-derivation-index"),
  });
}
