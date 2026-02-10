/// <reference types="node" />
/**
 * Generic test fixture and serialization utilities.
 * Ported from @bitgo/utxo-core/testutil/fixtures.utils.ts
 * and @bitgo/utxo-core/testutil/toPlainObject.utils.ts.
 *
 * NOTE: getFixture requires Node.js (fs, process.env).
 * The toPlainObject / jsonNormalize utilities are platform-independent.
 */
import * as fs from "fs";
import * as mpath from "path";

// ===== getFixture / jsonNormalize =====

type FixtureEncoding = "json" | "hex" | "txt";

function isNodeJsError(e: unknown): e is NodeJS.ErrnoException {
  return e instanceof Error && typeof (e as NodeJS.ErrnoException).code === "string";
}

function fixtureEncoding(path: string): FixtureEncoding {
  if (path.endsWith(".json")) {
    return "json";
  }
  if (path.endsWith(".hex")) {
    return "hex";
  }
  if (path.endsWith(".txt")) {
    return "txt";
  }
  throw new Error(`unknown fixture encoding for ${path}`);
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function decodeFixture(raw: string, encoding: FixtureEncoding): unknown {
  switch (encoding) {
    case "json":
      return JSON.parse(raw);
    case "hex":
      return hexToBytes(raw);
    case "txt":
      return raw;
  }
}

function encodeFixture(value: unknown, encoding: FixtureEncoding): string {
  switch (encoding) {
    case "json":
      return JSON.stringify(value, null, 2) + "\n";
    case "hex":
      if (!(value instanceof Uint8Array)) {
        throw new Error(`expected Uint8Array, got ${typeof value}`);
      }
      return bytesToHex(value);
    case "txt":
      if (typeof value !== "string") {
        throw new Error(`expected string, got ${typeof value}`);
      }
      return value;
  }
}

/**
 * Return fixture described in `path`.
 *
 * If the file does not exist and `defaultValue` is provided,
 * writes defaultValue to `path` and throws an error prompting
 * the developer to inspect and re-run.
 *
 * @param path - Path to the fixture file (.json, .hex, or .txt)
 * @param defaultValue - Default value to write if fixture is missing
 * @returns The fixture content
 */
export async function getFixture<T>(
  path: string,
  defaultValue?: T | (() => Promise<T>),
): Promise<T> {
  try {
    await fs.promises.stat(mpath.dirname(path));
  } catch (e) {
    if (isNodeJsError(e) && e.code === "ENOENT") {
      throw new Error(`fixture directory ${mpath.dirname(path)} not found, please create it first`);
    }
    throw e;
  }

  const encoding = fixtureEncoding(path);

  try {
    return decodeFixture(await fs.promises.readFile(path, "utf8"), encoding) as T;
  } catch (e) {
    if (isNodeJsError(e) && e.code === "ENOENT") {
      // eslint-disable-next-line no-restricted-globals
      if (process.env.WRITE_FIXTURES === "0") {
        throw new Error(`fixture ${path} not found, WRITE_FIXTURES=0`);
      }
      if (defaultValue === undefined) {
        throw new Error(`fixture ${path} not found and no default value given`);
      }
      if (typeof defaultValue === "function") {
        defaultValue = await (defaultValue as () => Promise<T>)();
      }
      await fs.promises.writeFile(path, encodeFixture(defaultValue, encoding));
      throw new Error(`wrote default value for ${path}, please inspect and restart test`);
    }

    throw e;
  }
}

/**
 * JSON round-trip normalization.
 * Converts a value to JSON and back, stripping non-serializable properties
 * and normalizing types (e.g. undefined -> null in arrays).
 */
export function jsonNormalize<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

// ===== toPlainObject =====

export type ToPlainObjectOpts = {
  propertyDescriptors?: boolean;
  skipUndefinedValues?: boolean;
  ignorePaths?: string[] | ((path: PathElement[]) => boolean);
  apply?: (v: unknown, path: PathElement[]) => unknown;
};

export type PathElement = string | number;

export function matchPath(a: PathElement[], b: PathElement[]): boolean {
  return a.length === b.length && a.every((e, i) => e === b[i]);
}

function includePath(opts: ToPlainObjectOpts, path: PathElement[]): boolean {
  if (!opts.ignorePaths) {
    return true;
  }
  if (typeof opts.ignorePaths === "function") {
    return !opts.ignorePaths(path);
  }
  return !opts.ignorePaths.some((ignorePath) => matchPath(path, ignorePath.split(".")));
}

function toPlainEntries(
  key: string,
  value: unknown,
  opts: ToPlainObjectOpts,
  path: PathElement[],
): [] | [[string, unknown]] {
  if (!includePath(opts, [...path, key])) {
    return [];
  }
  if (value === undefined && (opts.skipUndefinedValues ?? true)) {
    return [];
  }
  return [[key, toPlainObject(value, opts, [...path, key])]];
}

function getAllPropertyDescriptors(v: unknown): PropertyDescriptorMap {
  if (v === null || typeof v !== "object") {
    return {};
  }
  const descriptors: PropertyDescriptorMap = Object.getOwnPropertyDescriptors(v);
  const proto: unknown = Object.getPrototypeOf(v);
  if (proto) {
    Object.assign(descriptors, getAllPropertyDescriptors(proto));
  }
  return descriptors;
}

function toPlainObjectFromPropertyDescriptors(
  v: unknown,
  opts: ToPlainObjectOpts,
  path: PathElement[],
) {
  const descriptors = getAllPropertyDescriptors(v);
  return Object.fromEntries(
    Object.entries(descriptors).flatMap(([key, descriptor]) => {
      if (typeof descriptor.value === "function") {
        return [];
      }
      if (descriptor.value !== undefined) {
        return toPlainEntries(key, descriptor.value, opts, path);
      }
      if (typeof descriptor.get === "function") {
        return toPlainEntries(key, descriptor.get.call(v), opts, path);
      }
      return [];
    }),
  );
}

/**
 * Recursively convert a value to a plain JSON-serializable object.
 * Handles Uint8Array (to hex), bigint (to string), Buffer, and more.
 *
 * @param v - The value to convert
 * @param opts - Options for customizing the conversion
 * @param path - Current property path (used for ignorePaths)
 */
export function toPlainObject(
  v: unknown,
  opts: ToPlainObjectOpts = {},
  path: PathElement[] = [],
): unknown {
  if (opts.apply) {
    const result = opts.apply(v, path);
    if (result !== undefined) {
      return result;
    }
  }

  switch (typeof v) {
    case "string":
    case "number":
    case "boolean":
    case "undefined":
      return v;
    case "bigint":
      return v.toString();
    case "function":
    case "symbol":
      return undefined;
  }

  if (v === null) {
    return v;
  }

  if (v instanceof Uint8Array) {
    return Array.from(v, (b) => b.toString(16).padStart(2, "0")).join("");
  }
  if (Array.isArray(v)) {
    return v.map((e, i) => toPlainObject(e, opts, [...path, i]));
  }
  if (typeof v === "object") {
    const result = Object.fromEntries(
      Object.entries(v).flatMap(([key, value]) => toPlainEntries(key, value, opts, path)),
    );
    if (opts.propertyDescriptors) {
      Object.assign(result, toPlainObjectFromPropertyDescriptors(v, opts, path));
    }
    return result;
  }
  throw new Error(`unknown v ${typeof v}`);
}
