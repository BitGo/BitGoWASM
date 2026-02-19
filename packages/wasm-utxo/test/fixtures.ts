import * as fs from "fs/promises";

type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

export async function getFixture(
  path: string,
  defaultValue: (() => JsonValue) | JsonValue,
): Promise<JsonValue> {
  try {
    return JSON.parse(await fs.readFile(path, "utf8")) as JsonValue;
  } catch (e) {
    if (
      typeof e === "object" &&
      e !== null &&
      "code" in e &&
      (e as { code: unknown }).code === "ENOENT"
    ) {
      const value: JsonValue = typeof defaultValue === "function" ? defaultValue() : defaultValue;
      await fs.writeFile(path, JSON.stringify(value, null, 2));
      throw new Error(`Fixture not found at ${path}, created a new one`);
    }
    throw e;
  }
}
