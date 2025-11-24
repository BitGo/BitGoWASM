import * as fs from "fs/promises";
export async function getFixture(path: string, defaultValue: unknown): Promise<unknown> {
  try {
    return JSON.parse(await fs.readFile(path, "utf8")) as unknown;
  } catch (e) {
    if (
      typeof e === "object" &&
      e !== null &&
      "code" in e &&
      (e as { code: unknown }).code === "ENOENT"
    ) {
      await fs.writeFile(path, JSON.stringify(defaultValue, null, 2));
      throw new Error(`Fixture not found at ${path}, created a new one`);
    }
    throw e;
  }
}
