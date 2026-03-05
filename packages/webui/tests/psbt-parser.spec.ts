import { test, expect } from "@playwright/test";

test.describe("PSBT/TX Parser", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/#/wasm-utxo/parser");
  });

  test("page loads with heading", async ({ page }) => {
    const heading = page.locator("psbt-tx-parser").locator("h1");
    await expect(heading).toHaveText("UTXO PSBT/TX Parser");
  });

  test("shows empty state initially", async ({ page }) => {
    const empty = page.locator("psbt-tx-parser").locator(".empty-state");
    await expect(empty).toBeVisible();
  });

  test("load sample PSBT shows tree with outputs", async ({ page }) => {
    const parser = page.locator("psbt-tx-parser");

    // Open sample modal and select first PSBT sample
    await parser.locator(".load-sample-btn").click();
    const modal = parser.locator(".modal-overlay");
    await expect(modal).toHaveClass(/open/);

    // Click the first sample (Bitcoin Lite PSBT Finalized)
    await parser.locator(".sample-item").first().click();

    // Modal should close
    await expect(modal).not.toHaveClass(/open/);

    // Tree should be rendered
    const tree = parser.locator(".tree-container");
    await expect(tree).toBeVisible();

    // Should show detected type
    const detected = parser.locator("#detected-type");
    await expect(detected).toContainText("PSBT");
  });

  test("load sample PSBT shows edit controls", async ({ page }) => {
    const parser = page.locator("psbt-tx-parser");

    // Load a PSBT sample
    await parser.locator(".load-sample-btn").click();
    await parser.locator(".sample-item").first().click();

    // Edit controls should appear (Add Output form)
    const editSection = parser.locator(".edit-section");
    await expect(editSection).toBeVisible();
    await expect(editSection.locator(".edit-title")).toHaveText("Edit Outputs");

    // Should have address and value inputs
    await expect(parser.locator("#add-address")).toBeVisible();
    await expect(parser.locator("#add-value")).toBeVisible();
  });

  test("edit controls not shown for TX mode", async ({ page }) => {
    const parser = page.locator("psbt-tx-parser");

    // Load a TX sample
    await parser.locator(".load-sample-btn").click();
    const txSample = parser.locator(".sample-item", { hasText: "TX" }).first();
    await txSample.click();

    // Edit controls should NOT appear for transactions
    const editSection = parser.locator(".edit-section");
    await expect(editSection).not.toBeVisible();
  });

  test("Remove buttons auto-visible on output nodes when PSBT loaded", async ({ page }) => {
    const parser = page.locator("psbt-tx-parser");

    // Load a PSBT sample
    await parser.locator(".load-sample-btn").click();
    await parser.locator(".sample-item").first().click();

    // Remove buttons should be visible immediately (auto-expanded to outputs level)
    const removeButtons = parser.locator(".action-btn-remove");
    await expect(removeButtons.first()).toBeVisible();
    const count = await removeButtons.count();
    expect(count).toBeGreaterThan(0);
  });

  test("Remove button removes output and preserves expand state", async ({ page }) => {
    const parser = page.locator("psbt-tx-parser");

    // Load a PSBT sample
    await parser.locator(".load-sample-btn").click();
    await parser.locator(".sample-item").first().click();

    // Count initial remove buttons (auto-expanded)
    const removeButtons = parser.locator(".action-btn-remove");
    await expect(removeButtons.first()).toBeVisible();
    const initialCount = await removeButtons.count();

    // Click first Remove button
    await removeButtons.first().click();

    // Tree should stay expanded and show one fewer output
    await expect(parser.locator(".action-btn-remove").first()).toBeVisible();
    const newCount = await parser.locator(".action-btn-remove").count();
    expect(newCount).toBe(initialCount - 1);

    // Textarea should have updated value (valid base64)
    const textarea = parser.locator("#data-input");
    const value = await textarea.inputValue();
    expect(value).toBeTruthy();
    expect(value).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });

  test("Add Output shows error when fields empty", async ({ page }) => {
    const parser = page.locator("psbt-tx-parser");

    // Load a PSBT sample
    await parser.locator(".load-sample-btn").click();
    await parser.locator(".sample-item").first().click();

    // Click Add Output without filling fields
    await parser.locator("button", { hasText: "Add Output" }).click();

    // Should show validation error
    const editError = parser.locator("#edit-error .error-message");
    await expect(editError).toBeVisible();
    await expect(editError).toContainText("Enter an address");
  });

  test("clear resets to empty state", async ({ page }) => {
    const parser = page.locator("psbt-tx-parser");

    // Load a sample
    await parser.locator(".load-sample-btn").click();
    await parser.locator(".sample-item").first().click();

    // Verify tree is visible
    await expect(parser.locator(".tree-container")).toBeVisible();

    // Click Clear
    await parser.locator("button", { hasText: "Clear" }).click();

    // Should show empty state
    await expect(parser.locator(".empty-state")).toBeVisible();

    // Edit controls should be gone
    await expect(parser.locator(".edit-section")).not.toBeVisible();
  });

  test("mode switching works", async ({ page }) => {
    const parser = page.locator("psbt-tx-parser");

    // Check initial mode is PSBT (active)
    const psbtBtn = parser.locator("#mode-psbt");
    await expect(psbtBtn).toHaveClass(/active/);

    // Switch to Transaction mode
    const txBtn = parser.locator("#mode-tx");
    await txBtn.click();
    await expect(txBtn).toHaveClass(/active/);
    await expect(psbtBtn).not.toHaveClass(/active/);

    // Switch to PSBT Raw mode
    const rawBtn = parser.locator("#mode-psbt-raw");
    await rawBtn.click();
    await expect(rawBtn).toHaveClass(/active/);
    await expect(txBtn).not.toHaveClass(/active/);
  });
});
