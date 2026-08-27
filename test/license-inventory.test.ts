import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error The build helper is plain ESM so Node can execute it without a loader.
const inventory = await import("../scripts/license-inventory.mjs");
const {
  bundledPackageNames,
  RUNTIME_LICENSE_CATALOG,
  validateLicenseInventory,
} = inventory;

const expected = [
  "@adversarylabs/sdk",
  "ajv",
  "fast-deep-equal",
  "fast-uri",
  "json-schema-traverse",
  "tree-sitter-go",
  "web-tree-sitter",
  "yaml",
];

test("the runtime license catalog is the exact bundled dependency inventory", () => {
  assert.deepEqual([...RUNTIME_LICENSE_CATALOG.keys()].sort(), expected);
  assert.deepEqual(
    bundledPackageNames([
      "src/index.ts",
      "node_modules/@adversarylabs/sdk/dist/index.js",
      "node_modules/ajv/dist/ajv.js",
      "node_modules/fast-deep-equal/index.js",
      "node_modules/fast-uri/index.js",
      "node_modules/json-schema-traverse/index.js",
      "node_modules/web-tree-sitter/web-tree-sitter.js",
      "node_modules/yaml/dist/index.js",
    ]),
    expected.filter((name) => name !== "tree-sitter-go"),
  );
  assert.deepEqual(validateLicenseInventory(expected), expected);
});

test("the build fails closed for unknown or stale license mappings", () => {
  assert.throws(
    () => validateLicenseInventory([...expected, "unknown-runtime"]),
    /missing=unknown-runtime/,
  );
  assert.throws(
    () => validateLicenseInventory(expected.slice(0, -1)),
    /stale=yaml/,
  );
});
