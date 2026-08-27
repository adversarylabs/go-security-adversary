export const RUNTIME_LICENSE_CATALOG = new Map([
  ["@adversarylabs/sdk", { license: "MIT", path: "node_modules/@adversarylabs/sdk/LICENSE" }],
  ["ajv", { license: "MIT", path: "node_modules/ajv/LICENSE" }],
  ["fast-deep-equal", { license: "MIT", path: "node_modules/fast-deep-equal/LICENSE" }],
  ["fast-uri", { license: "BSD-3-Clause", path: "node_modules/fast-uri/LICENSE" }],
  ["json-schema-traverse", { license: "MIT", path: "node_modules/json-schema-traverse/LICENSE" }],
  ["tree-sitter-go", { license: "MIT", path: "node_modules/tree-sitter-go/LICENSE" }],
  ["web-tree-sitter", { license: "MIT", path: "node_modules/web-tree-sitter/LICENSE" }],
  ["yaml", { license: "ISC", path: "node_modules/yaml/LICENSE" }],
]);

export function bundledPackageNames(inputs) {
  const packages = new Set();
  for (const input of inputs) {
    const marker = "node_modules/";
    const offset = input.lastIndexOf(marker);
    if (offset < 0) continue;
    const parts = input.slice(offset + marker.length).split("/");
    const name = parts[0]?.startsWith("@") ? `${parts[0]}/${parts[1]}` : parts[0];
    if (name !== undefined && name !== "") packages.add(name);
  }
  return [...packages].sort();
}

export function validateLicenseInventory(bundledPackages, catalog = RUNTIME_LICENSE_CATALOG) {
  const bundled = new Set(bundledPackages);
  const licensed = new Set(catalog.keys());
  const missing = [...bundled].filter((name) => !licensed.has(name)).sort();
  const stale = [...licensed].filter((name) => !bundled.has(name)).sort();
  if (missing.length > 0 || stale.length > 0) {
    throw new Error(
      `bundled dependency license inventory mismatch; missing=${missing.join(",")}; stale=${stale.join(",")}`,
    );
  }
  return [...bundled].sort();
}
