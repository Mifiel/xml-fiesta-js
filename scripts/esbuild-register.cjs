/**
 * Compile TypeScript on require. TypeScript 7 ships a native compiler and no
 * longer exposes the JavaScript API that ts-node needs.
 */
const fs = require("fs");
const Module = require("module");
const esbuild = require("esbuild");

Module._extensions[".ts"] = function (module, filename) {
  const source = fs.readFileSync(filename, "utf8");
  const { code } = esbuild.transformSync(source, {
    sourcefile: filename,
    loader: "ts",
    format: "cjs",
    target: "es2022",
    sourcemap: "inline",
  });
  module._compile(code, filename);
};
