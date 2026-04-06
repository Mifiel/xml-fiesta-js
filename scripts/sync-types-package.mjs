/**
 * Copies emitted .d.ts files from lib/ into xml-fiesta-types/, syncs the types
 * package version with the root package.json, and appends a declare module shim.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(dir, '..');
const libDir = path.join(rootDir, 'lib');
const typesPkgDir = path.join(rootDir, 'xml-fiesta-types');
const typesPkgJsonPath = path.join(typesPkgDir, 'package.json');
const rootPkgJsonPath = path.join(rootDir, 'package.json');

function rmrf(target) {
  if (!fs.existsSync(target)) return;
  const stat = fs.statSync(target);
  if (stat.isDirectory()) {
    for (const name of fs.readdirSync(target)) {
      rmrf(path.join(target, name));
    }
    fs.rmdirSync(target);
  } else {
    fs.unlinkSync(target);
  }
}

function walkLibDts(rel, onFile) {
  const abs = path.join(libDir, rel);
  const entries = fs.readdirSync(abs);
  for (const name of entries) {
    const relPath = rel ? path.join(rel, name) : name;
    const full = path.join(libDir, relPath);
    const st = fs.statSync(full);
    if (st.isDirectory()) {
      walkLibDts(relPath, onFile);
    } else if (name.endsWith('.d.ts')) {
      onFile(relPath);
    }
  }
}

function syncTypesPackageVersion() {
  const rootPkg = JSON.parse(fs.readFileSync(rootPkgJsonPath, 'utf8'));
  const typesPkg = JSON.parse(fs.readFileSync(typesPkgJsonPath, 'utf8'));
  typesPkg.version = rootPkg.version;
  fs.writeFileSync(
    typesPkgJsonPath,
    JSON.stringify(typesPkg, null, 2) + '\n',
    'utf8',
  );
}

function cleanTypesPackageOutput() {
  if (!fs.existsSync(typesPkgDir)) {
    fs.mkdirSync(typesPkgDir, { recursive: true });
    return;
  }
  for (const name of fs.readdirSync(typesPkgDir)) {
    if (name === 'package.json') continue;
    rmrf(path.join(typesPkgDir, name));
  }
}

if (!fs.existsSync(libDir)) {
  console.error(
    'sync-types-package: lib/ is missing (run `tsc` before this script).',
  );
  process.exit(1);
}

syncTypesPackageVersion();
cleanTypesPackageOutput();
walkLibDts('', (relPath) => {
  const from = path.join(libDir, relPath);
  const to = path.join(typesPkgDir, relPath);
  fs.mkdirSync(path.dirname(to), { recursive: true });
  fs.copyFileSync(from, to);
});

const typesEntryDts = path.join(typesPkgDir, 'xml-fiesta.d.ts');
fs.appendFileSync(
  typesEntryDts,
  [
    '',
    "declare module 'xml-fiesta' {",
    "  export * from './xml-fiesta.d.ts';",
    '}',
    '',
  ].join('\n'),
  'utf8',
);

console.log('Copied .d.ts files to xml-fiesta-types/');
