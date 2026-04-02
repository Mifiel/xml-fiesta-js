import * as esbuild from 'esbuild';
import { builtinModules } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { nodeModulesPolyfillPlugin } from 'esbuild-plugins-node-modules-polyfill';

// xml2js does `extend(Parser, require('events'))`, which expects Node's export shape
// (the EventEmitter constructor). The polyfill plugin intercepts `events` *before*
// esbuild `alias` runs and injects JSPM's shim (`export *` namespace), so inheritance
// breaks. Turn off polyfilling for `events` only, then alias to the npm `events` package
// (same API as Node's builtin).
const dir = path.dirname(fileURLToPath(import.meta.url));
const eventsEntry = path.resolve(dir, '../node_modules/events/events.js');

await esbuild.build({
  entryPoints: ['lib/xml-fiesta.js'],
  bundle: true,
  outfile: 'dist/xml-fiesta.js',
  format: 'iife',
  globalName: 'XMLFiesta',
  platform: 'browser',
  minify: true,
  legalComments: 'none',
  alias: {
    events: eventsEntry,
    'node:events': eventsEntry,
  },
  plugins: [
    nodeModulesPolyfillPlugin({
      globals: {
        Buffer: true,
        process: true,
      },
      modules: Object.fromEntries(
        builtinModules.map((name) => [name, name !== 'events'])
      ),
    }),
  ],
});
