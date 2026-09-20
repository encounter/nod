import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const path = process.argv[2] ?? 'target/wasm32-unknown-unknown/debug/examples/wasm_roundtrip.wasm';
const module = new WebAssembly.Module(readFileSync(path));
assert.deepEqual(WebAssembly.Module.imports(module), [], 'The core must run without host imports');
const instance = new WebAssembly.Instance(module, {});
assert.equal(instance.exports.main(0, 0), 0);
console.log('WASM disc roundtrips passed with no host imports.');
