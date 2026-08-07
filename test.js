
import { readFileSync } from 'node:fs';
import { WitnessCalculatorBuilder } from 'circom_runtime';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import assert from 'node:assert/strict';

import { genZKproof, verifyNative, toCircuitInput } from './ECDSA.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const WASM = join(__dirname, 'build', 'verify_js', 'verify.wasm');

let wcPromise;
function getWC() {
  if (!wcPromise) {
    wcPromise = (async () => {
      const wasm = readFileSync(WASM);
      return WitnessCalculatorBuilder(wasm);
    })();
  }
  return wcPromise;
}

async function accepts(input) {
  const wc = await getWC();
  const origWrite = process.stderr.write.bind(process.stderr);
  process.stderr.write = () => true;
  try {
    await wc.calculateWTNSBin(input, 0);
    return true;
  } catch (e) {
    return false;
  } finally {
    process.stderr.write = origWrite;
  }
}

async function main() {
  assert.ok(readFileSync(WASM), 'wasm not found');
  const proof = genZKproof('self-contained test');
  assert.ok(verifyNative(proof).ok, 'native oracle failed');

  const base = toCircuitInput(proof);
  console.log('validating valid proof...');
  const ok = await accepts(base);
  assert.ok(ok, 'valid proof rejected by circuit!');
  console.log('  valid proof: OK');

  // 篡改 rhs
  console.log('tampering rhs...');
  const badRhs = structuredClone(base);
  badRhs.rhs[0][0] = String(BigInt(badRhs.rhs[0][0]) ^ 1n);
  assert.equal(await accepts(badRhs), false, 'must reject tampered rhs');
  console.log('  tampered rhs: rejected OK');

  // 篡改 h
  const badH = structuredClone(base);
  badH.h[0] = String(BigInt(badH.h[0]) ^ 1n);
  assert.equal(await accepts(badH), false, 'must reject tampered h');
  console.log('  tampered h: rejected OK');

  // 篡改 s1
  const badS = structuredClone(base);
  badS.s1[0] = String(BigInt(badS.s1[0]) + 1n);
  assert.equal(await accepts(badS), false, 'must reject tampered s1');
  console.log('  tampered s1: rejected OK');

  console.log('\nAll witness tests passed.');
}

main().catch((e) => { console.error(e); process.exit(1); });
