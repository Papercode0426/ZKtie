# ecdsa-zk-circuit

A self-contained Circom zero-knowledge circuit that verifies an ECDSA-style signature over the **secp256k1** curve.

## What the circuit proves

```
public  : r1, h, rhs
witness : s1

Constraint 1 : r1^s1 = rhs                    (secp256k1 scalar multiplication)
Constraint 2 : h = SHA256(r1.x || r1.y || s1)  (hashing)
```

`rhs = g^h1 * y1^r1.x` can be recomputed by the verifier from public values; `s1` is the private witness held by the prover.

## Project layout

```
ECDSA.mjs                 # Off-chain crypto: key generation, proof generation, encoding, witness inputs
circuits/
  verify.circom           # Main circuit (windowed scalar multiplication + SHA256)
  lib/
    bigint.circom         # Self-written 256-bit modular arithmetic (special reduction 2^256 ≡ 2^32+977)
    secp256k1.circom      # EC point addition (collinearity / on-curve constraints), modular add/sub
test.mjs                  # Witness tests (constraint correctness)
prove_verify.mjs          # Full Groth16 prove + verify test
package.json              # Dependencies and scripts
```

## Design notes

- Numbers use **8 little-endian 32-bit limbs** (`k=8, n=32`).
- Scalar multiplication uses a **windowed** technique: a public precomputation table
  `table[32][256][2][8]` is an input, one 8-bit window per entry, selected via a
  Multiplexer and accumulated. The table is a deterministic function of the public `r1`,
  so the verifier can recompute it — no extra trust assumption. This reduces the number of
  on-circuit point additions from ~512 to 31.
- Point addition is validated with collinearity + on-curve constraints instead of circuit-side
  modular inversion, keeping the constraint count manageable.
- All intermediate witnesses (`partial` / `addout`) are computed off-circuit in `ECDSA.mjs`using BigInt.

## Requirements

- Node.js >= 18 (LTS recommended)
- `circom` (>= 2.0.x) — the Circom compiler
- `snarkjs` (>= 0.7.x)

## Installation

```bash
npm install
```

## Compiling the circuit

```bash
npm run build
# equivalent to:
# circom circuits/verify.circom --r1cs --wasm --sym -o build
```

This produces `build/verify.r1cs`, `build/verify.sym`, and `build/verify_js/verify.wasm`.

## Running the tests

```bash
npm test
```

Runs multiple valid proofs through the circuit (constraints satisfied) and checks that
tampered inputs (rhs / h / s1 / r1) are rejected.

## Groth16 trusted setup

The circuit has ~856k constraints, requiring a **power 21** Powers of Tau ceremony.
Use the official Hermez public ptau (no need to run phase 1 yourself):

```bash
mkdir -p build/zk
# download (~2.4 GB)
curl -sSL -C - -o build/zk/pot21_final.ptau \
  "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_21.ptau"

# Groth16 setup (~15 min)
snarkjs groth16 setup build/verify.r1cs build/zk/pot21_final.ptau build/zk/verify_0000.zkey

# Phase 2 contribution
snarkjs zkey contribute build/zk/verify_0000.zkey build/zk/verify_final.zkey \
  --name="c1" -e="some random entropy"

# Export the verification key
snarkjs zkey export verificationkey build/zk/verify_final.zkey build/zk/verification_key.json
```

## Full prove + verify

```bash
node prove_verify.mjs
```

This:

1. Generates a valid proof → `groth16 verify` returns **OK**.
2. Tampers with rhs / h / s1 → the witness calculation fails (constraints unsatisfiable),
   confirming the proof is rejected.

## Expected performance (single core)

| Step                       | Time                   |
| -------------------------- | ---------------------- |
| Witness generation         | ~2.0 s                 |
| Verifier recomputes table  | ~1.1 s                 |
| Groth16 prove              | ~30 s                  |
| Groth16 verify             | ~0.2 s (constant-time) |
| Setup (one-time, power 21) | ~15 min                |

## Test results

- `npm test`: valid proofs pass; tampered rhs / h / s1 are rejected.
- `node prove_verify.mjs`: valid proof verifies with **OK**; tampered inputs are rejected.

## Notes / trade-offs

- The public input `table` is large (131k fields) because it is a windowed precomputation made public so the verifier can recompute it. This is fine for **off-chain verification** but would incur high gas cost if deployed as an on-chain Solidity verifier.
- Proof size is always tiny (~719 bytes), independent of circuit size.
