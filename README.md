# SHA256 Preimage Zero-Knowledge Circuit

Circuit: given public `r` (264-bit compressed secp256k1 point) and `h` (256-bit hash), prove knowledge of private `s` (256-bit scalar) such that `h = SHA256(r || s)`.

Built with circom + snarkjs (Groth16 on BN128).

## Circuit Design

```
Template: SHA256Preimage
- Public inputs:  r[264]  (33 bytes, compressed point)
- Public inputs:  h[256]  (32 bytes, hash output)
- Private input:  s[256]  (32 bytes, scalar witness)
- Constraint:     SHA256(r || s) == h
```

Uses `Sha256(520)` from circomlib (2 SHA256 compression blocks for 65-byte input).

| Metric | Value |
|---|---|
| Total constraints | 62,528 |
| Wires | 62,425 |
| Public inputs | 520 |
| Private inputs | 256 |

## Prerequisites

- Node.js v16+
- [circom](https://docs.circom.io/) v2.0+

```bash
curl -Ls https://raw.githubusercontent.com/iden3/circom/master/scripts/install-circom.sh | bash
```

## Quick Start

```bash
npm install
npx circom circuit.circom --r1cs --wasm --sym --output .
node test.js
```

`test.js` runs: Powers of Tau → Groth16 setup → genProof → verifyProof → prints sizes & timings.

## API

### `genProof(input)`

```javascript
const { proof, publicSignals, timeMs } = await genProof({
    r: [0, 1, 0, ...],  // 264 bits
    h: [1, 0, 1, ...],  // 256 bits
    s: [0, 0, 1, ...],  // 256 bits (private witness)
});
```

### `verifyProof(proof, publicSignals)`

```javascript
const { verified, timeMs } = await verifyProof(proof, publicSignals);
```

## File Structure

```
zk-sha256-circuit/
├── circuit.circom              # Circuit source
├── test.js                     # Test script
├── package.json                # Dependencies
├── circuit.r1cs                # Compiled R1CS
├── circuit.sym                 # Symbol mapping
├── circuit_js/
│   └── circuit.wasm            # Witness WASM
├── pot16.ptau                  # Powers of Tau
├── circuit_final.zkey          # Proving key
└── verification_key.json       # Verification key
```

## Deployment

### Source code deployment (recipient compiles + sets up):

```
circuit.circom + package.json + test.js
```

```bash
npm install
npx circom circuit.circom --r1cs --wasm --sym --output .
node test.js
```

### Pre-compiled deployment (no circom needed):

```
circuit_js/circuit.wasm + circuit_final.zkey + verification_key.json + test.js + package.json
```

```bash
npm install
node test.js
```

## Proving System

- **Scheme**: Groth16
- **Curve**: BN128
- **Powers of Tau**: pot16 (2^16)
- **Hash**: SHA256 (circomlib)

## Notes

- Input bits use **big-endian** byte order (MSB first per byte), matching SHA256's internal representation.
- `genProof` time is dominated by MSM operations; `verifyProof` is fast (constant-time pairings).
- zkTieProof.py is used to generate and verify the combination of ECDSA and Shnorr.
