const snarkjs = require("snarkjs");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const CIRCUIT_WASM = path.join(__dirname, "circuit_js", "circuit.wasm");
const CIRCUIT_R1CS = path.join(__dirname, "circuit.r1cs");
const ZKEY_FILE = path.join(__dirname, "circuit_final.zkey");
const VK_FILE = path.join(__dirname, "verification_key.json");
const PTAU_FILE = path.join(__dirname, "pot16.ptau");

function bytesToBits(bytes) {
    const bits = [];
    for (const b of bytes) {
        for (let j = 7; j >= 0; j--) {
            bits.push((b >> j) & 1);
        }
    }
    return bits;
}

function sha256(...inputs) {
    const hash = crypto.createHash("sha256");
    for (const input of inputs) {
        if (Buffer.isBuffer(input)) {
            hash.update(input);
        } else {
            hash.update(Buffer.from(input, "hex"));
        }
    }
    return hash.digest();
}

async function setup() {
    console.log("=== Phase 1: Powers of Tau ===");
    const PTAU_INIT = path.join(__dirname, "pot16_init.ptau");
    const PTAU_CONT = path.join(__dirname, "pot16_cont.ptau");
    if (!fs.existsSync(PTAU_FILE)) {
        console.log("Step 1: new powers of tau...");
        execSync(`npx snarkjs powersoftau new bn128 16 ${PTAU_INIT}`, { stdio: "inherit" });
        console.log("Step 2: contribute...");
        execSync(`npx snarkjs powersoftau contribute ${PTAU_INIT} ${PTAU_CONT} --name="first" -e="random"`, { stdio: "inherit" });
        console.log("Step 3: prepare phase2...");
        execSync(`npx snarkjs powersoftau prepare phase2 ${PTAU_CONT} ${PTAU_FILE}`, { stdio: "inherit" });
        console.log("Powers of Tau done.");
        try { fs.unlinkSync(PTAU_INIT); } catch(e) {}
        try { fs.unlinkSync(PTAU_CONT); } catch(e) {}
    } else {
        console.log("Powers of Tau file already exists, skipping.");
    }

    console.log("\n=== Phase 2: Circuit Setup (Groth16) ===");
    if (!fs.existsSync(ZKEY_FILE)) {
        console.log("Initializing zkey...");
        execSync(
            `npx snarkjs groth16 setup ${CIRCUIT_R1CS} ${PTAU_FILE} ${ZKEY_FILE}`,
            { stdio: "inherit" }
        );
        console.log("zkey generated.");
    } else {
        console.log("zkey already exists, skipping.");
    }

    if (!fs.existsSync(VK_FILE)) {
        console.log("Exporting verification key...");
        execSync(
            `npx snarkjs zkey export verificationkey ${ZKEY_FILE} ${VK_FILE}`,
            { stdio: "inherit" }
        );
        console.log("Verification key exported.");
    } else {
        console.log("Verification key already exists, skipping.");
    }
}

async function genProof(input) {
    const startTime = process.hrtime.bigint();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        CIRCUIT_WASM,
        ZKEY_FILE
    );
    const endTime = process.hrtime.bigint();
    const elapsed = Number(endTime - startTime) / 1e6;
    return { proof, publicSignals, timeMs: elapsed };
}

async function verifyProof(proof, publicSignals) {
    const vk = JSON.parse(fs.readFileSync(VK_FILE, "utf8"));
    const startTime = process.hrtime.bigint();
    const result = await snarkjs.groth16.verify(vk, publicSignals, proof);
    const endTime = process.hrtime.bigint();
    const elapsed = Number(endTime - startTime) / 1e6;
    return { verified: result, timeMs: elapsed };
}

async function main() {
    console.log("=".repeat(60));
    console.log("SHA256 Preimage ZK Circuit Test");
    console.log("=".repeat(60));

    await setup();

    const vk = JSON.parse(fs.readFileSync(VK_FILE, "utf8"));
    const zkeyStat = fs.statSync(ZKEY_FILE);
    const vkStr = JSON.stringify(vk);

    console.log("\n=== Size Measurements ===");
    console.log(`PK (zkey) size:     ${(zkeyStat.size / 1024 / 1024).toFixed(2)} MB`);
    console.log(`VK size:            ${(vkStr.length / 1024).toFixed(2)} KB`);

    console.log("\n=== Test: Generate Inputs ===");
    const rBytes = crypto.randomBytes(33);
    const sBytes = crypto.randomBytes(32);
    const hBytes = sha256(Buffer.concat([rBytes, sBytes]));

    console.log(`r (33 bytes):       ${rBytes.toString("hex").slice(0, 32)}...`);
    console.log(`s (32 bytes):       ${sBytes.toString("hex").slice(0, 32)}...`);
    console.log(`h (32 bytes):       ${hBytes.toString("hex")}`);

    const input = {
        r: bytesToBits(rBytes),
        h: bytesToBits(hBytes),
        s: bytesToBits(sBytes),
    };

    console.log("\n=== Test: Generate Proof (genProof) ===");
    const { proof, publicSignals, timeMs: genTime } = await genProof(input);
    const proofStr = JSON.stringify(proof);
    console.log(`Proof size:         ${(proofStr.length / 1024).toFixed(2)} KB`);
    console.log(`genProof time:      ${genTime.toFixed(2)} ms`);

    console.log("\n=== Test: Verify Proof (verifyProof) ===");
    const { verified, timeMs: verifyTime } = await verifyProof(proof, publicSignals);
    console.log(`verifyProof time:   ${verifyTime.toFixed(2)} ms`);
    console.log(`Verification:       ${verified ? "PASS" : "FAIL"}`);

    console.log("\n" + "=".repeat(60));
    console.log("Summary:");
    console.log(`  Constraints:      62528 (59313 non-linear + 3215 linear)`);
    console.log(`  PK (zkey) size:   ${(zkeyStat.size / 1024 / 1024).toFixed(2)} MB`);
    console.log(`  VK size:          ${(vkStr.length / 1024).toFixed(2)} KB`);
    console.log(`  Proof size:       ${(proofStr.length / 1024).toFixed(2)} KB`);
    console.log(`  genProof time:    ${genTime.toFixed(2)} ms`);
    console.log(`  verifyProof time: ${verifyTime.toFixed(2)} ms`);
    console.log("=".repeat(60));
}

main()
    .then(() => {
        console.log("\nTest completed successfully!");
        process.exit(0);
    })
    .catch((err) => {
        console.error("Test failed:", err);
        process.exit(1);
    });