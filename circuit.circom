pragma circom 2.0.0;

include "node_modules/circomlib/circuits/sha256/sha256.circom";

template SHA256Preimage() {
    signal input r[264];
    signal input h[256];
    signal input s[256];

    component sha256 = Sha256(520);

    for (var i = 0; i < 264; i++) {
        sha256.in[i] <== r[i];
    }
    for (var i = 0; i < 256; i++) {
        sha256.in[264 + i] <== s[i];
    }

    for (var i = 0; i < 256; i++) {
        sha256.out[i] === h[i];
    }
}

component main { public [r, h] } = SHA256Preimage();