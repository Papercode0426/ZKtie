pragma circom 2.0.2;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/gates.circom";

// ---------------------------------------------------------------------------
// 自包含的 256-bit 模 p 算术，p = secp256k1 素数。
// 所有数用 k=8 个 32-bit little-endian limbs 表示（n=32, k=8）。
// 模乘用特殊约减：p = 2^256 - 2^32 - 977  =>  2^256 ≡ c = 2^32 + 977 (mod p)
// ---------------------------------------------------------------------------

// secp256k1 素数 p 的 8 个 32-bit limbs
function ifn_p() {
    var p[8];
    p[0] = 4294966319;   // 0xFFFFFC2F
    p[1] = 4294967294;   // 0xFFFFFFFE
    p[2] = 4294967295;
    p[3] = 4294967295;
    p[4] = 4294967295;
    p[5] = 4294967295;
    p[6] = 4294967295;
    p[7] = 4294967295;
    return p;
}

// p^{-1} mod 2^256 的 8 个 32-bit limbs（常数）
function ifn_invp() {
    var c[8];
    c[0] = 769313487;
    c[1] = 667416290;
    c[2] = 601579430;
    c[3] = 1129176065;
    c[4] = 1779255454;
    c[5] = 1673084221;
    c[6] = 3937172582;
    c[7] = 910354170;
    return c;
}

// 比较 a >= b（8 个 32-bit limb，高位优先，含相等）
function ifn_ge(a, b) {
    var ge = 1;
    var decided = 0;
    for (var i = 7; i >= 0; i--) {
        if (decided == 0) {
            if (a[i] > b[i]) { ge = 1; decided = 1; }
            else if (a[i] < b[i]) { ge = 0; decided = 1; }
        }
    }
    return ge;
}

// 把 8 个 32-bit limb 的数 r（< 2^256）归约到 [0, p)
function ifn_reduce(v) {
    var p[8] = ifn_p();
    var r[8];
    for (var i = 0; i < 8; i++) r[i] = v[i];
    for (var IT = 0; IT < 2; IT++) {
        var ge = ifn_ge(r, p);
        if (ge == 1) {
            var borrow = 0;
            for (var i = 0; i < 8; i++) {
                var sub = r[i] - p[i] - borrow;
                if (sub < 0) { sub += 4294967296; borrow = 1; }
                else borrow = 0;
                r[i] = sub;
            }
        }
    }
    return r;
}

// 模乘：out = (a*b) mod p，a,b 各 8 个 32-bit limb
function ifn_modmul(a, b) {
    var prod[15];
    for (var i = 0; i < 15; i++) prod[i] = 0;
    for (var i = 0; i < 8; i++)
        for (var j = 0; j < 8; j++)
            prod[i + j] += a[i] * b[j];
    var clean[16];
    var carry = 0;
    for (var i = 0; i < 15; i++) {
        var v = prod[i] + carry;
        clean[i] = v % 4294967296;
        carry = v \ 4294967296;
    }
    clean[15] = carry;
    var c = 4294968273;  // 2^32 + 977
    var hm[9];
    var hc = 0;
    for (var i = 0; i < 8; i++) {
        var hv = clean[8 + i] * 977 + hc;
        hm[i] = hv % 4294967296;
        hc = hv \ 4294967296;
    }
    hm[8] = hc;
    var t[9];
    var tc = 0;
    for (var i = 0; i < 9; i++) {
        var lv = (i < 8 ? clean[i] : 0);
        var sv = (i >= 1 ? clean[7 + i] : 0);
        var tv = lv + sv + hm[i] + tc;
        t[i] = tv % 4294967296;
        tc = tv \ 4294967296;
    }
    var th = t[8];
    var cs0 = (th * 977) % 4294967296;
    var cs1 = (th * 977) \ 4294967296;
    var t2[9];
    var c2 = 0;
    for (var i = 0; i < 9; i++) {
        var lv = (i < 8 ? t[i] : 0);
        var sh2 = (i == 1 ? th : 0);
        var csm = (i == 0 ? cs0 : (i == 1 ? cs1 : 0));
        var tv = lv + sh2 + csm + c2;
        t2[i] = tv % 4294967296;
        c2 = tv \ 4294967296;
    }
    var p[8] = ifn_p();
    for (var IT = 0; IT < 3; IT++) {
        var ge = 0;
        if (t2[8] > 0) ge = 1;
        else ge = ifn_ge(t2, p);
        if (ge == 1) {
            var borrow = 0;
            for (var i = 0; i < 8; i++) {
                var sub = t2[i] - p[i] - borrow;
                if (sub < 0) { sub += 4294967296; borrow = 1; }
                else borrow = 0;
                t2[i] = sub;
            }
            t2[8] = t2[8] - borrow;
        }
    }
    var r[8];
    for (var i = 0; i < 8; i++) r[i] = t2[i];
    return r;
}

// 模板：range check 8 个 32-bit limb
template RangeCheck(k) {
    signal input in[k];
    component rc[k];
    for (var i = 0; i < k; i++) {
        rc[i] = Num2Bits(32);
        rc[i].in <== in[i];
    }
}

// 无进位卷积：out[s] = sum_{i+j=s} a[i]*b[j]（overflowed limbs）
template BigMultNoCarry(ka, kb) {
    signal input a[ka];
    signal input b[kb];
    signal output out[ka + kb - 1];
    var prod[ka + kb - 1];
    for (var s = 0; s < ka + kb - 1; s++) prod[s] = 0;
    for (var i = 0; i < ka; i++)
        for (var j = 0; j < kb; j++)
            prod[i + j] += a[i] * b[j];
    for (var s = 0; s < ka + kb - 1; s++) out[s] <-- prod[s];
    var np = ka + kb - 1;
    for (var x = 0; x < np; x++) {
        var lhs = 0;
        var xp = 1;
        for (var s = 0; s < np; s++) { lhs += out[s] * xp; xp *= x; }
        var A = 0;
        xp = 1;
        for (var s = 0; s < ka; s++) { A += a[s] * xp; xp *= x; }
        var B = 0;
        xp = 1;
        for (var s = 0; s < kb; s++) { B += b[s] * xp; xp *= x; }
        lhs === A * B;
    }
}

// overflowed limbs -> 干净 32-bit limbs
template LongToShort(k) {
    signal input in[k];
    signal output out[k + 1];
    out[0] <-- in[0] % 4294967296;
    signal carry[k];
    carry[0] <-- in[0] \ 4294967296;
    in[0] === carry[0] * 4294967296 + out[0];
    for (var i = 1; i < k; i++) {
        out[i] <-- (in[i] + carry[i - 1]) % 4294967296;
        carry[i] <-- (in[i] + carry[i - 1]) \ 4294967296;
        in[i] + carry[i - 1] === carry[i] * 4294967296 + out[i];
    }
    out[k] <-- carry[k - 1];
    component rc_out[k + 1];
    for (var i = 0; i <= k; i++) { rc_out[i] = Num2Bits(32); rc_out[i].in <== out[i]; }
}

// 大数乘法，返回干净 limbs
template BigMult(ka, kb) {
    signal input a[ka];
    signal input b[kb];
    signal output out[ka + kb];
    component mult = BigMultNoCarry(ka, kb);
    for (var i = 0; i < ka; i++) mult.a[i] <== a[i];
    for (var i = 0; i < kb; i++) mult.b[i] <== b[i];
    component ls = LongToShort(ka + kb - 1);
    for (var i = 0; i < ka + kb - 1; i++) ls.in[i] <== mult.out[i];
    for (var i = 0; i < ka + kb; i++) out[i] <== ls.out[i];
}

// 大数小于（a < b）
template BigLessThan(k) {
    signal input a[k];
    signal input b[k];
    signal output out;
    component lt[k];
    component eq[k];
    for (var i = 0; i < k; i++) {
        lt[i] = LessThan(32);
        lt[i].in[0] <== a[i];
        lt[i].in[1] <== b[i];
        eq[i] = IsEqual();
        eq[i].in[0] <== a[i];
        eq[i].in[1] <== b[i];
    }
    signal acc[k];
    signal eq_all[k][k];
    acc[k - 1] <== lt[k - 1].out;
    for (var i = k - 2; i >= 0; i--) {
        eq_all[i][i + 1] <== eq[i + 1].out;
        for (var j = i + 2; j < k; j++) eq_all[i][j] <== eq_all[i][j - 1] * eq[j].out;
        acc[i] <== acc[i + 1] + eq_all[i][k - 1] * lt[i].out;
    }
    out <== acc[0];
}

// 大数相等
template BigEq(k) {
    signal input in[2][k];
    signal output out;
    component eq[k];
    for (var i = 0; i < k; i++) {
        eq[i] = IsEqual();
        eq[i].in[0] <== in[0][i];
        eq[i].in[1] <== in[1][i];
    }
    signal sumarr[k];
    sumarr[0] <== eq[0].out;
    for (var i = 1; i < k; i++) sumarr[i] <== sumarr[i - 1] * eq[i].out;
    out <== sumarr[k - 1];
}

// 模乘模板：out = (a*b) mod p
// witness out 由链侧函数算，验证 out = a*b mod p 通过：
//   a*b == out + k*p，其中 k = (a*b - out) * p^{-1} mod 2^256（链侧函数算）
template ModMulP() {
    signal input a[8];
    signal input b[8];
    signal input p[8];
    signal output out[8];

    var rr[8] = ifn_modmul(a, b);
    for (var i = 0; i < 8; i++) out[i] <-- rr[i];
    component rc_out = RangeCheck(8);
    for (var i = 0; i < 8; i++) rc_out.in[i] <== out[i];

    // 验证 out < p
    component lt = BigLessThan(8);
    lt.a[0] <== out[0]; lt.b[0] <== p[0];
    lt.a[1] <== out[1]; lt.b[1] <== p[1];
    lt.a[2] <== out[2]; lt.b[2] <== p[2];
    lt.a[3] <== out[3]; lt.b[3] <== p[3];
    lt.a[4] <== out[4]; lt.b[4] <== p[4];
    lt.a[5] <== out[5]; lt.b[5] <== p[5];
    lt.a[6] <== out[6]; lt.b[6] <== p[6];
    lt.a[7] <== out[7]; lt.b[7] <== p[7];
    lt.out === 1;

    // 计算 a*b（16 limbs）与 out + k*p（16 limbs）并比较
    component abm = BigMult(8, 8);
    for (var i = 0; i < 8; i++) { abm.a[i] <== a[i]; abm.b[i] <== b[i]; }

    // k = (a*b - out) * inv_p mod 2^256
    signal k[8];
    // 用专门函数计算 k（见 ifn_moddiv）
    var kk[8] = ifn_moddiv(a, b, out);
    for (var i = 0; i < 8; i++) k[i] <-- kk[i];
    component rc_k = RangeCheck(8);
    for (var i = 0; i < 8; i++) rc_k.in[i] <== k[i];

    component kpm = BigMult(8, 8);
    for (var i = 0; i < 8; i++) { kpm.a[i] <== k[i]; kpm.b[i] <== p[i]; }

    // out + k*p：kpm.out 是 16 limbs，out 加到低 8 个
    // 验证 abm.out == kpm.out + out（16 limbs，带进位）
    // 逐 limb 比较（处理进位）
    signal sum16[16];
    signal carry16[16];
    sum16[0] <-- (kpm.out[0] + out[0]) % 4294967296;
    carry16[0] <-- (kpm.out[0] + out[0]) \ 4294967296;
    sum16[0] === kpm.out[0] + out[0] - carry16[0] * 4294967296;
    for (var i = 1; i < 16; i++) {
        var bval = (i < 8 ? out[i] : 0);
        carry16[i] <-- (kpm.out[i] + bval + carry16[i - 1]) \ 4294967296;
        sum16[i] <-- (kpm.out[i] + bval + carry16[i - 1]) % 4294967296;
        kpm.out[i] + bval + carry16[i - 1] === carry16[i] * 4294967296 + sum16[i];
    }
    component cheq[16];
    for (var i = 0; i < 16; i++) {
        cheq[i] = IsEqual();
        cheq[i].in[0] <== sum16[i];
        cheq[i].in[1] <== abm.out[i];
    }
    signal all_arr16[16];
    all_arr16[0] <== cheq[0].out;
    for (var i = 1; i < 16; i++) all_arr16[i] <== all_arr16[i - 1] * cheq[i].out;
    all_arr16[15] === 1;
}

// 模加：out = (a + b) mod p（a,b < p）
function ifn_modadd(a, b) {
    var p[8] = ifn_p();
    var s[9];
    var c = 0;
    for (var i = 0; i < 8; i++) {
        var v = a[i] + b[i] + c;
        s[i] = v % 4294967296;
        c = v \ 4294967296;
    }
    s[8] = c;
    // 反复减 p（s < 2p，最多 2 次）
    for (var IT = 0; IT < 2; IT++) {
        var ge = 0;
        if (s[8] > 0) ge = 1;
        else ge = ifn_ge(s, p);
        if (ge == 1) {
            var borrow = 0;
            for (var i = 0; i < 8; i++) {
                var sub = s[i] - p[i] - borrow;
                if (sub < 0) { sub += 4294967296; borrow = 1; } else borrow = 0;
                s[i] = sub;
            }
            s[8] = s[8] - borrow;
        }
    }
    var r[8];
    for (var i = 0; i < 8; i++) r[i] = s[i];
    return r;
}

// 模减：out = (a - b) mod p（a,b < p）
function ifn_modsub(a, b) {
    var p[8] = ifn_p();
    var d[8];
    var borrow = 0;
    for (var i = 0; i < 8; i++) {
        var sub = a[i] - b[i] - borrow;
        if (sub < 0) { sub += 4294967296; borrow = 1; } else borrow = 0;
        d[i] = sub;
    }
    // 若 borrow，则 a<b，out = a - b + p
    var r[8];
    if (borrow == 1) {
        var c = 0;
        for (var i = 0; i < 8; i++) {
            var v = d[i] + p[i] + c;
            r[i] = v % 4294967296;
            c = v \ 4294967296;
        }
    } else {
        for (var i = 0; i < 8; i++) r[i] = d[i];
    }
    return r;
}

// a+b >= p ? 1 : 0（用于 ModAddP 的 k witness）
function ifn_modadd_k(a, b) {
    var p[8] = ifn_p();
    var s[9];
    var c = 0;
    for (var i = 0; i < 8; i++) {
        var v = a[i] + b[i] + c;
        s[i] = v % 4294967296;
        c = v \ 4294967296;
    }
    s[8] = c;
    if (s[8] > 0) return 1;
    return ifn_ge(s, p);
}

// a < b ? 1 : 0（用于 ModSubP 的 k witness）
function ifn_modsub_k(a, b) {
    var borrow = 0;
    for (var i = 0; i < 8; i++) {
        var sub = a[i] - b[i] - borrow;
        if (sub < 0) { sub += 4294967296; borrow = 1; } else borrow = 0;
    }
    return borrow;
}

// 计算 k = (a*b - out) * inv_p mod 2^256（8 limbs）
function ifn_moddiv(a, b, out) {
    var inv[8] = ifn_invp();
    // t = a*b - out（先算 a*b 低 8 limbs，再减 out）
    // a*b 低 8 limbs：卷积后取 i+j<8 项 + 进位
    var prod_low[8];
    for (var i = 0; i < 8; i++) prod_low[i] = 0;
    var carry = 0;
    for (var s = 0; s < 8; s++) {
        var acc = carry;
        for (var i = 0; i <= s; i++) acc += a[i] * b[s - i];
        prod_low[s] = acc % 4294967296;
        carry = acc \ 4294967296;
    }
    // t = prod_low - out（mod 2^256）
    var t[8];
    var borrow = 0;
    for (var i = 0; i < 8; i++) {
        var sub = prod_low[i] - out[i] - borrow;
        if (sub < 0) { sub += 4294967296; borrow = 1; } else borrow = 0;
        t[i] = sub;
    }
    // k = t * inv mod 2^256
    var k[8];
    for (var i = 0; i < 8; i++) k[i] = 0;
    var kc = 0;
    for (var s = 0; s < 8; s++) {
        var acc = kc;
        for (var i = 0; i <= s; i++) acc += t[i] * inv[s - i];
        k[s] = acc % 4294967296;
        kc = acc \ 4294967296;
    }
    return k;
}