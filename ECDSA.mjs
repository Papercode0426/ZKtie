pragma circom 2.0.2;

include "bigint.circom";
include "../../node_modules/circomlib/circuits/multiplexer.circom";

// ---------------------------------------------------------------------------
// secp256k1 曲线 y^2 = x^3 + 7 (mod p)，点用 8 个 32-bit limb 表示（x, y）。
// 所有中间结果由链侧函数计算（<-- witness），电路用约束验证正确性。
// ---------------------------------------------------------------------------

// 模加：out = (a + b) mod p
// 验证：a + b == out + k*p，k ∈ {0,1}（因为 a+b < 2p）
template ModAddP() {
    signal input a[8];
    signal input b[8];
    signal input p[8];
    signal output out[8];

    var rr[8] = ifn_modadd(a, b);
    for (var i = 0; i < 8; i++) out[i] <-- rr[i];
    component rc = RangeCheck(8);
    for (var i = 0; i < 8; i++) rc.in[i] <== out[i];

    // k witness：a+b >= p ? 1 : 0
    signal k;
    k <-- ifn_modadd_k(a, b);

    // 验证 a + b == out + k*p（9 limbs，带进位到第 9 位）
    // 左边 a+b：9 limbs
    signal s[9];
    signal sc[9];
    sc[0] <-- 0;
    sc[0] === 0;
    for (var i = 0; i < 8; i++) {
        s[i] <-- (a[i] + b[i] + sc[i]) % 4294967296;
        sc[i + 1] <-- (a[i] + b[i] + sc[i]) \ 4294967296;
        a[i] + b[i] + sc[i] === sc[i + 1] * 4294967296 + s[i];
    }
    s[8] <-- sc[8];

    // 右边 out + k*p：8 limbs + 进位
    signal r[9];
    signal rc2[9];
    rc2[0] <-- 0;
    rc2[0] === 0;
    for (var i = 0; i < 8; i++) {
        r[i] <-- (out[i] + k * p[i] + rc2[i]) % 4294967296;
        rc2[i + 1] <-- (out[i] + k * p[i] + rc2[i]) \ 4294967296;
        out[i] + k * p[i] + rc2[i] === rc2[i + 1] * 4294967296 + r[i];
    }
    r[8] <-- rc2[8];

    // s == r
    component eq[9];
    for (var i = 0; i < 9; i++) {
        eq[i] = IsEqual();
        eq[i].in[0] <== s[i];
        eq[i].in[1] <== r[i];
    }
    signal all_arr[9];
    all_arr[0] <== eq[0].out;
    for (var i = 1; i < 9; i++) all_arr[i] <== all_arr[i - 1] * eq[i].out;
    all_arr[8] === 1;
}

// 模减：out = (a - b) mod p
// 验证：a == b + out - k*p 或 a + k*p == b + out，k = (a<b) ? 1 : 0
template ModSubP() {
    signal input a[8];
    signal input b[8];
    signal input p[8];
    signal output out[8];

    var rr[8] = ifn_modsub(a, b);
    for (var i = 0; i < 8; i++) out[i] <-- rr[i];
    component rc = RangeCheck(8);
    for (var i = 0; i < 8; i++) rc.in[i] <== out[i];

    // k witness：a < b ? 1 : 0
    signal k;
    k <-- ifn_modsub_k(a, b);

    // 验证 a + k*p == b + out（9 limbs）
    signal s[9];   // a + k*p
    signal sc[9];
    sc[0] <-- 0;
    sc[0] === 0;
    for (var i = 0; i < 8; i++) {
        s[i] <-- (a[i] + k * p[i] + sc[i]) % 4294967296;
        sc[i + 1] <-- (a[i] + k * p[i] + sc[i]) \ 4294967296;
        a[i] + k * p[i] + sc[i] === sc[i + 1] * 4294967296 + s[i];
    }
    s[8] <-- sc[8];

    signal r[9];   // b + out
    signal rc2[9];
    rc2[0] <-- 0;
    rc2[0] === 0;
    for (var i = 0; i < 8; i++) {
        r[i] <-- (b[i] + out[i] + rc2[i]) % 4294967296;
        rc2[i + 1] <-- (b[i] + out[i] + rc2[i]) \ 4294967296;
        b[i] + out[i] + rc2[i] === rc2[i + 1] * 4294967296 + r[i];
    }
    r[8] <-- rc2[8];

    component eq[9];
    for (var i = 0; i < 9; i++) {
        eq[i] = IsEqual();
        eq[i].in[0] <== s[i];
        eq[i].in[1] <== r[i];
    }
    signal all_arr[9];
    all_arr[0] <== eq[0].out;
    for (var i = 1; i < 9; i++) all_arr[i] <== all_arr[i - 1] * eq[i].out;
    all_arr[8] === 1;
}

// 验证点 (x,y) 在曲线上：y^2 == x^3 + 7 (mod p)
template PointOnCurve() {
    signal input x[8];
    signal input y[8];
    signal input p[8];

    component x2 = ModMulP();
    for (var i = 0; i < 8; i++) { x2.a[i] <== x[i]; x2.b[i] <== x[i]; x2.p[i] <== p[i]; }
    component x3 = ModMulP();
    for (var i = 0; i < 8; i++) { x3.a[i] <== x2.out[i]; x3.b[i] <== x[i]; x3.p[i] <== p[i]; }
    component y2 = ModMulP();
    for (var i = 0; i < 8; i++) { y2.a[i] <== y[i]; y2.b[i] <== y[i]; y2.p[i] <== p[i]; }

    // x^3 + 7 - y^2 == 0  =>  x^3 + 7 == y^2
    // 构造常量 7
    signal p7[8];
    p7[0] <== 7;
    for (var i = 1; i < 8; i++) p7[i] <== 0;
    component add7 = ModAddP();
    for (var i = 0; i < 8; i++) { add7.a[i] <== x3.out[i]; add7.b[i] <== p7[i]; add7.p[i] <== p[i]; }

    component eq = BigEq(8);
    for (var i = 0; i < 8; i++) { eq.in[0][i] <== add7.out[i]; eq.in[1][i] <== y2.out[i]; }
    eq.out === 1;
}

// 验证 a, b, out 三点共线：
//   x3*y2 + x2*y3 + x2*y1 - x3*y1 - x1*y2 - x1*y3 == 0 (mod p)
template PointOnLine() {
    signal input x1[8]; signal input y1[8];
    signal input x2[8]; signal input y2[8];
    signal input x3[8]; signal input y3[8];
    signal input p[8];

    component m1 = ModMulP(); // x3*y2
    component m2 = ModMulP(); // x2*y3
    component m3 = ModMulP(); // x2*y1
    component m4 = ModMulP(); // x3*y1
    component m5 = ModMulP(); // x1*y2
    component m6 = ModMulP(); // x1*y3
    for (var i = 0; i < 8; i++) {
        m1.a[i] <== x3[i]; m1.b[i] <== y2[i]; m1.p[i] <== p[i];
        m2.a[i] <== x2[i]; m2.b[i] <== y3[i]; m2.p[i] <== p[i];
        m3.a[i] <== x2[i]; m3.b[i] <== y1[i]; m3.p[i] <== p[i];
        m4.a[i] <== x3[i]; m4.b[i] <== y1[i]; m4.p[i] <== p[i];
        m5.a[i] <== x1[i]; m5.b[i] <== y2[i]; m5.p[i] <== p[i];
        m6.a[i] <== x1[i]; m6.b[i] <== y3[i]; m6.p[i] <== p[i];
    }

    // lhs = (m1+m2+m3) - (m4+m5+m6) mod p == 0
    component s12 = ModAddP();
    for (var i = 0; i < 8; i++) { s12.a[i] <== m1.out[i]; s12.b[i] <== m2.out[i]; s12.p[i] <== p[i]; }
    component s123 = ModAddP();
    for (var i = 0; i < 8; i++) { s123.a[i] <== s12.out[i]; s123.b[i] <== m3.out[i]; s123.p[i] <== p[i]; }
    component s45 = ModAddP();
    for (var i = 0; i < 8; i++) { s45.a[i] <== m4.out[i]; s45.b[i] <== m5.out[i]; s45.p[i] <== p[i]; }
    component s456 = ModAddP();
    for (var i = 0; i < 8; i++) { s456.a[i] <== s45.out[i]; s456.b[i] <== m6.out[i]; s456.p[i] <== p[i]; }
    component sub = ModSubP();
    for (var i = 0; i < 8; i++) { sub.a[i] <== s123.out[i]; sub.b[i] <== s456.out[i]; sub.p[i] <== p[i]; }

    component zero = BigEq(8);
    for (var i = 0; i < 8; i++) { zero.in[0][i] <== sub.out[i]; zero.in[1][i] <== 0; }
    zero.out === 1;
}

// 点加：out = a + b（a, b 不同且非无穷远点）
// out 由链侧 JS 计算作为 witness 传入，电路验证 out 正确（在曲线上 + 共线）
template AddUnequal() {
    signal input a[2][8];
    signal input b[2][8];
    signal input out[2][8];
    signal input p[8];

    // 验证 out 在曲线上
    component poc = PointOnCurve();
    for (var i = 0; i < 8; i++) { poc.x[i] <== out[0][i]; poc.y[i] <== out[1][i]; poc.p[i] <== p[i]; }
    // 验证 a,b,out 共线
    component pol = PointOnLine();
    for (var i = 0; i < 8; i++) {
        pol.x1[i] <== a[0][i]; pol.y1[i] <== a[1][i];
        pol.x2[i] <== b[0][i]; pol.y2[i] <== b[1][i];
        pol.x3[i] <== out[0][i]; pol.y3[i] <== out[1][i];
        pol.p[i] <== p[i];
    }
}