import hashlib
import secrets
from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point, PointJacobi
from ecdsa.numbertheory import inverse_mod

class ZKProofSystem:
    def __init__(self):
        self.curve = SECP256k1.curve
        self.generator = SECP256k1.generator
        self.q = SECP256k1.order
        
    def int_to_bytes(self, n):
        n = n % self.q
        byte_length = (self.q.bit_length() + 7) // 8
        return n.to_bytes(byte_length, 'big')
    
    def point_hash_data(self, point):
        """Get hashable data from a point (just the x-coordinate)"""
        if isinstance(point, PointJacobi):
            point = point.to_affine()
        return self.int_to_bytes(point.x())
    
    def H3(self, *args):
        data = b''
        for arg in args:
            if isinstance(arg, int):
                data += self.int_to_bytes(arg)
            elif isinstance(arg, (Point, PointJacobi)):
                data += self.point_hash_data(arg)
            elif isinstance(arg, str):
                data += arg.encode('utf-8')
            elif isinstance(arg, bytes):
                data += arg
            else:
                data += str(arg).encode('utf-8')
        
        hash_bytes = hashlib.sha256(data).digest()
        return int.from_bytes(hash_bytes, 'big') % self.q
    
    def mod_inverse(self, a):
        return inverse_mod(a, self.q)
    
    def point_to_int(self, point):
        if isinstance(point, PointJacobi):
            point = point.to_affine()
        return point.x() % self.q
    
    def genZKproof(self, m0, m1, x0, x1):
        y0 = self.generator * x0
        y1 = self.generator * x1
        
        k0 = secrets.randbelow(self.q - 1) + 1
        k1 = secrets.randbelow(self.q - 1) + 1
        
        r0 = self.generator * k0
        r1 = self.generator * k1
        
        h0 = self.H3(y0, r0, m0)
        h1 = self.H3(y1, r1, m1)
        
        s0 = (k0 + x0 * h0) % self.q
        
        k1_inv = self.mod_inverse(k1)
        r1_int = self.point_to_int(r1)
        s1 = (k1_inv * (h1 + x1 * r1_int)) % self.q
        
        tau = (s0 + s1) % self.q
        
        c = (self.generator * tau) + (r0 * (-1 % self.q)) + (y0 * (-h0 % self.q))
        
        r1_int = self.point_to_int(r1)
        d = (self.generator * h1) + (y1 * r1_int)
        
        w = secrets.randbelow(self.q - 1) + 1
        
        gw = self.generator * w
        cw = c * w
        u = self.H3(self.generator, c, r1, d, gw, cw)
        
        v = (w - u * k1) % self.q
        
        # Convert to affine for consistency
        r0 = r0.to_affine() if isinstance(r0, PointJacobi) else r0
        r1 = r1.to_affine() if isinstance(r1, PointJacobi) else r1
        y0 = y0.to_affine() if isinstance(y0, PointJacobi) else y0
        y1 = y1.to_affine() if isinstance(y1, PointJacobi) else y1
        
        return (r0, r1, m0, m1, y0, y1, tau, u, v)
    
    def VerifyZKProof(self, proof_tuple):
        r0, r1, m0, m1, y0, y1, tau, u, v = proof_tuple
        
        h0 = self.H3(y0, r0, m0)
        h1 = self.H3(y1, r1, m1)
        
        c = (self.generator * tau) + (r0 * (-1 % self.q)) + (y0 * (-h0 % self.q))
        
        r1_int = self.point_to_int(r1)
        d = (self.generator * h1) + (y1 * r1_int)
        
        t1 = (self.generator * v) + (r1 * u)
        t2 = (c * v) + (d * u)
        
        u_prime = self.H3(self.generator, c, r1, d, t1, t2)
        
        return u == u_prime

def main():
    zk = ZKProofSystem()
    
    m0 = "Transaction 1: Alice pays Bob 5 BTC"
    m1 = "Transaction 2: Carol pays Dave 3 BTC"
    
    x0 = secrets.randbelow(zk.q - 1) + 1
    x1 = secrets.randbelow(zk.q - 1) + 1
    
    print("Secret x0:", x0)
    print("Secret x1:", x1)
    print()
    
    proof = zk.genZKproof(m0, m1, x0, x1)
    print("✓ Proof generated successfully!")
    
    is_valid = zk.VerifyZKProof(proof)
    print("✓ Verification result:", "Valid ✓" if is_valid else "Invalid ✗")
    
    r0, r1, _, _, y0, y1, tau, u, v = proof
    print("\nProof components:")
    print(f"r0.x: {r0.x()}")
    print(f"r1.x: {r1.x()}")
    print(f"y0.x: {y0.x()}")
    print(f"y1.x: {y1.x()}")
    print(f"tau: {tau}")
    print(f"u: {u}")
    print(f"v: {v}")
    
    print("\n--- Testing with invalid proof ---")
    invalid_proof = list(proof)
    invalid_proof[6] = (invalid_proof[6] + 1) % zk.q
    invalid_proof = tuple(invalid_proof)
    
    is_valid = zk.VerifyZKProof(invalid_proof)
    print("Verification result for invalid proof:", "Valid ✓" if is_valid else "Invalid ✗")

if __name__ == "__main__":
    main()