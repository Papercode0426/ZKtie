import hashlib
import secrets
import time
import statistics
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

def time_function(func, *args, repeats=100):
    """
    Measure the average execution time of a function
    
    Args:
        func: The function to time
        *args: Arguments to pass to the function
        repeats: Number of times to repeat the measurement
    
    Returns:
        tuple: (average_time, min_time, max_time, std_dev, times_list)
    """
    times = []
    
    # Warm-up run
    func(*args)
    
    for _ in range(repeats):
        start_time = time.perf_counter()
        result = func(*args)
        end_time = time.perf_counter()
        times.append(end_time - start_time)
    
    avg_time = statistics.mean(times)
    min_time = min(times)
    max_time = max(times)
    std_dev = statistics.stdev(times) if len(times) > 1 else 0
    
    return avg_time, min_time, max_time, std_dev, times

def format_time(seconds):
    """Format time in appropriate units"""
    if seconds < 1e-6:
        return f"{seconds * 1e9:.2f} ns"
    elif seconds < 1e-3:
        return f"{seconds * 1e6:.2f} µs"
    elif seconds < 1:
        return f"{seconds * 1e3:.2f} ms"
    else:
        return f"{seconds:.4f} s"

def run_timing_tests(repeats=100):
    """Run comprehensive timing tests"""
    print("=" * 80)
    print(f"ZK PROOF SYSTEM - PERFORMANCE ANALYSIS")
    print(f"Running each test {repeats} times")
    print("=" * 80)
    print()
    
    zk = ZKProofSystem()
    
    # Test messages
    m0 = "Transaction 1: Alice pays Bob 5 BTC"
    m1 = "Transaction 2: Carol pays Dave 3 BTC"
    
    # Generate random secrets
    x0 = secrets.randbelow(zk.q - 1) + 1
    x1 = secrets.randbelow(zk.q - 1) + 1
    
    print("Configuration:")
    print(f"  Group order (q): {zk.q}")
    print(f"  Message 0: {m0}")
    print(f"  Message 1: {m1}")
    print()
    
    # 1. Time point_to_bytes (indirectly through H3)
    print("1. Timing individual operations:")
    print("-" * 40)
    
    # Test H3 with different input types
    test_point = zk.generator * secrets.randbelow(zk.q - 1)
    test_int = secrets.randbelow(zk.q - 1)
    test_str = "test message"
    
    # Time H3 with point only
    avg, min_t, max_t, std, _ = time_function(zk.H3, test_point, repeats=repeats)
    print(f"   H3 (point only):        avg={format_time(avg)}, min={format_time(min_t)}, max={format_time(max_t)}, std={format_time(std)}")
    
    # Time H3 with point and string
    avg, min_t, max_t, std, _ = time_function(zk.H3, test_point, test_str, repeats=repeats)
    print(f"   H3 (point + string):    avg={format_time(avg)}, min={format_time(min_t)}, max={format_time(max_t)}, std={format_time(std)}")
    
    # Time H3 with multiple points
    avg, min_t, max_t, std, _ = time_function(zk.H3, test_point, test_point, test_point, test_point, repeats=repeats)
    print(f"   H3 (4 points):          avg={format_time(avg)}, min={format_time(min_t)}, max={format_time(max_t)}, std={format_time(std)}")
    
    # Time mod_inverse
    test_a = secrets.randbelow(zk.q - 1) + 1
    avg, min_t, max_t, std, _ = time_function(zk.mod_inverse, test_a, repeats=repeats)
    print(f"   mod_inverse:            avg={format_time(avg)}, min={format_time(min_t)}, max={format_time(max_t)}, std={format_time(std)}")
    
    print()
    
    # 2. Time genZKproof
    print("2. Timing genZKproof():")
    print("-" * 40)
    
    # Pre-generate random values for consistent testing
    test_x0 = secrets.randbelow(zk.q - 1) + 1
    test_x1 = secrets.randbelow(zk.q - 1) + 1
    
    avg, min_t, max_t, std, times_proof = time_function(
        zk.genZKproof, m0, m1, test_x0, test_x1, repeats=repeats
    )
    print(f"   Average time:  {format_time(avg)}")
    print(f"   Min time:      {format_time(min_t)}")
    print(f"   Max time:      {format_time(max_t)}")
    print(f"   Std deviation: {format_time(std)}")
    
    # Generate a proof for verification timing
    proof = zk.genZKproof(m0, m1, test_x0, test_x1)
    
    print()
    
    # 3. Time VerifyZKProof
    print("3. Timing VerifyZKProof():")
    print("-" * 40)
    
    avg, min_t, max_t, std, times_verify = time_function(
        zk.VerifyZKProof, proof, repeats=repeats
    )
    print(f"   Average time:  {format_time(avg)}")
    print(f"   Min time:      {format_time(min_t)}")
    print(f"   Max time:      {format_time(max_t)}")
    print(f"   Std deviation: {format_time(std)}")
    
    print()
    
    # 4. Time full cycle (generate + verify)
    print("4. Timing full cycle (gen + verify):")
    print("-" * 40)
    
    def full_cycle():
        p = zk.genZKproof(m0, m1, test_x0, test_x1)
        return zk.VerifyZKProof(p)
    
    avg, min_t, max_t, std, _ = time_function(full_cycle, repeats=repeats)
    print(f"   Average time:  {format_time(avg)}")
    print(f"   Min time:      {format_time(min_t)}")
    print(f"   Max time:      {format_time(max_t)}")
    print(f"   Std deviation: {format_time(std)}")
    
    print()
    
    # 5. Performance statistics
    print("5. Performance Statistics:")
    print("-" * 40)
    
    # Calculate operations per second
    ops_per_sec_proof = 1.0 / avg if avg > 0 else 0
    ops_per_sec_verify = 1.0 / avg_verify if avg_verify > 0 else 0
    
    print(f"   genZKProof:     {ops_per_sec_proof:.2f} operations/second")
    print(f"   VerifyZKProof:  {ops_per_sec_verify:.2f} operations/second")
    print(f"   Full cycle:     {1.0 / avg_cycle:.2f} operations/second" if 'avg_cycle' in locals() else "")
    
    print()
    print("=" * 80)
    
    return {
        'H3_point_only': avg_h3_point,
        'H3_point_string': avg_h3_point_str,
        'H3_four_points': avg_h3_four,
        'mod_inverse': avg_mod_inv,
        'genZKproof': avg_proof,
        'VerifyZKProof': avg_verify,
        'full_cycle': avg_cycle if 'avg_cycle' in locals() else None
    }

def main():
    """Main function with timing analysis"""
    zk = ZKProofSystem()
    
    # First, demonstrate that it works
    print("DEMONSTRATION: Basic functionality test")
    print("=" * 50)
    
    m0 = "Transaction 1: Alice pays Bob 5 BTC"
    m1 = "Transaction 2: Carol pays Dave 3 BTC"
    
    x0 = secrets.randbelow(zk.q - 1) + 1
    x1 = secrets.randbelow(zk.q - 1) + 1
    
    print(f"Secret x0: {x0}")
    print(f"Secret x1: {x1}")
    print()
    
    # Generate and verify proof
    start_time = time.perf_counter()
    proof = zk.genZKproof(m0, m1, x0, x1)
    gen_time = time.perf_counter() - start_time
    
    start_time = time.perf_counter()
    is_valid = zk.VerifyZKProof(proof)
    verify_time = time.perf_counter() - start_time
    
    print(f"✓ Proof generated in {format_time(gen_time)}")
    print(f"✓ Verification result: {'Valid ✓' if is_valid else 'Invalid ✗'} (took {format_time(verify_time)})")
    
    r0, r1, _, _, y0, y1, tau, u, v = proof
    print("\nProof components:")
    print(f"  r0.x: {r0.x()}")
    print(f"  r1.x: {r1.x()}")
    print(f"  y0.x: {y0.x()}")
    print(f"  y1.x: {y1.x()}")
    print(f"  tau:  {tau}")
    print(f"  u:    {u}")
    print(f"  v:    {v}")
    
    # Test invalid proof
    print("\n--- Testing invalid proof ---")
    invalid_proof = list(proof)
    invalid_proof[6] = (invalid_proof[6] + 1) % zk.q  # Change tau
    invalid_proof = tuple(invalid_proof)
    
    is_valid = zk.VerifyZKProof(invalid_proof)
    print(f"Verification result for invalid proof: {'Valid ✓' if is_valid else 'Invalid ✗'}")
    
    print("\n" + "=" * 50)
    print()
    
    # Run comprehensive timing tests
    print("RUNNING PERFORMANCE TESTS")
    print("=" * 50)
    print()
    
    # Run with 100 repetitions
    results = run_timing_tests(repeats=100)
    
    # Additional analysis: test with different repeat counts
    print("\n6. Scaling Analysis:")
    print("-" * 40)
    
    for repeats in [10, 50, 100, 200]:
        print(f"\n   Testing with {repeats} repetitions:")
        zk_local = ZKProofSystem()
        m0_local = "Test message 0"
        m1_local = "Test message 1"
        x0_local = secrets.randbelow(zk_local.q - 1) + 1
        x1_local = secrets.randbelow(zk_local.q - 1) + 1
        proof_local = zk_local.genZKproof(m0_local, m1_local, x0_local, x1_local)
        
        avg, min_t, max_t, std, _ = time_function(
            zk_local.genZKproof, m0_local, m1_local, x0_local, x1_local, repeats=repeats
        )
        print(f"      genZKproof:  avg={format_time(avg)}, min={format_time(min_t)}, max={format_time(max_t)}")
        
        avg, min_t, max_t, std, _ = time_function(
            zk_local.VerifyZKProof, proof_local, repeats=repeats
        )
        print(f"      VerifyZKProof: avg={format_time(avg)}, min={format_time(min_t)}, max={format_time(max_t)}")
    
    print()
    print("=" * 80)
    print("Performance analysis complete!")

if __name__ == "__main__":
    main()