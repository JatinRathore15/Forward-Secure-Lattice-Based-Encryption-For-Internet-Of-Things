# ============================================
# LatticeCrypto.py
# P1: Lattice Infrastructure & Key Generation
# ============================================

import numpy as np
import hashlib
from math import ceil, log2

# --------------------------------------------
# Parameters
# --------------------------------------------

class LatticeParams:
    def __init__(self, n=16, q=3329, sigma=3.2):
        self.n = n                  # lattice dimension
        self.q = q                  # modulus
        self.k = ceil(log2(q))      # gadget width
        self.m = n * self.k         # lattice width
        self.sigma = sigma          # Gaussian stddev


# --------------------------------------------
# Gadget Matrix (Micciancio–Peikert)
# --------------------------------------------

def gadget_matrix(n, q):
    k = ceil(log2(q))
    G = np.zeros((n, n * k), dtype=int)
    for i in range(n):
        for j in range(k):
            G[i, i * k + j] = 1 << j
    return G % q


def bit_decompose(vec, q):
    """
    Gadget inversion G^{-1}
    """
    k = ceil(log2(q))
    bits = []
    for v in vec % q:
        for i in range(k):
            bits.append((v >> i) & 1)
    return np.array(bits, dtype=int)


# --------------------------------------------
# Trapdoor Generation (MP-style)
# --------------------------------------------

def TrapGen(params):
    """
    Outputs:
      A  ∈ Z_q^{n × 2m}
      T_A ∈ Z^{2m × m}   (trapdoor)
    """
    n, q, m = params.n, params.q, params.m

    A_bar = np.random.randint(0, q, size=(n, m))
    G = gadget_matrix(n, q)

    A = np.hstack([A_bar, G]) % q

    # Structured trapdoor for gadget part
    T_A = np.vstack([
        np.zeros((m, m), dtype=int),
        np.eye(m, dtype=int)
    ])

    return A, T_A


# --------------------------------------------
# Discrete Gaussian Sampler (Prototype-safe)
# --------------------------------------------

def discrete_gaussian(shape, sigma):
    return np.round(
        np.random.normal(0, sigma, size=shape)
    ).astype(int)


# --------------------------------------------
# SamplePre (CORE PRIMITIVE)
# --------------------------------------------

def SamplePre(A, T_A, u, params):
    """
    Toy-correct SamplePre
    Guarantees A·e = u (mod q)
    Pedagogical but algebraically valid
    """
    q = params.q
    n, m2 = A.shape
    m = m2 // 2

    # Split A = [A_bar | G]
    A_bar = A[:, :m]
    G = A[:, m:]

    # Gadget inversion (G·y = u mod q)
    y = bit_decompose(u, q)        # y ∈ Z^m

    # Construct preimage explicitly
    e = np.zeros(2 * m, dtype=int)
    e[m:] = y                     # only gadget part used

    # This GUARANTEES:
    # A @ e = G @ y = u mod q
    return e % q



# --------------------------------------------
# Hash Functions
# --------------------------------------------

def H_matrix(data, params):
    """
    H : {0,1}* → Z_q^{n×m}
    """
    digest = hashlib.sha256(data.encode()).digest()
    np.random.seed(int.from_bytes(digest[:4], 'big'))
    return np.random.randint(
        0, params.q,
        size=(params.n, params.m)
    )


def G_vector(data, params):
    """
    G : {0,1}* → Z_q^n
    Safe integer conversion (no uint8 overflow)
    Expands hash output for n > 32 using key derivation
    """
    # Use key derivation to get enough bytes for large n
    vec = []
    counter = 0
    while len(vec) < params.n:
        # Hash data with counter to get more bytes
        h = hashlib.sha256((data + str(counter)).encode()).digest()
        vec.extend([h[i] for i in range(min(32, params.n - len(vec)))])
        counter += 1
    
    return np.array(vec[:params.n], dtype=int) % params.q



# --------------------------------------------
# Binary Tree for Time Epochs
# --------------------------------------------

class BinaryTreeNode:
    def __init__(self, label):
        self.label = label
        self.left = None
        self.right = None


class BinaryTree:
    def __init__(self, depth):
        self.depth = depth
        self.root = self._build(0, 2**depth - 1)

    def _build(self, l, r):
        if l > r:
            return None
        mid = (l + r) // 2
        node = BinaryTreeNode(mid)
        node.left = self._build(l, mid - 1)
        node.right = self._build(mid + 1, r)
        return node


# --------------------------------------------
# Setup & Key Generation
# --------------------------------------------

def Setup(tree_depth=4, params=None):
    """
    Outputs public params and master secret key
    """
    if params is None:
        params = LatticeParams()

    A, T_A = TrapGen(params)

    return {
        "params": params,
        "A": A,
        "T_A": T_A,
        "tree": BinaryTree(tree_depth)
    }


def KeyGen(system, user_id):
    """
    Outputs initial secret key sk_{id,0}
    """
    params = system["params"]
    A = system["A"]
    T_A = system["T_A"]

    u = G_vector(user_id, params)
    sk = SamplePre(A, T_A, u, params)

    return sk


# --------------------------------------------
# Main Demo
# --------------------------------------------

if __name__ == "__main__":
    import time
    
    # Test with paper's recommended parameters
    test_params = [
        ("PARA.512", 512, 3329),
        ("PARA.768", 768, 3329),
        ("PARA.1024", 1024, 3329)
    ]
    
    print("=" * 70)
    print("Testing with Research Paper Parameters (Table 1)")
    print("=" * 70)
    print()
    
    for param_name, n, q in test_params:
        print(f"\n{'='*70}")
        print(f"Testing: {param_name} (n={n}, q={q})")
        print(f"{'='*70}\n")
        
        try:
            start_time = time.time()
            
            # Initialize system with paper parameters
            params = LatticeParams(n=n, q=q, sigma=3.2)
            system = Setup(tree_depth=4, params=params)
            
            setup_time = time.time() - start_time
            
            print(f"1. System Setup (took {setup_time:.4f} seconds)")
            print(f"   Lattice dimension (n): {params.n}")
            print(f"   Modulus (q): {params.q}")
            print(f"   Gaussian stddev (sigma): {params.sigma}")
            print(f"   Gadget width (k): {params.k}")
            print(f"   Lattice width (m): {params.m}")
            print(f"   Matrix A shape: {system['A'].shape}")
            print(f"   Trapdoor T_A shape: {system['T_A'].shape}")
            print()
            
            # Generate keys
            keygen_start = time.time()
            user_id = "Alice"
            sk = KeyGen(system, user_id)
            keygen_time = time.time() - keygen_start
            
            print(f"2. Key Generation (took {keygen_time:.4f} seconds)")
            print(f"   User ID: {user_id}")
            print(f"   Secret key shape: {sk.shape}")
            print(f"   Secret key (first 10 elements): {sk[:10]}")
            print(f"   Secret key (last 10 elements): {sk[-10:]}")
            print()
            
            # Verify the key property
            verify_start = time.time()
            u = G_vector(user_id, params)
            result = (system["A"] @ sk) % params.q
            verify_time = time.time() - verify_start
            
            print(f"3. Verification (took {verify_time:.4f} seconds)")
            print(f"   Target vector u shape: {u.shape}")
            print(f"   Target vector u (first 10): {u[:10]}")
            print(f"   Computed A @ sk (first 10): {result[:10]}")
            verification_passed = np.array_equal(result, u)
            print(f"   Verification: {'PASS' if verification_passed else 'FAIL'}")
            print()
            
            total_time = time.time() - start_time
            print(f"Total execution time: {total_time:.4f} seconds")
            
            if not verification_passed:
                print("   WARNING: Verification failed!")
                
        except MemoryError:
            print(f"   ERROR: Out of memory for n={n}")
            print("   This parameter set requires too much memory.")
        except Exception as e:
            print(f"   ERROR: {type(e).__name__}: {str(e)}")
    
    print("\n" + "=" * 70)
    print("All parameter tests completed!")
    print("=" * 70)