import numpy as np
import hashlib
from math import ceil, log2


# --------------------------------------------
# Parameters
# --------------------------------------------

class LatticeParams:
    def __init__(self, n=16, q=3329, sigma=3.2):
        self.n = n
        self.q = q
        self.k = ceil(log2(q))
        self.m = n * self.k
        self.sigma = sigma


# --------------------------------------------
# Gadget Matrix
# --------------------------------------------

def gadget_matrix(n, q):
    k = ceil(log2(q))
    G = np.zeros((n, n * k), dtype=int)
    for i in range(n):
        for j in range(k):
            G[i, i * k + j] = 1 << j
    return G % q


def bit_decompose(vec, q):
    k = ceil(log2(q))
    bits = []
    for v in vec % q:
        for i in range(k):
            bits.append((v >> i) & 1)
    return np.array(bits, dtype=int)


# --------------------------------------------
# Trapdoor Generation (MP-style, pedagogical)
# --------------------------------------------

def TrapGen(params):
    n, q, m = params.n, params.q, params.m
    A_bar = np.random.randint(0, q, size=(n, m))
    G = gadget_matrix(n, q)
    A = np.hstack([A_bar, G]) % q
    T_A = np.vstack([np.zeros((m, m), dtype=int), np.eye(m, dtype=int)])
    return A, T_A


# --------------------------------------------
# Discrete Gaussian
# --------------------------------------------

def discrete_gaussian(shape, sigma):
    return np.round(np.random.normal(0, sigma, size=shape)).astype(int)


# --------------------------------------------
# SamplePre (A·e = u mod q)
# --------------------------------------------

def SamplePre(A, T_A, u, params):
    q = params.q
    _, m2 = A.shape
    m = m2 // 2
    y = bit_decompose(u, q)
    e = np.zeros(2 * m, dtype=int)
    e[m:] = y
    return e % q


# --------------------------------------------
# Hash → Lattice Vector
# --------------------------------------------

def G_vector(data, params):
    vec = []
    ctr = 0
    while len(vec) < params.n:
        h = hashlib.sha256((data + str(ctr)).encode()).digest()
        vec.extend(h[:min(32, params.n - len(vec))])
        ctr += 1
    return np.array(vec[:params.n], dtype=int) % params.q


# --------------------------------------------
# Binary Tree (Forward Security)
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
# Setup & KeyGen
# --------------------------------------------

def Setup(tree_depth=4, params=None):
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
    params = system["params"]
    u = G_vector(user_id, params)
    return SamplePre(system["A"], system["T_A"], u, params)


# --------------------------------------------
# Unit Test
# --------------------------------------------

if __name__ == "__main__":
    params = LatticeParams(n=64)
    system = Setup(tree_depth=3, params=params)
    sk = KeyGen(system, "Alice")
    u = G_vector("Alice", params)
    assert np.array_equal((system["A"] @ sk) % params.q, u)
    print("[P1] PASS")
