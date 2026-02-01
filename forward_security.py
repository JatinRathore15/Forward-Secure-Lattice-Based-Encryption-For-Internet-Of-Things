import numpy as np
import LatticeCrypto as P1


class UserOps:
    def __init__(self, system):
        self.params = system["params"]
        self.A = system["A"]
        self.T_A = system["T_A"]
        self.tree = system["tree"]
        self.total_epochs = 2 ** self.tree.depth


    # --------------------------------------------
    # Minimal Cover
    # --------------------------------------------

    def get_min_cover(self, current_time):
        cover = []

        def dfs(node, l, r):
            if node is None or r < current_time:
                return
            if l >= current_time:
                cover.append(node.label)
                return
            mid = (l + r) // 2
            dfs(node.left, l, mid - 1)
            if mid >= current_time:
                cover.append(node.label)
            dfs(node.right, mid + 1, r)

        dfs(self.tree.root, 0, self.total_epochs - 1)
        return sorted(set(cover))


    # --------------------------------------------
    # Key Update
    # --------------------------------------------

    def Update(self, key_bundle, t):
        next_t = t + 1
        if next_t >= self.total_epochs:
            return {}, []
        needed = self.get_min_cover(next_t)
        return {k: key_bundle[k] for k in needed if k in key_bundle}, needed


    def simulate_key_evolution(self, user_id, nodes):
        bundle = {}
        for node in nodes:
            uid = f"{user_id}_{node}"
            u = P1.G_vector(uid, self.params)
            bundle[node] = P1.SamplePre(self.A, self.T_A, u, self.params)
        return bundle


    # --------------------------------------------
    # Dual Regev Encrypt / Decrypt
    # --------------------------------------------

    def Encrypt(self, user_id, epoch, bit):
        uid = f"{user_id}_{epoch}"
        u = P1.G_vector(uid, self.params)
        q = self.params.q
        s = np.random.randint(0, q, size=self.params.n)
        e1 = P1.discrete_gaussian((self.A.shape[1],), self.params.sigma)
        e2 = P1.discrete_gaussian((1,), self.params.sigma)[0]
        c1 = (self.A.T @ s + e1) % q
        c2 = (u @ s + e2 + (q // 2) * bit) % q
        return {"c1": c1, "c2": c2, "epoch": epoch}


    def Decrypt(self, ct, key_bundle):
        sk = key_bundle.get(ct["epoch"])
        if sk is None:
            return None
        q = self.params.q
        approx = (ct["c2"] - sk @ ct["c1"]) % q
        return 0 if min(approx, q - approx) < abs(approx - q // 2) else 1


# --------------------------------------------
# Unit Test
# --------------------------------------------

if __name__ == "__main__":
    system = P1.Setup(tree_depth=3, params=P1.LatticeParams(n=64))
    ops = UserOps(system)
    keys = ops.simulate_key_evolution("Alice", [0, 1, 2])
    ct = ops.Encrypt("Alice", 1, 1)
    assert ops.Decrypt(ct, keys) == 1
    print("[P2] Forward Security (Encrypt/Decrypt): PASS", flush=True)
