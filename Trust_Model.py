"""
P3: Trust Model & Novel Query Logic (the "Verification" layer).

Implements the trust verification model from:
  - README: "Lattice-Based Forward Secure IBE with Trust-Based Verification"
  - Paper: "A lattice-based forward secure IBE scheme for Internet of things"
  - Modification: "Novel Approach: Secure query-based trust model"

Implements:
  - Post-quantum signature interface (DilithiumStub; replace with Dilithium-3 for full compliance).
  - TrustDatabase logic: TrustManager with UserID -> Score, CheckTrust(Score >= 0), reward/penalize.
  - Query structure: Q = { EncryptedKeyword, Signature, Epoch_ID }.
  - Query validation: trust check, then verify signature; penalize on bad signature, reward on success.
  - Match logic: compare User Query vs. stored data tags (epoch, optional keyword).
"""
import hashlib
from dataclasses import dataclass
import LatticeCrypto as P1


# --------------------------------------------
# Post-Quantum Signatures (README: Dilithium-3)
# --------------------------------------------
# README requires: "Integrate Dilithium-3 (NIST Security Level 3)",
# "Sign(message, user_priv_key)", "Verify(message, signature, user_pub_key)".
# This stub uses SHA256 for prototyping; for full compliance use a Dilithium-3
# library (e.g. PyPQ/pydilithium or NIST reference bindings).

class DilithiumStub:
    def pk_from_sk(self, sk: bytes) -> bytes:
        return hashlib.sha256(sk).digest()

    def sign(self, msg: bytes, sk: bytes) -> bytes:
        return hashlib.sha256(msg + self.pk_from_sk(sk)).digest()

    def verify(self, msg: bytes, sig: bytes, pk: bytes) -> bool:
        return hashlib.sha256(msg + pk).digest() == sig


# --------------------------------------------
# Trust Manager (README: TrustDatabase, CheckTrust)
# --------------------------------------------
# README: "Create a TrustDatabase (Key-Value store: UserID -> Score)."
# "CheckTrust(UserID): Returns True if Score >= 0, else False."
# "Implement logic to decrease score on malicious attempts (e.g., bad signature)."

class TrustManager:
    def __init__(self):
        self.db = {}

    def check(self, uid):
        """README: CheckTrust(UserID). Returns True if Score >= 0, else False."""
        return self.db.get(uid, 0) >= 0

    CheckTrust = check  # README naming

    def reward(self, uid):
        self.db[uid] = min(self.db.get(uid, 0) + 1, 10)

    def penalize(self, uid):
        self.db[uid] = self.db.get(uid, 0) - 1


# --------------------------------------------
# Query + Validator (README: Q = { EncryptedKeyword, Signature, Epoch_ID })
# --------------------------------------------

@dataclass
class Query:
    """Query structure per README: Q = { EncryptedKeyword, Signature, Epoch_ID }."""
    encrypted_keyword: bytes
    signature: bytes
    epoch: int


class QueryValidator:
    def __init__(self, tm, signer, params):
        self.tm = tm
        self.signer = signer
        self.params = params

    def validate(self, user_id, q, pk):
        if not self.tm.check(user_id):
            return False
        msg = self.serialize(user_id, q)
        if not self.signer.verify(msg, q.signature, pk):
            self.tm.penalize(user_id)
            return False
        self.tm.reward(user_id)
        return True

    def serialize(self, uid, q):
        u = P1.G_vector(uid, self.params)
        return b"P3|" + u.tobytes() + q.encrypted_keyword + q.epoch.to_bytes(8, "big")


# --------------------------------------------
# Match Logic (README: Compare User Query vs. Stored Data tags)
# --------------------------------------------
# README P3: "Implement the Match Logic: Compare User Query vs. Stored Data tags."
# encrypted_data: list of dicts with at least "epoch"; optionally same structure as ciphertexts
# (e.g. {"epoch": t, "c1": ..., "c2": ...}). Returns list of indices of matching items.

def match_query_to_data(query: Query, encrypted_data: list) -> list:
    """Compare user query to stored data tags (epoch, optional keyword). Returns indices of matches."""
    indices = []
    for i, item in enumerate(encrypted_data):
        if item.get("epoch") != query.epoch:
            continue
        # Optional: compare encrypted_keyword to item tag if present
        if "tag" in item and item["tag"] != query.encrypted_keyword:
            continue
        indices.append(i)
    return indices


# --------------------------------------------
# Unit Test
# --------------------------------------------

if __name__ == "__main__":
    params = P1.LatticeParams(n=64)
    tm = TrustManager()
    sig = DilithiumStub()

    sk = b"secret"
    pk = sig.pk_from_sk(sk)

    q = Query(b"kw", b"", 0)
    msg = b"P3|" + P1.G_vector("Alice", params).tobytes() + b"kw" + (0).to_bytes(8, "big")
    q.signature = sig.sign(msg, sk)

    v = QueryValidator(tm, sig, params)
    assert v.validate("Alice", q, pk)
    assert tm.CheckTrust("Alice")  # README: CheckTrust(UserID)
    # Match logic: query vs stored data (list of dicts with "epoch")
    encrypted_data = [{"epoch": 0, "c1": None, "c2": None}, {"epoch": 1}]
    assert match_query_to_data(q, encrypted_data) == [0]
    assert match_query_to_data(Query(b"x", b"", 1), encrypted_data) == [1]
    print("[P3] Trust Model (Sign/Verify, CheckTrust, Match): PASS", flush=True)
