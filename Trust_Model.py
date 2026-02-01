import hashlib
from dataclasses import dataclass
import LatticeCrypto as P1


# --------------------------------------------
# Signature Stub
# --------------------------------------------

class DilithiumStub:
    def pk_from_sk(self, sk: bytes) -> bytes:
        return hashlib.sha256(sk).digest()

    def sign(self, msg: bytes, sk: bytes) -> bytes:
        return hashlib.sha256(msg + self.pk_from_sk(sk)).digest()

    def verify(self, msg: bytes, sig: bytes, pk: bytes) -> bool:
        return hashlib.sha256(msg + pk).digest() == sig


# --------------------------------------------
# Trust Manager
# --------------------------------------------

class TrustManager:
    def __init__(self):
        self.db = {}

    def check(self, uid):
        return self.db.get(uid, 0) >= 0

    def reward(self, uid):
        self.db[uid] = min(self.db.get(uid, 0) + 1, 10)

    def penalize(self, uid):
        self.db[uid] = self.db.get(uid, 0) - 1


# --------------------------------------------
# Query + Validator
# --------------------------------------------

@dataclass
class Query:
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
    print("[P3] Trust Model (Sign/Verify): PASS", flush=True)
