import secrets
import json
from time import time
import os
import random

import subprocess
from zokrates_pycrypto.field import FQ, field_modulus
from zokrates_pycrypto.babyjubjub import Point, JUBJUB_L

# JUBJUB_L 2736030358979909402780800718157159386076813972158567259200215660948447373041
# field_modulus 21888242871839275222246405745257275088548364400416034343698204186575808495617
from Crypto.Hash import keccak
from Crypto.Util.number import getRandomRange, bytes_to_long, getRandomNBitInteger, inverse
# Compile C 2m1.000
# GenKey C 2m7.944
# Export C 0m0.032
# 1m28.646
# 1286497840 + 11406896
# 256 + 128 + 128
# 512 + 256 + 1152
# 63625128 + 40704
# 256
# 1024 + 3072
# 12 * 1024

# 1024 1536

# Compile D 0m1.311
# GenKey D 0m1.101
# Export D 0m0.016

Signature = tuple[Point, FQ]
Ciphertext = tuple[Point, Point] # 1024
VoteProof = tuple[list[int], list[int], list[Point], list[Point]] # 3072

def compute_witness(C: str, json):
  compute_witness_cmd = [
    "zokrates", "compute-witness",
    "-i", f"Circuit_{C}/out",
    "-s", f"Circuit_{C}/abi.json",
    "--abi",
    "--stdin"
  ]

  generate_proof_cmd = [
      "zokrates", "generate-proof",
      "-i", f"Circuit_{C}/out",
      "-s", "gm17",
      "-w", "witness",
      "-p", f"Circuit_{C}/proving.key"
  ]

  try:
    print("Running compute-witness...")
    subprocess.run(compute_witness_cmd, input=json.encode('utf-8'), check=True)
  except subprocess.CalledProcessError as e:
    print(f"Error in compute-witness: {e}")
  try:
      print("Running generate-proof...")
      subprocess.run(generate_proof_cmd, check=True)
  except subprocess.CalledProcessError as e:
      print(f"Error in generate-proof: {e}")

class Signer:
  def __init__(self):
    self.sk = FQ(getRandomRange(0, field_modulus))
    self.pk = Point.generator().mult(self.sk)

  @staticmethod
  def get_r(sk: FQ, m: FQ) -> FQ:
    r = keccak.new(digest_bits=256)
    r.update(
      keccak.new(digest_bits=256).update(sk.n.to_bytes(32)).digest()
    )
    r.update(m.n.to_bytes(32))
    return FQ(bytes_to_long(r.digest()))
  
  @staticmethod
  def get_h(R: Point, pk: Point, m: FQ) -> FQ:
    h = keccak.new(digest_bits=256)
    h.update(
      R.x.n.to_bytes(32) + R.y.n.to_bytes(32) 
      + pk.x.n.to_bytes(32) + pk.y.n.to_bytes(32)
      + m.n.to_bytes(32)
    )
    return FQ(bytes_to_long(h.digest()))

  @staticmethod
  def sign(m: FQ, sk: FQ) -> Signature:
    pk = Point.generator().mult(sk)

    r = Signer.get_r(sk, m)
    R = Point.generator().mult(r)
    h = Signer.get_h(R, pk, m)
    s = (r.n + sk.n * h.n) % JUBJUB_L
    return (R, FQ(s))
  
  @staticmethod
  def verify(m: FQ, pk: Point, sig: Signature) -> bool:
    R, s = sig

    h = Signer.get_h(R, pk, m)
    P1 = Point.generator().mult(s)
    P2 = R.add(pk.mult(h))

    return P1 == P2
  
  @staticmethod
  def encrypt(m: Point, pk: Point, r: FQ) -> Ciphertext:
    c1 = Point.generator().mult(r)
    c2 = m.add(pk.mult(r))

    return (c1, c2)
  
  @staticmethod
  def decrypt(sk: FQ, c: Ciphertext) -> Point:
    c1, c2 = c

    s = c1.mult(sk)
    m = c2.add(s.neg())

    return m

class IP:
  def __init__(self):
    self.storage = []
    self.signer = Signer()

  @staticmethod 
  def get_root_i(X_t: list[FQ], h_i: bytes) -> FQ:
    root_i = keccak.new(digest_bits=256)
    for x in X_t:
      root_i.update(x.n.to_bytes(16))
    
    root_i.update(h_i)

    return FQ(bytes_to_long(root_i.digest()))
  
  def register(self, X_t: list[FQ], h_i: bytes) -> Signature:
    t = time()
    # Store
    self.storage.append([
      Point.generator().mult(X_t[0]), 
      X_t
    ])

    root_i = IP.get_root_i(X_t, h_i)
    sig = Signer.sign(root_i, self.signer.sk)

    # print(time() - t)
    return sig

  def reconstruct(self, S: list[tuple[int, Point]]) -> list[int]:
    t = time()
    x, y = zip(*S)

    delta = []
    for i in range(len(S)):
      cur = 1
      for j in range(len(S)):
        if (j == i):
          continue
        cur = (cur * x[j]) * inverse(x[j] - x[i], JUBJUB_L) % JUBJUB_L
      delta.append(cur)
    s0 = Point.infinity()
    for y_i, delta_i in zip(y, delta):
      s0 = s0.add(y_i.mult(delta_i))
    
    x = None
    for i in range(len(self.storage)):
      if (s0 == self.storage[i][0]):
        x = self.storage[i][1]        
    
    print(time() - t)
    return x
    

class Validator:
  def __init__(self):
    self.signer = Signer()

class User:
  def __init__(self, k, n, ip: IP, validators, X_t: list[FQ]):
    self.k = k
    self.n = n
    self.ip = ip
    self.validators = validators
    self.security = 128
    self.X_t = X_t
    self.signer = Signer()

  def register(self):
    t = time()
    self.m_i = FQ(getRandomNBitInteger(128))
    self.h_i = keccak.new(digest_bits=256).update(self.m_i.n.to_bytes(16)).digest()

    self.e_i = Point.generator().mult(self.X_t[0])
    # print(time() - t)
    self.cert_i = self.ip.register(self.X_t, self.h_i)

  def authenticate(self):
    # t = time()
    self.r = FQ(getRandomNBitInteger(128))
    self.Pk_i_minus1 = [FQ(getRandomRange(0, JUBJUB_L)) for i in range(self.k - 1)]
    self.Q_t = [secrets.token_bytes(16) for _ in range(len(self.X_t))]

    self.hat_h_i = keccak.new(digest_bits=256).update((self.m_i.n + 1).to_bytes(16)).digest()
    self.S_n = User.shares_gen(self.Pk_i_minus1, self.e_i, self.n)
    self.C_n = [Signer.encrypt(s, v.signer.pk, self.r) for s, v in zip(self.S_n, self.validators)]
    self.y_t = [keccak.new(digest_bits=256).update(
      x.n.to_bytes(16) + q
    ).digest() for x, q in zip(self.X_t, self.Q_t)]

    self.json = (json.dumps([
      str(self.m_i.n), 
      str(self.r.n),
      [str(pk.n) for pk in self.Pk_i_minus1],
      [[f"0x{b:02x}" for b in q] for q in self.Q_t],
      [str(x.n) for x in self.X_t],
      [str(self.cert_i[0].x.n), str(self.cert_i[0].y.n), str(self.cert_i[1].n)],

      [f"0x{b:02x}" for b in self.hat_h_i],
      [str(self.ip.signer.pk.x.n), str(self.ip.signer.pk.y.n)],
      [[
        [str(cipher[0].x.n), str(cipher[0].y.n)], 
        [str(cipher[1].x.n), str(cipher[1].y.n)]
      ] for cipher in self.C_n],
      [[str(v.signer.pk.x.n), str(v.signer.pk.y.n)] for v in self.validators],
      [[f"0x{b:02x}" for b in y] for y in self.y_t]
    ]))

    """
    compute_witness("C", self.json)
    """

  def reveal_role(self):
    # t = time()
    keccak.new(digest_bits=256).update(
      self.X_t[-1].n.to_bytes(16) + self.Q_t[-1]
    ).digest()
    # print(time() - t)

  def provide(self, E: bytes) -> (Ciphertext, Signature):
    t = time()
    g_h_e = bytes_to_long(keccak.new(digest_bits=256).update(E).digest())
    E_g = Point.generator().mult(g_h_e)
    c = self.signer.encrypt(E_g, self.signer.pk, FQ(getRandomNBitInteger(128)))
    res = (c, self.signer.sign(FQ(g_h_e), self.signer.sk))
    print(len(E), time() - t)
    return res

  def upload(self, E: bytes, R_u: (Ciphertext, Signature)):
    t = time()
    E_g = self.signer.decrypt(self.signer.sk, R_u[0])
    ok = True
    g_h_e = bytes_to_long(keccak.new(digest_bits=256).update(E).digest())
    ok &= (E_g == Point.generator().mult(g_h_e))
    ok &= (self.signer.verify(FQ(g_h_e), self.signer.pk, R_u[1]))
    print(len(E), time() - t)
    return ok

  @staticmethod
  def shares_gen(Pk_i_minus1: list[FQ], s0: Point, n: int):
    S_n = [Point.infinity() for i in range(n)]
    Pk_point = [
      Point.generator().mult(x.n) for x in Pk_i_minus1
    ]

    for i in range(len(S_n)):
      for j in range(len(Pk_point)):
        S_n[i] = S_n[i].add(Pk_point[-j - 1])
        S_n[i] = S_n[i].mult(i + 1)
      
      S_n[i] = S_n[i].add(s0)

    return S_n


class Trial:
  def __init__(self):
    self.signer = Signer()
    n_candidate = 2
    self.M = [Point.generator().mult(getRandomRange(0, JUBJUB_L)) for _ in range(n_candidate)]
    self.ballot = []
    self.V = [0 for _ in range(n_candidate)]

  def vote(self, cp: int) -> tuple[Ciphertext, VoteProof]:
    self.V[cp] += 1
    t = time()
    r = getRandomRange(0, JUBJUB_L)
    c = self.signer.encrypt(self.M[cp], self.signer.pk, r)
    U = [getRandomRange(0, JUBJUB_L) for _ in range(len(self.M))]
    W = [getRandomRange(0, JUBJUB_L) for _ in range(len(self.M))]
    s = getRandomRange(0, JUBJUB_L)
    A = [Point.generator().mult(w).add(c[0].mult(u)) for (w, u) in zip(W, U)]
    A[cp] = Point.generator().mult(s)
    B = [self.signer.pk.mult(w).add((c[1].add(m.neg())).mult(u)) for (w, m, u) in zip(W, self.M, U)]
    B[cp] = self.signer.pk.mult(s)
    chall = keccak.new(digest_bits=256)
    for a in A:
      chall.update(a.x.n.to_bytes(32) + a.y.n.to_bytes(32))
    for b in B:
      chall.update(b.x.n.to_bytes(32) + b.y.n.to_bytes(32))
    chall = bytes_to_long(chall.digest())
    for i in range(len(self.M)):
      if (i != cp):
        chall -= U[i]
    U[cp] = chall % JUBJUB_L
    W[cp] = (s - U[cp] * r) % JUBJUB_L
    self.ballot.append(c)
    print(time() - t)
    return (c, (U, W, A, B))
  
  def open(self):
    t = time()
    c1, c2 = Point.infinity(), Point.infinity()
    for c in self.ballot:
      c1 = c1.add(c[0])
      c2 = c2.add(c[1])
    
    res = None
    C = (c1, c2)
    S = self.signer.decrypt(self.signer.sk, C)
    self.json = (json.dumps([
      str(self.signer.sk),
      [str(c1.x.n), str(c1.y.n)],
      [str(c2.x.n), str(c2.y.n)],
      [str(S.x.n), str(S.y.n)],
      [str(self.signer.pk.x), str(self.signer.pk.y)]
    ]))
    compute_witness("D", self.json)
    for i in range(len(self.ballot) + 1):
      if self.M[0].mult(i).add(self.M[1].mult(len(self.ballot) - i)) == S:
        print(i, self.V[0], self.V[1])
        res = (C, S, i, len(self.ballot) - i)

    print(time() - t)
    return res

  def verify(self, c: Ciphertext, pi: VoteProof) -> bool:
    t = time()
    U, W, A, B = pi
    ok = True
    for i in range(len(A)):
      w, u, m = W[i], U[i], self.M[i]
      ok &= (A[i] == Point.generator().mult(w).add(c[0].mult(u)))
      ok &= (B[i] == self.signer.pk.mult(w).add((c[1].add(m.neg())).mult(u)))
    chall = keccak.new(digest_bits=256)
    for a in A:
      chall.update(a.x.n.to_bytes(32) + a.y.n.to_bytes(32))
    for b in B:
      chall.update(b.x.n.to_bytes(32) + b.y.n.to_bytes(32))
    chall = bytes_to_long(chall.digest())
    ok &= ((chall - sum(U)) % JUBJUB_L == 0)
    print(time() - t)
    
    return ok

def test_auth():
  k = 6
  n = 10

  ip = IP()
  validators = [Validator() for _ in range(n)]
  user = User(k, n, ip, validators,
  [
    FQ(getRandomRange(0, 2 ** 128)),
    FQ(1)
  ])

  cert_i = user.register()
  user.authenticate()
  user.reveal_role()

def test_trial():
  trial = Trial()
  for i in range(12):
    c,pi = trial.vote(getRandomRange(0, 2))
    assert trial.verify(c, pi)
  print(trial.open())

def test_evidence():
  k = 6
  n = 10

  ip = IP()
  validators = [Validator() for _ in range(n)]
  user = User(k, n, ip, validators,
  [
    FQ(getRandomRange(0, 2 ** 128)),
    FQ(1)
  ])

  cert_i = user.register()
  user.authenticate()

  for i in range(100):
    E = os.urandom(1000000 * i)
    
    assert user.upload(E, user.provide(E))

def test_open_PIA():
  k = 6
  n = 10

  ip = IP()
  validators = [Validator() for _ in range(n)]
  user = User(k, n, ip, validators,
  [
    FQ(getRandomRange(0, 2 ** 128)),
    FQ(1)
  ])

  cert_i = user.register()
  user.authenticate()
  user.reveal_role()

  v = validators[0]
  c1, c2 = user.C_n[0]
  s = Signer.decrypt(v.signer.sk, (c1, c2))
  t = time()
  compute_witness("D", json.dumps([
      str(v.signer.sk),
      [str(c1.x.n), str(c1.y.n)],
      [str(c2.x.n), str(c2.y.n)],
      [str(s.x.n), str(s.y.n)],
      [str(v.signer.pk.x), str(v.signer.pk.y)]
    ]))
  print(time() - t)

  el = random.sample(range(n), k)
  S_k = [(i + 1, user.S_n[i]) for i in el]
  print(ip.reconstruct(S_k))

if __name__ == '__main__':
  test_open_PIA()

# zokrates compile -i circuit_c.zok --debug
# zokrates compute-witness --abi --stdin < pp.json
# time python3 PPChain.py > 

# zokrates compute-witness -i Circuit_C/out -s Circuit_C/abi.json --abi --stdin < Circuit_C/pp.json
# zokrates generate-proof -i Circuit_C/out -s gm17 -w witness -p Circuit_C/proving.key