import hashlib
import secrets

# Protocollo 2:
# 1: B -> A : RB
# 2: A -> B : RA || H(RA || RB || B || s)
# 3: B -> A : H(RA || RB || A || s)


def H(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

class Peer:
    def __init__(self, name, secret):
        self.name = name.encode()  # in questo protocollo il nome andrà inserito in un hash, lo uso come byte string per compatibilità con H
        self.secret = secret

    def generate_nonce(self):
        return secrets.token_bytes(16)

    # questo protocollo impone di usare entrambi i nonce + l'identificatore del destinatario
    def compute_response(self, RA, RB, other_id):
        # A -> B : H(RA || RB || B || s)   oppure   B -> A : H(RA || RB || A || s)
        return H(RA + RB + other_id + self.secret)

# Come prima istanzio Alice e Bob che condividono un segreto
shared_secret = b'segretoTraAliceEBob'
alice = Peer('Alice', shared_secret)
bob = Peer('Bob', shared_secret)

print("\n--- Identificazione mutua: Protocollo 2 ---\n")

# Step 1: B -> A : RB (come prima)
RB = bob.generate_nonce()
print("1: Bob -> Alice : RB")
print(f"RB = {RB.hex()}\n")

# Step 2: A -> B : RA || H(RA || RB || B || s)
RA = alice.generate_nonce()
response_AtoB = alice.compute_response(RA, RB, bob.name)
print("2: Alice -> Bob : RA || H(RA || RB || B || s)")
print(f"RA = {RA.hex()}, H(RA || RB || B || s) = {response_AtoB}\n")

# Bob verifica l'impronta ricevuta con quella aspettata
expected_fromA = bob.compute_response(RA, RB, bob.name)
print(f"Verifica di Bob:  H(RA || RB || B || s) = {expected_fromA}")
if response_AtoB == expected_fromA:
    print("OK: Bob identifica Alice")
else:
    print("KO: Bob rifiuta Alice")

# Step 3: B -> A : H(RA || RB || A || s)
response_BtoA = bob.compute_response(RA, RB, alice.name)
print("\n3: Bob -> Alice : H(RA || RB || A || s)")
print(f"H(RA || RB || A || s) = {response_BtoA}\n")

# Alice verifica l'impronta ricevuta con quella aspettata
expected_fromB = alice.compute_response(RA, RB, alice.name)
print(f"Verifica di Alice: H(RA || RB || A || s) = {expected_fromB}")
if response_BtoA == expected_fromB:
    print("OK: Alice identifica Bob")
else:
    print("KO: Alice rifiuta Bob")
