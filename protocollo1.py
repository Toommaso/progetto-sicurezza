import hashlib
import secrets

# Protocollo 1:
# 1: B -> A : RB
# 2: A -> B : RA || H(RB || s)
# 3: B -> A : H(RA || s)

# Funzione hash (prende in input dati in byte, restituisce in output l'impronta in formato esadecimale)
def H(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# Classe base per simulare le 2 parti, con un nome e un segreto condiviso,
# una funzione per generare un nonce crittograficamente sicuro (in questo caso di 16 byte) grazie alla libreria secrets,
# una funzione che genera l'hash usato nel protocollo, che usa la funzione hash SHA-256 data dalla libreria hashlib
class Peer:
    def __init__(self, name, secret):
        self.name = name
        self.secret = secret  # segreto condiviso

    def generate_nonce(self):
        return secrets.token_bytes(16)

    def compute_response(self, nonce):
        return H(nonce + self.secret)

# Istanzio Alice e Bob, che condividono lo stesso secreto
shared_secret = b'segretoTraAliceEBob'
alice = Peer('Alice', shared_secret)
bob = Peer('Bob', shared_secret)

print("\n--- Identificazione mutua: Protocollo 1 ---\n")

# Step 1: B -> A : RB
RB = bob.generate_nonce()
print("1: Bob -> Alice : RB")
print(f"RB = {RB.hex()}\n")

# Step 2: A -> B : RA || H(RB || s)
RA = alice.generate_nonce()
H_RB_S = alice.compute_response(RB)
print("2: Alice -> Bob : RA || H(RB||s)")
print(f"RA = {RA.hex()}, H(RB||s) = {H_RB_S}\n")

# Bob verifica H(RB || s)
expected_H_RB = bob.compute_response(RB)
print(f"Verifica di Bob: H(RB||s) = {expected_H_RB}")
if H_RB_S == expected_H_RB:
    print("OK: Bob identifica Alice")
else:
    print("KO: Bob rifiuta Alice")

# Step 3: B -> A : H(RA || s)
H_RA = bob.compute_response(RA)
print("\n3: Bob -> Alice : H(RA||s)")
print(f"H(RA||s) = {H_RA}\n")

# Alice verifica H(RA || s)
expected_H_RA = alice.compute_response(RA)
print(f"Verifica di Alice: H(RA||s) = {expected_H_RA}")
if H_RA == expected_H_RA:
    print("OK: Alice identifica Bob")
else:
    print("KO: Alice rifiuta Bob")
