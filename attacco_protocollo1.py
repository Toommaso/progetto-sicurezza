import hashlib
import secrets

# Attacco di reflection al protocollo 1:
# Charlie apre due sessioni simultaneamente con Bob
# Nella prima sessione Bob invia la sua sfida RB a Charlie
# Nella seconda sessione Charlie invia RB a Bob come se fosse la propria sfida RA
# Nella seconda sessione Bob risponde a Charlie
# Infine Charlie usa la risposta di Bob nella prima sessione, identificandosi per Alice

# NOTA per i nomi dei nonce:
# RA_1 -> nonce della sfida di Alice (o Charlie che impersonifica Alice) nella prima sessione
# RB_1 -> nonce della sfida di Bob nella prima sessione
# RA_2 -> nonce della sfida di Alice (o Charlie che impersonifica Alice) nella seconda sessione
# RB_2 -> nonce della sfida di Bob nella seconda sessione

def H(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

class Peer:
    def __init__(self, name, secret):
        self.name = name
        self.secret = secret

    def generate_nonce(self):
        return secrets.token_bytes(16)

    def compute_response(self, nonce):
        return H(nonce + self.secret)

# Istanzio Bob e Charlie (attaccante) che NON condividono nessun segreto
shared_secret = b'segretoTraAliceEBob'
bob = Peer('Bob', shared_secret)
charlie = Peer('Charlie', b'qualunque')  # Charlie NON conosce il segreto tra Alice e Bob

print("\n--- Attacco di reflection al protocollo 1 ---\n")

# Sessione 1: Charlie riceve la sfida di Bob
RB_1 = bob.generate_nonce()
print("[Sessione 1] Bob -> Charlie : RB_1")
print(f"RB_1 = {RB_1.hex()}\n")

# Sessione 2: Charlie inoltra la stessa sfida RB_1 come se fosse propria
RA_2 = RB_1
print("[Sessione 2] Charlie -> Bob : RA_2=RB_1")
print(f"RA_2=RB_1 = {RA_2.hex()}\n")

# Bob risponde normalmente nella seconda sessione e calcola H(RA_2||s) = H(RB_1||s)
RB_2 = bob.generate_nonce()
H_RA2_S = bob.compute_response(RA_2)
print("[Sessione 2] Bob -> Charlie : RB_2 || H(RA_2||s)")
print(f"RB_2 = {RB_2.hex()}, H(RA_2||s) = {H_RA2_S}\n")

# Charlie usa la risposta di Bob nella prima sessione
RA_1 = RB_2
print("[Sessione 1] Charlie -> Bob : RA_1=RB_2 || H(RA_2||s)")
print(f"RA_1=RB_2 = {RA_1.hex()}, H(RA_2||s) = {H_RA2_S}\n")

# Bob verifica H(RA_2 || s) ricevuto e lo confronta con quello che si aspetta (risposta al nonce RB_1)
expected_H = bob.compute_response(RB_1)
print(f"Verifica di Bob: H(RB||s) = {expected_H}")
if H_RA2_S == expected_H:
    print("KO: Bob identifica Charlie come Alice (reflection riuscito)")
else:
    print("OK: Bob rifiuta Charlie")

