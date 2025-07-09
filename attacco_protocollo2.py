import hashlib
import secrets

# Attacco di reflection al protocollo 2:
# Charlie apre due sessioni simultaneamente con Bob
# Nella prima sessione Bob invia la sua sfida RB a Charlie
# Nella seconda sessione Charlie invia RB a Bob come se fosse la propria sfida RA
# Nella seconda sessione Bob risponde a Charlie
# Infine Charlie usa la risposta di Bob nella prima sessione, identificandosi per Alice
# DIFFERENZA FONDAMENTALE: ora le due impronte saranno differenti, grazie all'asimmetria dei messaggi (l'identificatore della destinazione sarà diverso)

def H(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

class Peer:
    def __init__(self, name, secret):
        self.name = name.encode()
        self.secret = secret

    def generate_nonce(self):
        return secrets.token_bytes(16)

    def compute_response(self, RA, RB, other_id):
        return H(RA + RB + other_id + self.secret)

# Instanzio Bob, Charlie e anche Alice (serve perché è necessario l'identificatore in questo protocollo)
shared_secret = b'segretoTraAliceEBob'
alice = Peer('Alice', shared_secret)
bob = Peer('Bob', shared_secret)
charlie = Peer('Charlie', b'qualunque')  # Charlie non conosce il segreto

print("\n--- Attacco di reflection al protocollo 2 ---\n")

# Sessione 1: Charlie riceve la sfida di Bob
RB_1 = bob.generate_nonce()
print("[Sessione 1] Bob -> Charlie : RB_1")
print(f"RB_1 = {RB_1.hex()}\n")

# Sessione 2: Charlie inoltra la stessa sfida RB_1 come se fosse propria
RA_2 = RB_1
print("[Sessione 2] Charlie -> Bob : RA_2=RB_1")
print(f"RA_2=RB_1 = {RA_2.hex()}\n")

# Bob risponde normalmente nella seconda sessione, inserendo anche il nome di Alice
RB_2 = bob.generate_nonce()
H_msg = bob.compute_response(RA_2, RB_2, alice.name)
print("[Sessione 2] Bob -> Charlie : RB_2 || H(RA_2 || RB_2 || A || s)")
print(f"RB_2 = {RB_2.hex()}, H(RA_2 || RB_2 || A || s) = {H_msg}\n")

# Charlie usa la risposta di Bob nella prima sessione
RA_1 = RB_2
print("[Sessione 1] Charlie -> Bob : RA_1=RB_2 || H(RA || RB || A || s)")
print(f"RA_1=RB_2 = {RA_1.hex()}, H(RA || RB || A || s) = {H_msg}\n")

# Bob verifica il messaggio 2 ricevuto (con A come destinatario), pensando di essere lui il destinatario (B)
expected_message = bob.compute_response(RA_1, RB_1, bob.name)
print(f"Verifica di Bob: H(RA || RB || B || s) = {expected_message}")
if H_msg == expected_message:
    print("KO: Bob identifica Charlie come Alice: attacco riuscito")
else:
    print("OK: Attacco rilevato e fallito: Bob rifiuta Charlie")

