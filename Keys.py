import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.fernet import Fernet

AESGCMKey = AESGCM.generate_key(bit_length=128)
ChaChaPolyKey = ChaCha20Poly1305.generate_key()
FernetKey = Fernet.generate_key()
MultiFernetK1 = Fernet.generate_key()
MultiFernetK2 = Fernet.generate_key()
nonce_12 = os.urandom(12)
key_list = [AESGCMKey, ChaChaPolyKey, FernetKey, MultiFernetK1, MultiFernetK2, nonce_12]