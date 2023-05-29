import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.fernet import Fernet, MultiFernet

def AESdecrypt(key, nonce): 
    aad = b'authenticated but unencrypted'
    f = open(os.path.join(os.getcwd() + "\\EncryptedFiles", "0.txt"), "rb")
    cipher = f.read()
    f.close()
    os.remove(os.path.join(os.getcwd() + "\\EncryptedFiles", "0.txt"))
    decryptor = AESGCM(key)
    plaintext = decryptor.decrypt(nonce, cipher, aad)
    f = open(os.path.join(os.getcwd() + "\\SplitFiles", "0.txt"), "w")
    f.write(plaintext.decode())
    f.close()    
    


def ChaChadecrypt(key, nonce):
    aad = b"authenticated but unencrypted data"
    f = open(os.path.join(os.getcwd()+ "\\EncryptedFiles", "1.txt"), "rb")
    cipher = f.read()
    f.close()
    os.remove(os.path.join(os.getcwd() + "\\EncryptedFiles", "1.txt"))
    decryptor = ChaCha20Poly1305(key)
    plaintext =decryptor.decrypt(nonce, cipher, aad)
    f = open(os.path.join(os.getcwd() + "\\SplitFiles", "1.txt"), "w")
    f.write(plaintext.decode())
    f.close()
    
    
def FernetDecrypt(key):
    f = open(os.path.join(os.getcwd() + "\\EncryptedFiles", "2.txt"), "rb")
    cipher = f.read()
    f.close()
    os.remove(os.path.join(os.getcwd() + "\\EncryptedFiles", "2.txt"))
    decryptor = Fernet(key) 
    plaintext = decryptor.decrypt(cipher) 
    f = open(os.path.join(os.getcwd() + "\\SplitFiles", "2.txt"), "w")
    f.write(plaintext.decode())
    f.close()  
    
def MultiFernetDecrypt(key1, key2):
    f = open(os.path.join(os.getcwd() + "\\EncryptedFiles", "3.txt"), "rb")
    cipher = f.read()
    f.close()
    os.remove(os.path.join(os.getcwd() + "\\EncryptedFiles", "3.txt"))
    k1 = Fernet(key1)
    k2 = Fernet(key2)
    decryptor = MultiFernet([k1, k2])
    plaintext = decryptor.decrypt(cipher)
    f = open(os.path.join(os.getcwd() + "\\SplitFiles", "3.txt"), "w")
    f.write(plaintext.decode())
    f.close()
    
def fernet_media_decrypt(key, extension):
    path = os.path.join(os.getcwd() + "\\EncryptedFiles", "media_encryption.txt")
    f = open(path, "rb")
    cipher = f.read()
    f.close()
    os.remove(path)
    decryptor = Fernet(key)
    plaintext = decryptor.decrypt(cipher)
    f = open("Output" + "." + extension, "wb")
    f.write(plaintext)
    f.close()
    
    
    

    
    