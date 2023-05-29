import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.fernet import Fernet, MultiFernet
from file import window_input, openFile, openFiles
from processing import split
from Keys import * 


# AES Encryption 
def AESencrypt(key, nonce):
    aad = b'authenticated but unencrypted'
    path = os.path.join(os.getcwd() + "/SplitFiles", "0.txt")
    f = open(path, "r")
    content = f.read()
    f.close()
    os.remove(path)
    content = content.encode('utf-8')
    encryptor = AESGCM(key)
    ciphertext = encryptor.encrypt(nonce, content, aad)
    # print(ciphertext)
    # print('-' * 30)
    f = open(os.path.join(os.getcwd() + "/EncryptedFiles" , "0.txt"), "wb")
    f.write(ciphertext)
    f.close()


# ChaChaPoly Encryption
def ChaChaPolyencrypt(key, nonce):
    path = os.path.join(os.getcwd() + "/SplitFiles" , "1.txt")
    f = open(path, 'r')
    data = f.read()
    f.close()
    os.remove(path)
    data = data.encode('utf-8')
    aad = b"authenticated but unencrypted data"
    encryptor = ChaCha20Poly1305(key)
    ciphertext = encryptor.encrypt(nonce, data, aad)
    # print(ciphertext)
    # print('-' * 100)
    f = open(os.path.join(os.getcwd() + "/EncryptedFiles" , "1.txt"), "wb")
    f.write(ciphertext)
    f.close()

# Fernet Encryption
def FernetEncrypt(key):
    path = os.path.join(os.getcwd() + "/SplitFiles", "2.txt")
    f = open(path, "r")
    content = f.read()
    f.close()
    os.remove(path)
    content = content.encode('utf-8')
    encryptor = Fernet(key)
    ciphertext = encryptor.encrypt(content)
    f = open(os.path.join(os.getcwd() + "/EncryptedFiles" , "2.txt"), "wb")
    f.write(ciphertext)
    f.close()
         
# MultiFernet Encryption
def MultiFernetEncrypt(key1, key2): 
    path = os.path.join(os.getcwd() + "/SplitFiles", "3.txt")
    f = open(path, "r")
    content = f.read()
    f.close()
    os.remove(path)
    content = content.encode('utf-8')
    k1 = Fernet(key1)
    k2 = Fernet(key2)
    encryptor = MultiFernet([k1, k2])
    ciphertext = encryptor.encrypt(content)
    f = open(os.path.join(os.getcwd() + "/EncryptedFiles" , "3.txt"), "wb")
    f.write(ciphertext)
    f.close()

# Generate Keys 
def generateKeys():
    f = open("EncryptedKeys.txt","w") 
    for key in key_list:
        f.write("{} \n".format(key))
        
def fernet_media(key, path):
    path = "C:\\Users\\HP\\Pictures\\Screenshots\\"+ path
    f = open(path, 'rb')
    content = f.read()
    f.close()
    encryptor = Fernet(key)
    cipher = encryptor.encrypt(content)
    f = open(os.path.join(os.getcwd() + "/EncryptedFiles", "media_encryption.txt"), "wb")
    f.write(cipher)
    f.close()
    
# def encryption_main():
#     path = openFile()
#     if(file_checker.is_media_file(path)):
#         fernet_media(FernetKey, path)
#     print("File encrypted successfully!")


        