import unittest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.fernet import Fernet, MultiFernet
import os
from processing import split, merge
from encrypt import *
from decrypt import *


class KeyGeneration(unittest.TestCase):
    def setUp(self):
        self.FernetKey = Fernet.generate_key()
        self.AESGCMKey = AESGCM.generate_key(128)
        self.ChaChaPolyKey = ChaCha20Poly1305.generate_key()
        self.MultiFernetK1 = Fernet.generate_key()
        self.MultiFernetK2 = Fernet.generate_key()
        self.nonce_12 = os.urandom(12)
        
    def test_AES_Key_generation(self):
        # key = AESGCM.generate_key(128)
        expected_length = 16
        key_length = len(self.AESGCMKey)
        
        # ensure that key is of expected length
        self.assertEqual(key_length, expected_length)
        
        # ensure that key is in bytes type
        self.assertIsInstance(self.AESGCMKey, bytes)


    def test_ChaChaPoly_key_generation(self):
        expected_length = 32
        key_length = len(self.ChaChaPolyKey)
        
        # ensure that key is of expected length
        self.assertEqual(key_length, expected_length)
        
        # ensure that key is in bytes type
        self.assertIsInstance(self.ChaChaPolyKey, bytes)
        
        
    def test_Fernet_key_generation(self):
        expected_length = 44  # 32 bytes key + b64 encoding of 12 bytes
        
        key_length = len(self.FernetKey)
        
        # ensure that key is of expected length
        self.assertEqual(expected_length, key_length)
        # ensure that key is in bytes type
        self.assertIsInstance(self.FernetKey, bytes)
        
        
    def test_MultiFernet_key_generation(self):
        expected_length = 44
        length1 = len(self.MultiFernetK1)
        length2 = len(self.MultiFernetK2)
        
        #check that both keys are not equal
        self.assertNotEqual(self.MultiFernetK1, self.MultiFernetK2)

        #check that both the keys are of expected length 
        self.assertEqual(expected_length, length1)
        self.assertEqual(expected_length, length2)
        
        #check that both the keys are in bytes type
        self.assertIsInstance(self.MultiFernetK1, bytes)
        self.assertIsInstance(self.MultiFernetK2, bytes)

        
    def test_nonce_generation(self):
        nonce1 = os.urandom(12)
        nonce2 = os.urandom(12)
        # test for uniqueness of nonce
        self.assertNotEqual(nonce1, nonce2)
    
    
class FileTesting(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(os.getcwd() , 'test.txt')

    def test_split(self):
        split(self.path)
        files = os.listdir(os.path.join(os.getcwd(), './SplitFiles'))
        
        # check that the file is split into 4 parts
        self.assertEqual(len(files), 4)
        for file in files:
            os.remove(os.path.join(os.getcwd(), './SplitFiles', file))
        
    # @unittest.skip("Skipping merge test")
    def test_merge(self):
        split(self.path)
        merge()
        f = open(os.path.join(os.getcwd(),'Output.txt'), "r")
        merged_file = f.read()
        f.close()
        
        with open(self.path, "r") as f:
            original_file = f.read()
            
        # check that the merged file is same as original file
        self.assertEqual(merged_file, original_file)
        os.remove(os.path.join(os.getcwd(),'Output.txt'))            

class CryptographyTesting(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(os.getcwd() , 'test.txt')
        self.FernetKey = Fernet.generate_key()
        self.AESGCMKey = AESGCM.generate_key(128)
        self.ChaChaPolyKey = ChaCha20Poly1305.generate_key()
        self.MultiFernetK1 = Fernet.generate_key()
        self.MultiFernetK2 = Fernet.generate_key()
        self.nonce_12 = os.urandom(12)
        split(self.path)
        
    def test_AES_encryption(self):
        with open(os.path.join(os.getcwd(), './SplitFiles', '0.txt')) as f:
            original_content = f.read()
        
        AESencrypt(self.AESGCMKey, self.nonce_12)
        AESdecrypt(self.AESGCMKey, self.nonce_12)
        
        with open(os.path.join(os.getcwd(), './SplitFiles', '0.txt')) as f:
            decrypted_content = f.read()
        
        # test if original split file and decrypted file are same
        self.assertEqual(original_content, decrypted_content)
    
    def test_ChaChaPoly1305_encryption(self):
        with open(os.path.join(os.getcwd(), './SplitFiles' , '1.txt' ), 'r') as f:
            original_content = f.read()
        
        ChaChaPolyencrypt(self.ChaChaPolyKey, self.nonce_12)
        ChaChadecrypt(self.ChaChaPolyKey, self.nonce_12)
        
        with open(os.path.join(os.getcwd() ,'./SplitFiles' , '1.txt' ), 'r') as f:
            decrypted_content = f.read()
            
        self.assertEqual(original_content, decrypted_content)
    
    
    def test_Fernet_encryption(self):
        with open(os.path.join(os.getcwd() , './SplitFiles'  ,'2.txt'), 'r') as f:
            original_content = f.read()
        
        FernetEncrypt(self.FernetKey)
        FernetDecrypt(self.FernetKey)
        
        with open(os.path.join(os.getcwd() , './SplitFiles' , '2.txt'), 'r') as f:
            decrypted_content = f.read()
            
        self.assertEqual(original_content, decrypted_content)
    
    def test_MultiFernet_encryption(self):
        with open(os.path.join(os.getcwd() , './SplitFiles' , '3.txt'), 'r') as f:
            original_content = f.read()
        
        MultiFernetEncrypt(self.MultiFernetK1, self.MultiFernetK2)
        MultiFernetDecrypt(self.MultiFernetK1, self.MultiFernetK2)

        with open(os.path.join(os.getcwd() , './SplitFiles' , '3.txt'), 'r') as f:
            decrypted_content = f.read()
        
        self.assertEqual(original_content, decrypted_content)
    

# def file_testing():
#     suite = unittest.TestSuite()
#     suite.addTest(FileTesting('test_split'))
#     suite.addTest(FileTesting('test_merge'))
#     return suite

if __name__=='__main__':

    unittest.main()
    