import threading
from encrypt import *
from decrypt import *
from Keys import *

def HybridCrypt():
    t1 = threading.Thread(target=AESencrypt, args=(AESGCMKey, nonce_12,))
    t2 = threading.Thread(target=ChaChaPolyencrypt, args=(ChaChaPolyKey, nonce_12,))
    t3 = threading.Thread(target=FernetEncrypt, args=(FernetKey,))
    t4 = threading.Thread(target=MultiFernetEncrypt, args=(MultiFernetK1, MultiFernetK2,))
    
    #Starting the process
    t1.start()
    t2.start()
    t3.start()
    t4.start()
    
    #Waiting for the process to end
    t1.join()
    t2.join()
    t3.join() 
    t4.join()
    
def HybridDecrypt(): 
    t1 = threading.Thread(target=AESdecrypt, args=(AESGCMKey, nonce_12,))
    t2 = threading.Thread(target=ChaChaPolyencrypt, args=(ChaChaPolyKey, nonce_12,))
    t3 = threading.Thread(target=FernetEncrypt, args=(FernetKey,))
    t4 = threading.Thread(target=MultiFernetDecrypt, args=(MultiFernetK1, MultiFernetK2,))
    
    #Starting the decryption process
    t1.start()
    t2.start()
    t3.start()
    t4.start()
    
    #Waiting for the decryption process to end
    t1.join()
    t2.join()
    t3.join()
    t4.join()

    
    
    