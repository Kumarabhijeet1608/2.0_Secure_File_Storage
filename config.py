import os


def config(path):
    encrypted_folder = os.path.join(path, "EncryptedFiles") 
    split_folder = os.path.join(path, "SplitFiles")
    if not os.path.exists(encrypted_folder):
        os.makedirs(encrypted_folder)
        print(f'Created Encrypted Folder!')
    
    if not os.path.exists(split_folder):
        os.makedirs(split_folder)
        print(f'Created Split Folder!')
    
    print(f'Configuration Complete!')
        
        
        