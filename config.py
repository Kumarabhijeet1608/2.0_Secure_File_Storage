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
        
def s3_config():
    aws_access_key_id = 'Put your access id'
    aws_secret_key = 'Put your Key'


    s3 = boto3.client('s3', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_key)
    print('Connected to AWS S3 Service!')

        
    response = s3.list_buckets()
    buckets = response['Buckets']
    for bucket in buckets: 
        print(f'Bucket Name: {bucket["Name"]}')
        print(f'Creation Date: {bucket["CreationDate"]}')
        print(f'------------------------')
        
    return s3
    
s3_config()        
        