import boto3
import json
import os 
from config import s3_config

def s3_upload():
    s3 = s3_config()
    path = os.path.join(os.getcwd() , "EncryptedFiles")
    bucket_name = 'testbucketdsce'
    for roots, dirs, files in os.walk(path):
        for file in files:
            local_file = os.path.join(roots, file)
            s3.upload_file(local_file, bucket_name, file)
            os.remove(local_file)
            print(f'Uploaded {file} to {bucket_name}!')
    

def s3_download():
    s3 = s3_config()
    bucket_name = 'testbucketdsce'
    
    #list all objects in bucket
    response = s3.list_objects_v2(Bucket=bucket_name)

    if 'Contents' in response: 
        for obj in response['Contents']:
            file_name = obj['Key']
            local_path = os.path.join(os.getcwd(), 'EncryptedFiles', file_name)
            print(local_path)
            
            
            s3.download_file(bucket_name, file_name, local_path)
            print(f'Downloaded {file_name} from {bucket_name} to local storage!')

            
            s3.delete_object(Bucket=bucket_name, Key=file_name)
            print(f'Deleted {file_name} from {bucket_name}!')
            
    else:
        print(f"Bucket {bucket_name} is empty!")

if __name__=='__main__':
    s3_upload()
    s3_download()
    print('Done!')
    
    
