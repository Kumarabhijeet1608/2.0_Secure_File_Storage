from Keys import *
from processing import split, merge
from encrypt import *
from decrypt import *
from file_checker import *
from threads import *
import time 
import glob
from config import *
import streamlit as st
# from aws_config import * 

# Define session state variable
session_state = st.session_state

# Check if 'logged_in' key exists in session state
if 'logged_in' not in session_state:
    session_state['logged_in'] = False

def count_file(path):
    pattern  = path + "/*"
    file_paths = glob.glob(pattern)
    count = len(file_paths)
    print(count)
    return count


path = None


def main():
    if not session_state['logged_in']:
        username = st.text_input('Username')
        password = st.text_input('Password', type='password')
        if st.button('Login'):
            # Perform authentication logic
            if username == 'admin' and password == 'password':
                session_state['logged_in'] = True
                st.success('Login successful!')
            else:
                st.error('Invalid credentials!')
        return
    else:
        st.write("Select a file to encrypt")
        uploaded_file = st.file_uploader("Choose a file")
        st.write(uploaded_file)
        
        # if(button):
        #     path = openFile()
        if uploaded_file is not None:

            path = uploaded_file.name
            print(uploaded_file)
            #config(path)
            generateKeys()
            
            [checker, extension] = is_media_file(path)
            if(checker):
                fernet_media(FernetKey, path)
                time.sleep(5)
                # s3_upload()
            else:
                split(path)
                time.sleep(5)
                HybridCrypt()
                # s3_upload()

            button = st.button("Decrypt")
            if button:
                # s3_download()
                count = count_file(os.path.join(os.getcwd() , "EncryptedFiles"))
                if(count == 1):
                    fernet_media_decrypt(FernetKey, extension)
                else:
                    AESdecrypt(AESGCMKey, nonce_12)
                    ChaChadecrypt(ChaChaPolyKey, nonce_12)
                    FernetDecrypt(FernetKey)
                    MultiFernetDecrypt(MultiFernetK1, MultiFernetK2)
                    merge()
                st.write("Decrypted successfully!!")

                

            button_logout = st.button("Logout")
            if button_logout:
                session_state['logged_in'] = False
                st.success('Logged out successfully!')

        

main()
    
# from pymongo import MongoClient
# import streamlit as st
# import os
# import glob
# import time
# from Keys import *
# from processing import split, merge
# from encrypt import *
# from decrypt import *
# from file_checker import *

# # Define session state variable
# session_state = st.session_state

# # Check if 'logged_in' key exists in session state
# if 'logged_in' not in session_state:
#     session_state['logged_in'] = False

# def count_file(path):
#     pattern = path + "/*"
#     file_paths = glob.glob(pattern)
#     count = len(file_paths)
#     print(count)
#     return count

# def authenticate(username, password):
#     # Connect to MongoDB Atlas
#     client = MongoClient("mongodb+srv://root:secure123@cluster0.m99ursm.mongodb.net/?retryWrites=true&w=majority")

#     # Select the database and collection
#     db = client["Secure_File_Storage"]
#     collection = db["User_Auth"]



# # Schema is missing ....................................



#     # Query the database for the user
#     user = collection.find_one({'username': username, 'password': password})
#     return user is not None

# path = None

# def main():
#     if not session_state['logged_in']:
#         username = st.text_input('Username')
#         password = st.text_input('Password', type='password')
#         if st.button('Login'):
#             # Perform authentication logic
#             if authenticate(username, password):
#                 session_state['logged_in'] = True
#                 st.success('Login successful!')
#             else:
#                 st.error('Invalid credentials!')
#         return
#     else:
#         st.write("Select a file to encrypt")
#         uploaded_file = st.file_uploader("Choose a file")
#         st.write(uploaded_file)
        
#         if uploaded_file is not None:
#             path = uploaded_file.name
#             print(uploaded_file)
#             generateKeys()
            
#             [checker, extension] = is_media_file(path)
#             if checker:
#                 fernet_media(FernetKey, path)
#                 time.sleep(5)
#             else:
#                 split(path)
#                 time.sleep(5)
#                 HybridCrypt()

#             button = st.button("Decrypt")
#             if button:
#                 count = count_file(os.path.join(os.getcwd() , "EncryptedFiles"))
#                 if count == 1:
#                     fernet_media_decrypt(FernetKey, extension)
#                 else:
#                     AESdecrypt(AESGCMKey, nonce_12)
#                     ChaChadecrypt(ChaChaPolyKey, nonce_12)
#                     FernetDecrypt(FernetKey)
#                     MultiFernetDecrypt(MultiFernetK1, MultiFernetK2)
#                     merge()
#                 st.write("Decrypted successfully!!")

#             button_logout = st.button("Logout")
#             if button_logout:
#                 session_state['logged_in'] = False
#                 st.success('Logged out successfully!')

# main()
