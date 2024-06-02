from Keys import *
from processing import split, merge
from encrypt import *
from decrypt import *
from file_checker import *
from threads import *
import time 
import glob
#from config import s3_config
import streamlit as st

from pymongo import MongoClient
from passlib.hash import pbkdf2_sha256


# from aws_config import * 


# Define session state variable
session_state = st.session_state

# Connect to MongoDB
client = MongoClient('mongodb+srv://root:secure123@cluster0.amicdwp.mongodb.net/?retryWrites=true&w=majority')
db = client['final_year_project']
users_collection = db['users']

#User_registeration
def register_user(username, password):
    # Check if username already exists
    if users_collection.find_one({'username': username}):
        return False, 'Username already exists'

    # Hash the password using PBKDF2
    hashed_password = pbkdf2_sha256.hash(password)

    # Create a new user document
    user = {'username': username, 'password': hashed_password}

    # Insert the user document into the collection
    users_collection.insert_one(user)
    return True, 'Registration successful'

def authenticate(username, password):
    # Query the database for the user
    user = users_collection.find_one({'username': username})

    # Verify the password
    if user and pbkdf2_sha256.verify(password, user['password']):
        return True
    return False

def register():
    st.title('Login Page')
    st.write('Please enter your credentials')

    # Registration
    st.subheader('Registration')
    reg_username = st.text_input('Registration - Username', key='reg_username')
    reg_password = st.text_input('Registration - Password', type='password', key='reg_password')
    if st.button('Register'):
        success, message = register_user(reg_username, reg_password)
        if success:
            st.success('Registration successful!')
            
        else:
            st.error(message)

    # Login
    st.subheader('Login')
    username = st.text_input('Login - Username', key='login_username')
    password = st.text_input('Login - Password', type='password', key='login_password')
    if st.button('Login'):
        if authenticate(username, password):
            st.success('Login successful!')
        else:
            st.error('Invalid credentials')

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
    register()
    st.write("Select a file to encrypt")
    uploaded_file = st.file_uploader("Choose a file")
    st.write(uploaded_file)
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