import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json
import os
import time
from datetime import datetime, timedelta

# Generate or load encryption key
def load_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
    return open("secret.key", "rb").read()

KEY = load_key()
cipher = Fernet(KEY)

# Data storage setup
def load_data():
    if os.path.exists("data.json"):
        with open("data.json", "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open("data.json", "w") as f:
        json.dump(data, f)

stored_data = load_data()

# Session state for tracking attempts
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = {}
if 'locked_until' not in st.session_state:
    st.session_state.locked_until = {}

# Security functions
def hash_passkey(passkey, salt=None):
    if salt is None:
        salt = os.urandom(16).hex()
    return hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000).hex(), salt

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    st.write("### Features:")
    st.write("- 🔐 Military-grade encryption (AES-128)")
    st.write("- 🔑 PBKDF2 key derivation with SHA-256")
    st.write("- ⏱️ Temporary lockout after 3 failed attempts")
    st.write("- 💾 Persistent storage in encrypted JSON file")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    data_id = st.text_input("Enter a unique identifier for your data:")
    user_data = st.text_area("Enter Data to Encrypt:")
    passkey = st.text_input("Enter Passkey:", type="password")
    confirm_passkey = st.text_input("Confirm Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if not data_id or not user_data or not passkey:
            st.error("⚠️ All fields are required!")
        elif passkey != confirm_passkey:
            st.error("⚠️ Passkeys don't match!")
        elif data_id in stored_data:
            st.error("⚠️ This identifier already exists!")
        else:
            hashed_passkey, salt = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            stored_data[data_id] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey,
                "salt": salt,
                "failed_attempts": 0,
                "locked_until": None
            }
            save_data(stored_data)
            st.success("✅ Data stored securely!")
            st.info(f"Your data ID: {data_id}")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    data_id = st.text_input("Enter your data identifier:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if not data_id or not passkey:
            st.error("⚠️ Both fields are required!")
        elif data_id not in stored_data:
            st.error("❌ Data identifier not found!")
        else:
            data = stored_data[data_id]
            
            # Check if locked
            if data.get('locked_until') and datetime.now() < datetime.strptime(data['locked_until'], '%Y-%m-%d %H:%M:%S'):
                remaining_time = datetime.strptime(data['locked_until'], '%Y-%m-%d %H:%M:%S') - datetime.now()
                st.error(f"🔒 Account locked. Try again in {remaining_time.seconds//60} minutes and {remaining_time.seconds%60} seconds.")
            else:
                # Verify passkey
                hashed_input, _ = hash_passkey(passkey, data['salt'])
                if hashed_input == data['passkey']:
                    decrypted_text = decrypt_data(data['encrypted_text'])
                    data['failed_attempts'] = 0
                    data['locked_until'] = None
                    save_data(stored_data)
                    st.success("✅ Decryption successful!")
                    st.text_area("Decrypted Data:", value=decrypted_text, height=200)
                else:
                    data['failed_attempts'] = data.get('failed_attempts', 0) + 1
                    if data['failed_attempts'] >= 3:
                        lockout_time = datetime.now() + timedelta(minutes=5)
                        data['locked_until'] = lockout_time.strftime('%Y-%m-%d %H:%M:%S')
                        st.error("🔒 Too many failed attempts! Account locked for 5 minutes.")
                    else:
                        st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - data['failed_attempts']}")
                    save_data(stored_data)

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    st.warning("You need to authenticate to continue after multiple failed attempts.")
    
    login_pass = st.text_input("Enter Admin Password:", type="password")
    
    if st.button("Authenticate"):
        # In a real system, use proper password hashing and storage
        # This is just for demonstration purposes
        if login_pass == "secureadmin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Authentication successful! You can now try again.")
            time.sleep(1)
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")