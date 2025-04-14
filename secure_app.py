# Secure Data Vault with Full Authentication System 🛡️
import streamlit as st
import os
import json
import hashlib
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# -----------------------------
# File Constants
# -----------------------------
KEY_FILE = "secret.key"
DATA_FILE = "data_store.json"
USER_FILE = "users.json"

# -----------------------------
# Load or Create Master Key
# -----------------------------


def load_or_create_key():
    """
    Loads existing encryption key or creates a new one.
    This is used to persist encryption between sessions.
    """
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key

# -----------------------------
# Hash Password with SHA-256
# -----------------------------


def hash_password(password):
    """
    Converts the password to a secure hash using SHA-256.
    This is how user passwords are safely stored.
    """
    return hashlib.sha256(password.encode()).hexdigest()

# -----------------------------
# Derive Encryption Key from Passkey
# -----------------------------


def derive_key(passkey: str, salt: bytes) -> bytes:
    """
    Uses PBKDF2 to turn the passkey and salt into a secure encryption key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))


# -----------------------------
# Load User Data
# -----------------------------
if os.path.exists(USER_FILE):
    with open(USER_FILE, "r") as f:
        users = json.load(f)
else:
    users = {}

if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {}

# -----------------------------
# Save Functions
# -----------------------------


def save_users():
    with open(USER_FILE, "w") as f:
        json.dump(users, f)


def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f)


# -----------------------------
# Session State Initialization
# -----------------------------
if "username" not in st.session_state:
    st.session_state.username = None

# -----------------------------
# UI Setup and Navigation
# -----------------------------
st.set_page_config(page_title="🔐 User Vault", layout="centered")
st.title("🔐 Encrypted User Vault")

if st.session_state.username:
    menu = ["Home", "Store Data", "Retrieve Data", "Logout"]
else:
    menu = ["Login", "Register"]
choice = st.sidebar.selectbox("Navigation", menu)

# -----------------------------
# Registration Page
# -----------------------------
if choice == "Register":
    st.subheader("📝 Register New User")
    new_user = st.text_input("Choose a username")
    new_pass = st.text_input("Choose a password", type="password")

    if st.button("Register"):
        if new_user in users:
            st.error("❌ Username already exists.")
        elif new_user and new_pass:
            users[new_user] = hash_password(new_pass)
            save_users()
            st.success("✅ Registered successfully! Please login.")
        else:
            st.error("⚠️ Fill in both fields.")

    st.info("""
    👉 This section lets users register with a unique username and password.
    Passwords are safely hashed so even the app owner can't see them!
    """)

# -----------------------------
# Login Page
# -----------------------------
elif choice == "Login":
    st.subheader("🔐 User Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in users and users[username] == hash_password(password):
            st.session_state.username = username
            st.success(f"✅ Welcome, {username}!")
            st.rerun()
        else:
            st.error("❌ Invalid credentials.")

    st.info("""
    🔐 Users must log in before storing or viewing encrypted data.
    Passwords are matched using secure hashes.
    """)

# -----------------------------
# Logout Logic
# -----------------------------
elif choice == "Logout":
    st.session_state.username = None
    st.success("✅ Logged out successfully.")
    st.rerun()

    st.info("""
    🚪 This resets the session so you’re securely logged out.
    """)

# -----------------------------
# Home Page (Post Login)
# -----------------------------
elif choice == "Home" and st.session_state.username:
    st.subheader(f"🏠 Welcome, {st.session_state.username}")
    st.write("Store and retrieve encrypted data specific to your account.")
    st.info("""
    📁 Each user has their own vault. You need a passkey to lock/unlock your secret data.
    """)

# -----------------------------
# Store Data
# -----------------------------
elif choice == "Store Data" and st.session_state.username:
    st.subheader("📂 Store Encrypted Data")
    user_data = st.text_area("Enter data:", height=150)
    passkey = st.text_input("Passkey for this data:", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            salt = os.urandom(16)
            key = derive_key(passkey, salt)
            cipher = Fernet(key)
            encrypted = cipher.encrypt(user_data.encode()).decode()

            user_vault = stored_data.get(st.session_state.username, {})
            user_vault[encrypted] = base64.b64encode(salt).decode()
            stored_data[st.session_state.username] = user_vault
            save_data()

            st.success("✅ Data encrypted and saved!")
            st.text_area("Encrypted Text:", encrypted, height=100)
        else:
            st.error("⚠️ All fields are required.")

    st.info("""
    ✍️ Enter your data and create a **unique passkey** to encrypt it.
    Your data is locked with the passkey and cannot be decrypted without it.
    """)

# -----------------------------
# Retrieve Data
# -----------------------------
elif choice == "Retrieve Data" and st.session_state.username:
    st.subheader("🔍 Retrieve Your Data")
    encrypted_input = st.text_area("Paste your encrypted text:", height=100)
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        user_vault = stored_data.get(st.session_state.username, {})
        salt_b64 = user_vault.get(encrypted_input)

        if salt_b64:
            try:
                salt = base64.b64decode(salt_b64)
                key = derive_key(passkey, salt)
                cipher = Fernet(key)
                decrypted = cipher.decrypt(encrypted_input.encode()).decode()
                st.success("✅ Decryption successful!")
                st.code(decrypted)
            except InvalidToken:
                st.error("❌ Invalid passkey or data.")
        else:
            st.error("⚠️ Encrypted data not found for your account.")

    st.info("""
    🧪 Paste your encrypted message and enter the correct passkey to unlock it.
    If the passkey or encrypted text is wrong, decryption will fail.
    """)
