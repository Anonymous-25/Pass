# app_streamlit.py
import streamlit as st
import sqlite3
import bcrypt
import base64
import os
import secrets
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# --------------------------
# Utilities: encryption & key derivation
# --------------------------
def derive_key_from_password(password: str, salt: bytes, iterations: int = 390000) -> bytes:
    """
    Derive a 32-byte key for Fernet (urlsafe base64) using PBKDF2-HMAC-SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def generate_salt() -> bytes:
    return os.urandom(16)

def generate_api_token() -> str:
    return secrets.token_urlsafe(32)

# --------------------------
# DB setup
# --------------------------
DB_PATH = "vault_full.db"
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
c = conn.cursor()

# Users: username PRIMARY KEY, password_hash, salt, kdf_iterations, api_token, api_token_expiry
c.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash BLOB NOT NULL,
    salt BLOB NOT NULL,
    kdf_iterations INTEGER NOT NULL,
    api_token TEXT,
    api_token_expiry INTEGER
)
""")

# Vault: id, owner (username), site, site_username, password_blob (encrypted), notes, created_at, updated_at
c.execute("""
CREATE TABLE IF NOT EXISTS vault (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner TEXT NOT NULL,
    site TEXT NOT NULL,
    site_username TEXT NOT NULL,
    password_blob BLOB NOT NULL,
    notes TEXT,
    created_at INTEGER,
    updated_at INTEGER,
    FOREIGN KEY(owner) REFERENCES users(username)
)
""")
conn.commit()

# --------------------------
# Session helper
# --------------------------
if "user" not in st.session_state:
    st.session_state.user = None
if "fernet" not in st.session_state:
    st.session_state.fernet = None
if "api_token" not in st.session_state:
    st.session_state.api_token = None

# --------------------------
# Auth: register / login / logout
# --------------------------
def register_user(username: str, master_password: str) -> (bool, str):
    c.execute("SELECT username FROM users WHERE username=?", (username,))
    if c.fetchone():
        return False, "Username already exists."
    salt = generate_salt()
    iterations = 390000  # PBKDF2 iterations
    # Hash master password for authentication (bcrypt)
    pw_hash = bcrypt.hashpw(master_password.encode(), bcrypt.gensalt())
    # Save user with salt and iterations for key derivation
    c.execute("INSERT INTO users (username, password_hash, salt, kdf_iterations) VALUES (?, ?, ?, ?)",
              (username, pw_hash, salt, iterations))
    conn.commit()
    return True, "User created successfully."

def login_user(username: str, master_password: str) -> (bool, str):
    c.execute("SELECT password_hash, salt, kdf_iterations FROM users WHERE username=?", (username,))
    row = c.fetchone()
    if not row:
        return False, "User not found."
    pw_hash_db, salt, iterations = row
    if not bcrypt.checkpw(master_password.encode(), pw_hash_db):
        return False, "Invalid credentials."
    # Derive encryption key and set Fernet in session
    key = derive_key_from_password(master_password, salt, iterations)
    st.session_state.user = username
    st.session_state.fernet = Fernet(key)
    # create an API token for browser extension usage (short lived by default)
    token = generate_api_token()
    expiry = int(time.time()) + 3600  # 1 hour
    c.execute("UPDATE users SET api_token=?, api_token_expiry=? WHERE username=?", (token, expiry, username))
    conn.commit()
    st.session_state.api_token = token
    return True, "Logged in."

def logout_user():
    st.session_state.user = None
    st.session_state.fernet = None
    st.session_state.api_token = None

# --------------------------
# CRUD functions
# --------------------------
def add_entry(owner: str, site: str, site_username: str, password_plain: str, notes: str):
    enc = st.session_state.fernet.encrypt(password_plain.encode())
    ts = int(time.time())
    c.execute("INSERT INTO vault (owner, site, site_username, password_blob, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
              (owner, site, site_username, enc, notes, ts, ts))
    conn.commit()

def list_entries(owner: str):
    c.execute("SELECT id, site, site_username, password_blob, notes, created_at, updated_at FROM vault WHERE owner=?", (owner,))
    return c.fetchall()

def get_entry(owner: str, entry_id: int):
    c.execute("SELECT id, site, site_username, password_blob, notes, created_at, updated_at FROM vault WHERE owner=? AND id=?", (owner, entry_id))
    return c.fetchone()

def update_entry(owner: str, entry_id: int, site: str, site_username: str, password_plain: str, notes: str):
    enc = st.session_state.fernet.encrypt(password_plain.encode())
    ts = int(time.time())
    c.execute("UPDATE vault SET site=?, site_username=?, password_blob=?, notes=?, updated_at=? WHERE id=? AND owner=?",
              (site, site_username, enc, notes, ts, entry_id, owner))
    conn.commit()

def delete_entry(owner: str, entry_id: int):
    c.execute("DELETE FROM vault WHERE id=? AND owner=?", (entry_id, owner))
    conn.commit()

# --------------------------
# UI Pages
# --------------------------
def show_register():
    st.header("Create account")
    with st.form("register_form"):
        username = st.text_input("Username")
        master_password = st.text_input("Master password", type="password")
        confirm = st.text_input("Confirm password", type="password")
        submitted = st.form_submit_button("Register")
    if submitted:
        if not username or not master_password:
            st.error("Username and password required.")
            return
        if master_password != confirm:
            st.error("Passwords do not match.")
            return
        ok, msg = register_user(username, master_password)
        if ok:
            st.success(msg + " Please login.")
            st.session_state.page = "login"
        else:
            st.error(msg)

def show_login():
    st.header("Login")
    with st.form("login_form"):
        username = st.text_input("Username")
        master_password = st.text_input("Master password", type="password")
        submitted = st.form_submit_button("Login")
    if submitted:
        ok, msg = login_user(username, master_password)
        if ok:
            st.success(msg)
            st.session_state.page = "dashboard"
        else:
            st.error(msg)

def show_dashboard():
    st.title("🔐 Dashboard")
    st.write(f"Logged in as **{st.session_state.user}**")
    if st.button("Logout"):
        logout_user()
        st.session_state.page = "login"
        st.rerun()


    st.subheader("Add new credential")
    with st.form("add_form"):
        site = st.text_input("Website / Site")
        site_user = st.text_input("Site username / email")
        site_pw = st.text_input("Site password", type="password")
        notes = st.text_area("Notes (optional)")
        add_sub = st.form_submit_button("Save")
    if add_sub:
        if not site or not site_user or not site_pw:
            st.error("Site, site username and password required.")
        else:
            add_entry(st.session_state.user, site, site_user, site_pw, notes)
            st.success("Saved!")
            st.rerun()


    st.subheader("Stored credentials")
    rows = list_entries(st.session_state.user)
    if not rows:
        st.info("No credentials stored yet.")
    for row in rows:
        entry_id, site, site_username, password_blob, notes, created_at, updated_at = row
        pw_plain = st.session_state.fernet.decrypt(password_blob).decode()
        with st.expander(f"{site} — {site_username}"):
            st.write("**Password:**", pw_plain)
            st.write("**Notes:**", notes)
            col1, col2, col3 = st.columns([1,1,1])
            if col1.button("Edit", key=f"edit_{entry_id}"):
                st.session_state.editing = entry_id
                st.session_state.page = "edit"
                st.rerun()

            if col2.button("Copy", key=f"copy_{entry_id}"):
                st.write("Click to copy then paste in desired site:")
                st.code(pw_plain)
            if col3.button("Delete", key=f"del_{entry_id}"):
                delete_entry(st.session_state.user, entry_id)
                st.success("Deleted")
                st.rerun()


def show_edit():
    entry_id = st.session_state.get("editing")
    if not entry_id:
        st.error("No entry selected.")
        st.session_state.page = "dashboard"
        return
    row = get_entry(st.session_state.user, entry_id)
    if not row:
        st.error("Entry not found.")
        st.session_state.page = "dashboard"
        return
    _id, site, site_username, password_blob, notes, created_at, updated_at = row
    pw_plain = st.session_state.fernet.decrypt(password_blob).decode()

    st.header("Edit credential")
    with st.form("edit_form"):
        site_new = st.text_input("Site", value=site)
        site_user_new = st.text_input("Site username", value=site_username)
        pw_new = st.text_input("Password", value=pw_plain, type="password")
        notes_new = st.text_area("Notes", value=notes)
        submitted = st.form_submit_button("Save changes")
    if submitted:
        update_entry(st.session_state.user, entry_id, site_new, site_user_new, pw_new, notes_new)
        st.success("Updated.")
        st.session_state.page = "dashboard"
        st.rerun()


# --------------------------
# Router
# --------------------------
st.sidebar.title("Navigation")
if st.session_state.user:
    choice = st.sidebar.radio("Go to", ["dashboard", "logout"], index=0)
    if choice == "logout":
        if st.sidebar.button("Confirm Logout"):
            logout_user()
            st.session_state.page = "login"
            st.rerun()

        else:
            st.session_state.page = "dashboard"
else:
    choice = st.sidebar.radio("Menu", ["login", "register"], index=0)
    st.session_state.page = choice

page = st.session_state.get("page", None)
if st.session_state.user and page in (None, "dashboard"):
    st.session_state.page = "dashboard"
    show_dashboard()
elif page == "register":
    show_register()
elif page == "login":
    show_login()
elif page == "dashboard":
    if not st.session_state.user:
        st.error("Please login.")
    else:
        show_dashboard()
elif page == "edit":
    if not st.session_state.user:
        st.error("Please login.")
    else:
        show_edit()
else:
    st.write("Welcome — please pick Login or Register.")
