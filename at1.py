import os
import json
import base64
import hashlib
import hmac
import secrets
import re
from datetime import datetime
from getpass import getpass

USERS_FILE = "users.jsonl"
PII_FILE = "pii_store.jsonl"

# =============== VALIDATION FUNCTIONS ===============

def validate_name(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z\-' ]{2,100}", name.strip()):
        raise ValueError("Invalid name format.")
    return name.strip()

def validate_phone(phone: str) -> str:
    phone = re.sub(r"\s+", "", phone)
    if not re.fullmatch(r"\+?\d{7,15}", phone):
        raise ValueError("Invalid phone number.")
    return phone

def validate_tfn(tfn: str) -> str:
    tfn = re.sub(r"\D", "", tfn)
    if len(tfn) not in (8, 9):
        raise ValueError("Invalid TFN.")
    return tfn

def validate_credit_card(card: str) -> str:
    card = re.sub(r"\D", "", card)
    if not (12 <= len(card) <= 19):
        raise ValueError("Invalid card length.")
    digits = [int(d) for d in card]
    checksum = sum(
        (x if i % 2 else (x * 2 - 9 if x * 2 > 9 else x * 2))
        for i, x in enumerate(digits[::-1])
    )
    if checksum % 10 != 0:
        raise ValueError("Invalid credit card number.")
    return card

def sanitize_text(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())

# =============== USERNAME GENERATION ===============

def make_username_from_name(full_name: str) -> str:
    """
    Generate a username from first + last name.
    Example: 'Tate HK' -> 'tate.hk'
    """
    parts = full_name.strip().lower().split()
    if len(parts) < 2:
        raise ValueError("Full name must include at least first and last name.")
    first = re.sub(r"[^a-z0-9]", "", parts[0])
    last = re.sub(r"[^a-z0-9]", "", parts[-1])
    if not first or not last:
        raise ValueError("Name must contain alphabetic characters.")
    return f"{first}.{last}"

# =============== ENCRYPTION HELPERS (PII) ===============

def derive_keys(password: str, salt: bytes):
    """Derive two 32-byte keys from a password and salt using PBKDF2."""
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200_000, dklen=64)
    return key[:32], key[32:]

def stream_xor_encrypt(enc_key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < len(plaintext):
        block = hmac.new(enc_key, nonce + counter.to_bytes(4, 'big'),
                         hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(a ^ b for a, b in zip(plaintext, out[:len(plaintext)]))

def encrypt_bytes(plaintext: bytes, password: str) -> dict:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(8)
    enc_key, mac_key = derive_keys(password, salt)
    ciphertext = stream_xor_encrypt(enc_key, nonce, plaintext)
    mac = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    return {
        'salt': base64.b64encode(salt).decode(),
        'nonce': base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'mac': base64.b64encode(mac).decode(),
        'kdf': 'pbkdf2_sha256_200k'
    }

def decrypt_bytes(enc_obj: dict, password: str) -> bytes:
    salt = base64.b64decode(enc_obj['salt'])
    nonce = base64.b64decode(enc_obj['nonce'])
    ciphertext = base64.b64decode(enc_obj['ciphertext'])
    mac = base64.b64decode(enc_obj['mac'])
    enc_key, mac_key = derive_keys(password, salt)
    calc_mac = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, calc_mac):
        raise ValueError("Integrity check failed (wrong password or tampered data).")
    return stream_xor_encrypt(enc_key, nonce, ciphertext)

# =============== USER ACCOUNT HELPERS (LOGIN + ROLES) ===============

def hash_password(password: str, salt: bytes | None = None) -> dict:
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200_000, dklen=32)
    return {
        'salt': base64.b64encode(salt).decode(),
        'pw_hash': base64.b64encode(dk).decode(),
        'kdf': 'pbkdf2_sha256_200k'
    }

def verify_password(password: str, stored: dict) -> bool:
    salt = base64.b64decode(stored['salt'])
    expected = base64.b64decode(stored['pw_hash'])
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200_000, dklen=32)
    return hmac.compare_digest(dk, expected)

def load_users(filename: str) -> list[dict]:
    if not os.path.exists(filename):
        return []
    users = []
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                users.append(json.loads(line))
    return users

def save_user(filename: str, username: str, password: str, role: str):
    users = load_users(filename)
    for u in users:
        if u['username'] == username:
            raise ValueError("Username already exists.")
    record = {
        'username': username,
        'password': hash_password(password),
        'role': role
    }
    with open(filename, 'a', encoding='utf-8') as f:
        f.write(json.dumps(record) + '\n')

def find_user(filename: str, username: str) -> dict | None:
    users = load_users(filename)
    for u in users:
        if u['username'] == username:
            return u
    return None

def ensure_initial_admin():
    """If there is no admin user, force creation of one."""
    users = load_users(USERS_FILE)
    if any(u.get('role') == 'admin' for u in users):
        return
    print("\nNo admin accounts found. Create an initial admin account.")
    while True:
        username = input("Admin username: ").strip()
        if not username:
            print("Username cannot be empty.")
            continue
        pw = getpass("Admin password: ")
        pw2 = getpass("Confirm admin password: ")
        if pw != pw2:
            print("Passwords do not match, try again.")
            continue
        try:
            save_user(USERS_FILE, username, pw, "admin")
            print("Initial admin account created.")
            break
        except Exception as e:
            print("Error creating admin:", e)

def login() -> dict | None:
    print("\n=== Login ===")
    username = input("Username: ").strip()
    pw = getpass("Password: ")
    user = find_user(USERS_FILE, username)
    if not user:
        print("No such user.")
        return None
    if not verify_password(pw, user['password']):
        print("Incorrect password.")
        return None
    print(f"Login successful. Role: {user['role']}")
    return user

# =============== STORAGE HANDLER (PII) ===============

class PiiSecure:
    def __init__(self, filename: str, password: str):
        self.filename = filename
        self.password = password
        self.pii_fields = ["name", "phone", "tfn", "credit_card"]

    def encrypt_record_fields(self, record: dict) -> dict:
        out = {}
        for k, v in record.items():
            if k in self.pii_fields:
                out[k] = encrypt_bytes(v.encode(), self.password)
            else:
                out[k] = v
        out['_meta'] = {'encrypted_at': datetime.utcnow().isoformat() + 'Z'}
        return out

    def decrypt_record_fields(self, record: dict) -> dict:
        out = {}
        for k, v in record.items():
            if k in self.pii_fields:
                out[k] = decrypt_bytes(v, self.password).decode()
            else:
                out[k] = v
        return out

    def store(self, record: dict):
        enc = self.encrypt_record_fields(record)
        with open(self.filename, 'a', encoding='utf-8') as f:
            f.write(json.dumps(enc) + '\n')
        # redacted view
        redacted = {}
        for k, v in record.items():
            if k in self.pii_fields:
                redacted[k] = v[:-4].rjust(len(v), '*')
            else:
                redacted[k] = v
        return redacted

    def retrieve_all(self) -> list[dict]:
        records = []
        if not os.path.exists(self.filename):
            return records
        with open(self.filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                records.append(self.decrypt_record_fields(record))
        return records

    def overwrite_all(self, records: list[dict]):
        """Overwrite the file with these (plaintext) records, re-encrypting each."""
        with open(self.filename, 'w', encoding='utf-8') as f:
            for rec in records:
                enc = self.encrypt_record_fields(rec)
                f.write(json.dumps(enc) + '\n')

# =============== PII / USER OPERATIONS ===============

def admin_create_pii_and_user(ps: PiiSecure):
    """Admin/manager/employee: create PII + linked user (role 'user')."""
    try:
        print("\n=== Create new PII record and user account (role=user) ===")
        full_name = input("Enter full name (first + last): ").strip()
        # validate name format first
        full_name = validate_name(full_name)
        username = make_username_from_name(full_name)
        print(f"Generated username: {username}")

        user_pw = getpass("Set user password: ")
        user_pw2 = getpass("Confirm user password: ")
        if user_pw != user_pw2:
            raise ValueError("Passwords do not match.")
        save_user(USERS_FILE, username, user_pw, "user")

        name = full_name
        phone = validate_phone(input("Enter phone number (+61...): "))
        tfn = validate_tfn(input("Enter Tax File Number: "))
        credit_card = validate_credit_card(input("Enter credit card number: "))
        email = sanitize_text(input("Enter email address: "))
        notes = sanitize_text(input("Enter any notes (optional): "))

        record = {
            'username': username,
            'name': name,
            'phone': phone,
            'tfn': tfn,
            'credit_card': credit_card,
            'email': email,
            'notes': notes
        }

        confirmation = ps.store(record)
        print("\nRecord securely saved in:", PII_FILE)
        print("User login created:")
        print(f"  Username: {username}")
        print("  (Password is the one you just set; it is stored hashed.)")
        print("\nRedacted confirmation:")
        print(json.dumps(confirmation, indent=2))
    except Exception as e:
        print("Error creating record + user:", e)

def admin_create_account():
    """Admin: create any type of account (admin/manager/employee/user)."""
    try:
        print("\n=== Create new account ===")
        username = input("New username: ").strip()
        if not username:
            raise ValueError("Username cannot be empty.")
        role = input("Role (admin/manager/employee/user): ").strip().lower()
        if role not in ("admin", "manager", "employee", "user"):
            raise ValueError("Invalid role.")
        pw = getpass("Password: ")
        pw2 = getpass("Confirm password: ")
        if pw != pw2:
            raise ValueError("Passwords do not match.")
        save_user(USERS_FILE, username, pw, role)
        print(f"Account created: {username} ({role})")
    except Exception as e:
        print("Error creating account:", e)

def view_all_records(ps: PiiSecure):
    records = ps.retrieve_all()
    print("\nAll decrypted records:")
    print(json.dumps(records, indent=2))

def pick_record_index_for_edit(ps: PiiSecure, filter_username: str | None = None) -> int | None:
    """Return index into records list, or None."""
    records = ps.retrieve_all()
    if not records:
        print("No records.")
        return None
    visible = []
    for idx, r in enumerate(records):
        if filter_username is None or r.get('username') == filter_username:
            visible.append((idx, r))
    if not visible:
        print("No matching records.")
        return None
    print("\nSelect a record:")
    for i, (idx, rec) in enumerate(visible, start=1):
        print(f"{i}. username={rec.get('username')} name={rec.get('name')} email={rec.get('email')}")
    choice = input("Enter number: ").strip()
    try:
        ci = int(choice) - 1
        return visible[ci][0]
    except Exception:
        print("Invalid selection.")
        return None

def edit_record_by_index(ps: PiiSecure, idx: int, only_for_username: str | None = None):
    records = ps.retrieve_all()
    if idx < 0 or idx >= len(records):
        print("Invalid index.")
        return
    record = records[idx]
    if only_for_username is not None and record.get('username') != only_for_username:
        print("You can only edit your own record.")
        return
    print("\nLeave blank to keep the current value.")
    try:
        name = input(f"Name [{record.get('name')}]: ").strip() or record['name']
        phone = input(f"Phone [{record.get('phone')}]: ").strip() or record['phone']
        tfn = input(f"TFN [{record.get('tfn')}]: ").strip() or record['tfn']
        cc = input(f"Credit card [{record.get('credit_card')[-4:]} masked]: ").strip() or record['credit_card']
        email = input(f"Email [{record.get('email')}]: ").strip() or record['email']
        notes = input(f"Notes [{record.get('notes')}]: ").strip() or record['notes']

        # validation
        name = validate_name(name)
        phone = validate_phone(phone)
        tfn = validate_tfn(tfn)
        cc = validate_credit_card(cc)
        email = sanitize_text(email)
        notes = sanitize_text(notes)

        updated = dict(record)
        updated.update({
            'name': name,
            'phone': phone,
            'tfn': tfn,
            'credit_card': cc,
            'email': email,
            'notes': notes
        })

        records[idx] = updated
        ps.overwrite_all(records)
        print("Record updated.")
    except Exception as e:
        print("Error updating record:", e)

def delete_record_by_index(ps: PiiSecure, idx: int):
    records = ps.retrieve_all()
    if idx < 0 or idx >= len(records):
        print("Invalid index.")
        return
    confirm = input("Type DELETE to confirm deletion: ")
    if confirm != "DELETE":
        print("Deletion cancelled.")
        return
    deleted = records.pop(idx)
    ps.overwrite_all(records)
    print(f"Record for username={deleted.get('username')} deleted.")

def user_view_own(ps: PiiSecure, username: str):
    records = ps.retrieve_all()
    my_records = [r for r in records if r.get('username') == username]
    if not my_records:
        print("No record found for your account.")
        return
    print("\nYour record:")
    print(json.dumps(my_records[0], indent=2))

def user_edit_own(ps: PiiSecure, username: str):
    idx = pick_record_index_for_edit(ps, filter_username=username)
    if idx is None:
        return
    edit_record_by_index(ps, idx, only_for_username=username)

# =============== ROLE MENUS ===============

def admin_menu(ps: PiiSecure, current_user: dict):
    while True:
        print("\nAdmin Menu")
        print("1. Create PII record + user (role=user)")
        print("2. Create account (admin/manager/employee/user)")
        print("3. View all PII records")
        print("4. Edit any PII record")
        print("5. Delete PII record")
        print("6. Logout")
        choice = input("Choice: ").strip()
        if choice == "1":
            admin_create_pii_and_user(ps)
        elif choice == "2":
            admin_create_account()
        elif choice == "3":
            view_all_records(ps)
        elif choice == "4":
            idx = pick_record_index_for_edit(ps)
            if idx is not None:
                edit_record_by_index(ps, idx)
        elif choice == "5":
            idx = pick_record_index_for_edit(ps)
            if idx is not None:
                delete_record_by_index(ps, idx)
        elif choice == "6":
            print("Logging out.")
            break
        else:
            print("Invalid choice.")

def manager_menu(ps: PiiSecure, current_user: dict):
    while True:
        print("\nManager Menu")
        print("1. Create PII record + user (role=user)")
        print("2. View all PII records")
        print("3. Edit any PII record")
        print("4. Logout")
        choice = input("Choice: ").strip()
        if choice == "1":
            admin_create_pii_and_user(ps)
        elif choice == "2":
            view_all_records(ps)
        elif choice == "3":
            idx = pick_record_index_for_edit(ps)
            if idx is not None:
                edit_record_by_index(ps, idx)
        elif choice == "4":
            print("Logging out.")
            break
        else:
            print("Invalid choice.")

def employee_menu(ps: PiiSecure, current_user: dict):
    while True:
        print("\nEmployee Menu")
        print("1. Create PII record + user (role=user)")
        print("2. View all PII records")
        print("3. Edit any PII record")
        print("4. Logout")
        choice = input("Choice: ").strip()
        if choice == "1":
            admin_create_pii_and_user(ps)
        elif choice == "2":
            view_all_records(ps)
        elif choice == "3":
            idx = pick_record_index_for_edit(ps)
            if idx is not None:
                edit_record_by_index(ps, idx)
        elif choice == "4":
            print("Logging out.")
            break
        else:
            print("Invalid choice.")

def user_menu(ps: PiiSecure, current_user: dict):
    username = current_user['username']
    while True:
        print("\nUser Menu")
        print("1. View my record")
        print("2. Edit my record")
        print("3. Logout")
        choice = input("Choice: ").strip()
        if choice == "1":
            user_view_own(ps, username)
        elif choice == "2":
            user_edit_own(ps, username)
        elif choice == "3":
            print("Logging out.")
            break
        else:
            print("Invalid choice.")

# =============== MAIN ===============

def main():
    print("Secure PII Storage System with RBAC\n-----------------------------------")
    enc_password = getpass("Enter master encryption password: ")
    ps = PiiSecure(PII_FILE, enc_password)

    # Ensure we have at least one admin
    ensure_initial_admin()

    # Login loop (one user at a time)
    current_user = None
    while current_user is None:
        current_user = login()

    role = current_user['role']
    if role == "admin":
        admin_menu(ps, current_user)
    elif role == "manager":
        manager_menu(ps, current_user)
    elif role == "employee":
        employee_menu(ps, current_user)
    else:
        # default to 'user' behaviour
        user_menu(ps, current_user)

if __name__ == "__main__":
    main()
