"""
Secure PII storage demo with RBAC and OOP design.

Features:
- Defensive input validation and sanitisation of PII fields.
- Encryption of PII before saving to disk (educational stream cipher + MAC).
- User accounts with hashed passwords (PBKDF2-HMAC-SHA256).
- Roles: admin, manager, employee, user.
- Only way to create a `user` account is through PII creation.
- Admin can create staff accounts (admin/manager/employee).
- Manager can create employee accounts only.
- Admin can change roles and reset passwords (with super-admin rule for other admins).
- Admin + Manager can delete accounts and linked PII (with safety checks).
- Login lockout (5 failed attempts = 5 minute lock).
- Audit log of security-relevant actions.
- Pretty card-style display of PII.
- Search, export-my-data, and full login/logout loop.
- Auto-generated passwords and welcome/role-update/deletion text files.
- Users can change their own password (logged-in self-service).
- Only the first admin (super admin) can reset passwords for other admins.
- Logging for "user changed own password".

NOTE: The crypto here is for learning. For production, use a vetted library
such as `cryptography` with AES-GCM and proper secret management.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import string
from dataclasses import dataclass
from datetime import datetime, timedelta
from getpass import getpass
from typing import Any, Dict, List, Optional, Set

USERS_FILE = "users.jsonl"
PII_FILE = "pii_store.jsonl"
AUDIT_FILE = "audit.log"


# ======================================================================
# Utility / validation helpers
# ======================================================================

def audit(actor: str, action: str, details: str = "") -> None:
    """
    Append a one-line audit entry to the audit log.

    :param actor: Username performing the action (or 'SYSTEM').
    :param action: Short action name, e.g. 'login_success'.
    :param details: Optional extra data about the action.
    """
    ts = datetime.utcnow().isoformat() + "Z"
    line = f"[{ts}] actor={actor} action={action} details={details}\n"
    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(line)


def validate_name(name: str) -> str:
    """
    Validate a full name (basic alpha, dash, apostrophe and spaces).

    Raises ValueError if invalid.
    """
    if not re.fullmatch(r"[A-Za-z\-' ]{2,100}", (name or "").strip()):
        raise ValueError("Invalid name format.")
    return (name or "").strip()


def validate_phone(phone: str) -> str:
    """
    Validate a phone number: + and 7–15 digits after stripping spaces.

    Raises ValueError if invalid.
    """
    phone = re.sub(r"\s+", "", phone or "")
    if not re.fullmatch(r"\+?\d{7,15}", phone):
        raise ValueError("Invalid phone number.")
    return phone


def validate_tfn(tfn: str) -> str:
    """
    Validate an Australian TFN (8 or 9 digits).

    Raises ValueError if invalid.
    """
    tfn = re.sub(r"\D", "", tfn or "")
    if len(tfn) not in (8, 9):
        raise ValueError("Invalid TFN.")
    return tfn


def validate_credit_card(card: str) -> str:
    """
    Validate a credit card number using length and Luhn checksum.

    Raises ValueError if invalid.
    """
    card = re.sub(r"\D", "", card or "")
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
    """
    Strip leading/trailing whitespace and collapse internal whitespace.
    """
    return re.sub(r"\s+", " ", (s or "").strip())


def make_username_from_name(full_name: str) -> str:
    """
    Generate a username from first and last name.

    Example:
        'Tate HK' -> 'tate.hk'
    """
    parts = (full_name or "").strip().lower().split()
    if len(parts) < 2:
        raise ValueError("Full name must include at least first and last name.")
    first = re.sub(r"[^a-z0-9]", "", parts[0])
    last = re.sub(r"[^a-z0-9]", "", parts[-1])
    if not first or not last:
        raise ValueError("Name must contain alphanumeric characters.")
    return f"{first}.{last}"


def mask_tail(value: str, keep: int = 4) -> str:
    """
    Mask all but the last `keep` characters of a string.
    """
    s = str(value or "")
    if len(s) <= keep:
        return "*" * len(s)
    return "*" * (len(s) - keep) + s[-keep:]


def generate_password(length: int = 10) -> str:
    """
    Generate a random password of letters + digits (no symbols).
    """
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def describe_permissions(role: str) -> List[str]:
    """
    Return a list of human-readable permission lines for a given role.
    """
    if role == "admin":
        return [
            "Full system access.",
            "Can create and manage all accounts (admin/manager/employee/user).",
            "Can view, edit and delete any PII record.",
            "Can change roles and reset passwords (with restrictions for other admins).",
            "Can delete any account and its linked PII (not the last admin).",
        ]
    if role == "manager":
        return [
            "Can create employee accounts.",
            "Can create PII records and linked user accounts.",
            "Can view and edit all PII records.",
            "Can delete employee and user accounts and their linked PII.",
        ]
    if role == "employee":
        return [
            "Can create PII records and linked user accounts.",
            "Can view and edit all PII records.",
        ]
    # default: user
    return [
        "Can log in and view their own PII record.",
        "Can edit their own PII record.",
        "Cannot view or manage anyone else's data.",
    ]


def write_welcome_file(username: str, full_name: Optional[str], role: str, password: str) -> None:
    """
    Write a welcome-<username>.txt file describing login details and permissions.
    """
    filename = f"welcome-{username}.txt"
    lines: List[str] = []
    display_name = full_name or username

    lines.append(f"Welcome {display_name}!")
    lines.append("")
    if role == "user":
        lines.append("Your new account has been created so you can access your PII record.")
    else:
        lines.append("A staff account has been created for you.")

    lines.append("")
    lines.append(f"Username: {username}")
    lines.append(f"Password: {password}")
    lines.append(f"Role: {role}")
    lines.append("")

    lines.append("Permissions:")
    for perm in describe_permissions(role):
        lines.append(f"• {perm}")

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def write_role_update_file(username: str, full_name: Optional[str], old_role: str, new_role: str) -> None:
    """
    Write a role-update-<username>.txt file whenever a role is changed.
    """
    filename = f"role-update-{username}.txt"
    display_name = full_name or username

    lines: List[str] = []
    lines.append(f"Role Update Notification for {display_name}")
    lines.append("")
    lines.append(f"Username: {username}")
    lines.append(f"Old Role: {old_role}")
    lines.append(f"New Role: {new_role}")
    lines.append("")
    lines.append("Permissions have been updated:")
    for perm in describe_permissions(new_role):
        lines.append(f"• {perm}")
    lines.append("")
    lines.append("Your password has not changed.")

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def write_deleted_file(
    username: str,
    full_name: Optional[str],
    role: str,
    deleted_by: str,
    pii_deleted: bool,
) -> None:
    """
    Write a deleted-<username>.txt file when an account is removed.
    """
    filename = f"deleted-{username}.txt"
    display_name = full_name or username

    lines: List[str] = []
    lines.append(f"Account Deleted: {username}")
    lines.append("")
    lines.append(f"Name: {display_name}")
    lines.append(f"Role: {role}")
    lines.append(f"Deleted by: {deleted_by}")
    lines.append("")
    if pii_deleted:
        lines.append("Any PII record belonging to this user has also been securely destroyed.")
    else:
        lines.append("No PII record was found for this user, or none was deleted.")
    lines.append("")
    lines.append("This file is a system audit artefact and should be retained for records.")

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def write_password_reset_file(
    username: str,
    full_name: Optional[str],
    role: str,
    new_password: str,
    reset_by: str,
) -> None:
    """
    Write a password-reset-<username>.txt file whenever an admin resets a password.
    """
    filename = f"password-reset-{username}.txt"
    display_name = full_name or username
    ts = datetime.utcnow().isoformat() + "Z"

    lines: List[str] = []
    lines.append(f"Password Reset Notification for {display_name}")
    lines.append("")
    lines.append(f"Username: {username}")
    lines.append(f"Role: {role}")
    lines.append(f"New Temporary Password: {new_password}")
    lines.append("")
    lines.append(f"Reset By: {reset_by}")
    lines.append(f"Time: {ts}")
    lines.append("")
    lines.append("Your password was reset by an authorised staff member.")
    lines.append("Please log in and change it as soon as possible.")

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ======================================================================
# Crypto helpers (educational stream cipher + MAC)
# ======================================================================

def _derive_keys(password: str, salt: bytes) -> (bytes, bytes):
    """
    Derive an encryption key and a MAC key from a password and salt using PBKDF2.
    """
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000, dklen=64)
    return dk[:32], dk[32:]


def _stream_xor(enc_key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """
    Very simple HMAC-based stream cipher (for learning only).

    XORs the plaintext with a keystream derived from HMAC(enc_key, nonce || counter).
    """
    out = bytearray()
    counter = 0
    while len(out) < len(plaintext):
        block = hmac.new(enc_key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(a ^ b for a, b in zip(plaintext, out[: len(plaintext)]))


def encrypt_bytes(plaintext: bytes, password: str) -> Dict[str, str]:
    """
    Encrypt a bytes payload with password-derived keys and return a JSON-serialisable dict.
    """
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(8)
    enc_key, mac_key = _derive_keys(password, salt)
    ciphertext = _stream_xor(enc_key, nonce, plaintext)
    mac = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    return {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "mac": base64.b64encode(mac).decode(),
        "kdf": "pbkdf2_sha256_200k",
    }


def decrypt_bytes(enc_obj: Dict[str, str], password: str) -> bytes:
    """
    Decrypt an object produced by encrypt_bytes, verifying integrity.

    Raises ValueError if MAC fails or structure is invalid.
    """
    salt = base64.b64decode(enc_obj["salt"])
    nonce = base64.b64decode(enc_obj["nonce"])
    ciphertext = base64.b64decode(enc_obj["ciphertext"])
    mac = base64.b64decode(enc_obj["mac"])
    enc_key, mac_key = _derive_keys(password, salt)
    calc_mac = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, calc_mac):
        raise ValueError("Integrity check failed (wrong password or tampered data).")
    return _stream_xor(enc_key, nonce, ciphertext)


def hash_password(password: str, salt: Optional[bytes] = None) -> Dict[str, str]:
    """
    Hash a password using PBKDF2-HMAC-SHA256 with a per-user salt.
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000, dklen=32)
    return {
        "salt": base64.b64encode(salt).decode(),
        "pw_hash": base64.b64encode(dk).decode(),
        "kdf": "pbkdf2_sha256_200k",
    }


def verify_password(password: str, stored: Dict[str, str]) -> bool:
    """
    Verify a plaintext password against a stored hash/salt record.
    """
    salt = base64.b64decode(stored["salt"])
    expected = base64.b64decode(stored["pw_hash"])
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000, dklen=32)
    return hmac.compare_digest(dk, expected)


# ======================================================================
# Data classes
# ======================================================================

@dataclass
class User:
    """
    Simple user data wrapper used by UserManager and menus.
    """
    username: str
    role: str
    name: Optional[str] = None
    failed_attempts: int = 0
    locked_until: Optional[str] = None
    password_record: Optional[Dict[str, str]] = None
    is_super_admin: bool = False


# ======================================================================
# PiiSecure – encrypted PII storage
# ======================================================================

class PiiSecure:
    """
    Handle encrypted storage and retrieval of PII records.

    All PII fields are encrypted before writing to disk and decrypted on load.
    """

    def __init__(self, filename: str, master_password: str):
        self.filename = filename
        self.master_password = master_password
        self.pii_fields = ["name", "phone", "tfn", "credit_card"]

    # ---------- internal helpers ----------

    def _encrypt_record_fields(self, record: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k, v in record.items():
            if k in self.pii_fields:
                out[k] = encrypt_bytes(str(v).encode("utf-8"), self.master_password)
            else:
                out[k] = v
        out["_meta"] = {"encrypted_at": datetime.utcnow().isoformat() + "Z"}
        return out

    def _decrypt_record_fields(self, record: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k, v in record.items():
            if k in self.pii_fields and isinstance(v, dict) and "ciphertext" in v:
                out[k] = decrypt_bytes(v, self.master_password).decode("utf-8")
            else:
                out[k] = v
        return out

    # ---------- public API ----------

    def add_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Encrypt and append a single PII record to the backing file.

        Returns a redacted copy (for user feedback).
        """
        enc = self._encrypt_record_fields(record)
        with open(self.filename, "a", encoding="utf-8") as f:
            f.write(json.dumps(enc) + "\n")

        redacted: Dict[str, Any] = {}
        for k, v in record.items():
            if k in self.pii_fields:
                redacted[k] = mask_tail(str(v))
            else:
                redacted[k] = v
        return redacted

    def load_all(self) -> List[Dict[str, Any]]:
        """
        Load and decrypt all PII records.
        """
        if not os.path.exists(self.filename):
            return []
        records: List[Dict[str, Any]] = []
        with open(self.filename, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                enc_record = json.loads(line)
                records.append(self._decrypt_record_fields(enc_record))
        return records

    def overwrite_all(self, records: List[Dict[str, Any]]) -> None:
        """
        Replace the PII file contents with the given plain records, re-encrypting each one.
        """
        with open(self.filename, "w", encoding="utf-8") as f:
            for rec in records:
                enc = self._encrypt_record_fields(rec)
                f.write(json.dumps(enc) + "\n")


# ======================================================================
# UserManager – users, roles, lockout, passwords, deletion
# ======================================================================

class UserManager:
    """
    Manage storage and behaviour of user accounts:
    - creation of staff and PII users
    - password hashing and verification
    - login lockout enforcement
    - role changes and password resets
    - account deletion and linked PII deletion (for admin/manager)
    """

    def __init__(self, filename: str):
        self.filename = filename

    # ---------- persistence ----------

    def _load_users_raw(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.filename):
            return []
        users: List[Dict[str, Any]] = []
        with open(self.filename, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                obj.setdefault("failed_attempts", 0)
                obj.setdefault("locked_until", None)
                obj.setdefault("is_super_admin", False)
                users.append(obj)
        return users

    def _write_users_raw(self, users: List[Dict[str, Any]]) -> None:
        with open(self.filename, "w", encoding="utf-8") as f:
            for u in users:
                f.write(json.dumps(u) + "\n")

    # ---------- conversion helpers ----------

    def _to_user(self, data: Dict[str, Any]) -> User:
        return User(
            username=data["username"],
            role=data["role"],
            name=data.get("name"),
            failed_attempts=data.get("failed_attempts", 0),
            locked_until=data.get("locked_until"),
            password_record=data.get("password"),
            is_super_admin=data.get("is_super_admin", False),
        )

    # ---------- CRUD operations ----------

    def get_user(self, username: str) -> Optional[User]:
        """
        Return a User object for the given username, or None if not found.
        """
        for data in self._load_users_raw():
            if data["username"] == username:
                return self._to_user(data)
        return None

    def _username_exists(self, username: str) -> bool:
        return self.get_user(username) is not None

    def create_user(
        self,
        username: str,
        password: str,
        role: str,
        full_name: Optional[str] = None,
        is_super_admin: bool = False,
    ) -> User:
        """
        Create a new user with the given role.
        """
        if self._username_exists(username):
            raise ValueError("Username already exists.")
        users = self._load_users_raw()
        rec = {
            "username": username,
            "role": role,
            "password": hash_password(password),
            "failed_attempts": 0,
            "locked_until": None,
            "is_super_admin": is_super_admin,
        }
        if full_name:
            rec["name"] = full_name
        users.append(rec)
        self._write_users_raw(users)
        return self._to_user(rec)

    def ensure_initial_admin(self) -> None:
        """
        Ensure there is at least one admin.
        - If none exist, create one and mark as super admin.
        - If admins exist but none are marked as super admin, mark the first as super admin.
        """
        users = self._load_users_raw()
        admins = [u for u in users if u.get("role") == "admin"]

        if admins:
            # Ensure one of them is super admin
            if not any(u.get("is_super_admin") for u in admins):
                admins[0]["is_super_admin"] = True
                self._write_users_raw(users)
                audit("SYSTEM", "promote_existing_admin_to_super_admin", f"username={admins[0]['username']}")
            return

        # No admins at all -> create initial super admin
        print("\nNo admin accounts found. Create an initial admin account.")
        while True:
            full_name = input("Admin full name (first + last): ").strip()
            try:
                full_name = validate_name(full_name)
            except Exception as e:
                print(e)
                continue

            username = make_username_from_name(full_name)
            print(f"Generated admin username: {username}")
            pw = getpass("Admin password: ")
            pw2 = getpass("Confirm admin password: ")
            if pw != pw2:
                print("Passwords do not match, try again.")
                continue
            try:
                self.create_user(username, pw, "admin", full_name, is_super_admin=True)
                audit("SYSTEM", "create_initial_admin", f"username={username}")
                print("Initial admin account created (super admin).")
                break
            except Exception as e:
                print("Error creating admin:", e)

    # ---------- login / lockout ----------

    def login(self) -> Optional[User]:
        """
        Prompt for credentials and perform login with lockout logic.

        Returns a User on success, None on failure or 'exit'.
        """
        print("\n=== Login ===")
        username = input("Username (or 'exit' to quit): ").strip()
        if username.lower() == "exit":
            return None
        pw = getpass("Password: ")

        users = self._load_users_raw()
        target: Optional[Dict[str, Any]] = None
        for u in users:
            if u["username"] == username:
                target = u
                break

        if not target:
            print("No such user.")
            audit(username, "login_failure", "no_such_user")
            return None

        # lockout check
        locked_until = target.get("locked_until")
        if locked_until:
            try:
                locked_dt = datetime.fromisoformat(locked_until)
                if datetime.utcnow() < locked_dt:
                    remaining = (locked_dt - datetime.utcnow()).seconds
                    minutes = max(1, remaining // 60)
                    print(f"Account locked. Try again in about {minutes} minute(s).")
                    audit(username, "login_blocked_locked", f"locked_until={locked_until}")
                    return None
            except Exception:
                # ignore malformed lock value
                pass

        if not verify_password(pw, target["password"]):
            # bump failed attempts
            target["failed_attempts"] = target.get("failed_attempts", 0) + 1
            if target["failed_attempts"] >= 5:
                target["locked_until"] = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
            self._write_users_raw(users)
            audit(username, "login_failure", "wrong_password")
            print("Incorrect password.")
            return None

        # success -> reset counters
        target["failed_attempts"] = 0
        target["locked_until"] = None
        self._write_users_raw(users)
        audit(username, "login_success", f"role={target['role']}")
        return self._to_user(target)

    # ---------- admin / manager helpers ----------

    def list_users(self) -> List[User]:
        """
        Return all users as User objects.
        """
        return [self._to_user(u) for u in self._load_users_raw()]

    def change_role(self, actor: User, target_username: str, new_role: str) -> None:
        """
        Change the role of a user, enforcing 'last admin' safety,
        and write a role-update text file.
        """
        users = self._load_users_raw()
        target = None
        for u in users:
            if u["username"] == target_username:
                target = u
                break
        if not target:
            raise ValueError("User not found.")

        if target_username == actor.username:
            raise ValueError("You cannot change your own role.")

        if target["role"] == "admin" and new_role != "admin":
            admins = [u for u in users if u["role"] == "admin"]
            if len(admins) <= 1:
                raise ValueError("Cannot demote the last admin.")

        old_role = target["role"]
        target["role"] = new_role
        self._write_users_raw(users)
        audit(actor.username, "change_role", f"{target_username}: {old_role} -> {new_role}")
        # write role update file (password unchanged)
        write_role_update_file(target_username, target.get("name"), old_role, new_role)

    def reset_password(self, actor: User, target_username: str, new_password: str) -> None:
        """
        Reset the password of another user, clearing lockout counters.

        Rules:
        - Only admins can reset other users' passwords.
        - No one can use this to reset their own password (use self-change).
        - Only the super admin (first admin) can reset other admins' passwords.
        """
        if actor.role != "admin":
            raise PermissionError("Only admin can reset passwords for other users.")

        users = self._load_users_raw()
        target = None
        for u in users:
            if u["username"] == target_username:
                target = u
                break
        if not target:
            raise ValueError("User not found.")

        if target_username == actor.username:
            raise ValueError("Use 'change my password' for your own account.")

        target_role = target.get("role")

        # Only super admin can reset other admins' passwords
        if target_role == "admin" and not actor.is_super_admin:
            raise PermissionError("Only the super admin can reset other admins' passwords.")

        full_name = target.get("name")
        role = target_role

        target["password"] = hash_password(new_password)
        target["failed_attempts"] = 0
        target["locked_until"] = None
        self._write_users_raw(users)

        audit(actor.username, "reset_password", f"target={target_username}")
        write_password_reset_file(target_username, full_name, role, new_password, actor.username)

    def create_staff_account(self, actor: User, full_name: str, role: str) -> (User, str):
        """
        Create a staff account (admin/manager/employee) with an auto-generated password.

        Managers may only create employees. Admin may create any staff role.

        Returns (User, plaintext_password) so the caller can show/store it.
        """
        full_name = validate_name(full_name)
        username = make_username_from_name(full_name)

        if actor.role == "admin":
            allowed_roles = {"admin", "manager", "employee"}
        elif actor.role == "manager":
            allowed_roles = {"employee"}
        else:
            raise PermissionError("Insufficient permissions to create staff accounts.")

        if role not in allowed_roles:
            raise PermissionError("You do not have permission to create that role.")

        password = generate_password()
        user = self.create_user(username, password, role, full_name, is_super_admin=False)
        audit(actor.username, "create_staff_account", f"{username} -> {role}")
        # write welcome file with generated password
        write_welcome_file(user.username, user.name, user.role, password)
        return user, password

    def create_pii_user_account(self, actor: User, full_name: str) -> (User, str):
        """
        Create a 'user' role account to be associated with a PII record,
        with an auto-generated password.

        Returns (User, plaintext_password).
        """
        full_name = validate_name(full_name)
        username = make_username_from_name(full_name)
        password = generate_password()
        user = self.create_user(username, password, "user", full_name, is_super_admin=False)
        audit(actor.username, "create_user_with_pii", f"username={username}")
        # welcome file for end user
        write_welcome_file(user.username, user.name, user.role, password)
        return user, password

    def delete_account(
        self,
        actor: User,
        target_username: str,
        pii_store: Optional[PiiSecure] = None,
    ) -> bool:
        """
        Delete a user account, and (optionally) delete linked PII records.

        - Admin can delete any account except the last admin and themselves.
        - Manager can delete only 'employee' and 'user' accounts (not admins or managers).
        - PII deletion removes any record(s) whose username matches target_username.

        Returns True if any PII record was deleted, False otherwise.
        """
        users = self._load_users_raw()
        target = None
        for u in users:
            if u["username"] == target_username:
                target = u
                break
        if not target:
            raise ValueError("User not found.")

        if target_username == actor.username:
            raise ValueError("You cannot delete your own account.")

        target_role = target["role"]

        # Enforce manager restrictions
        if actor.role == "manager":
            if target_role not in {"employee", "user"}:
                raise PermissionError("Managers can only delete employee or user accounts.")
        elif actor.role != "admin":
            raise PermissionError("Only admin or manager can delete accounts.")

        # Do not allow deletion of the last admin
        if target_role == "admin":
            admins = [u for u in users if u["role"] == "admin"]
            if len(admins) <= 1:
                raise ValueError("Cannot delete the last admin account.")

        # Delete linked PII records (any records whose username matches)
        pii_deleted = False
        if pii_store is not None:
            records = pii_store.load_all()
            new_records = [r for r in records if r.get("username") != target_username]
            if len(new_records) != len(records):
                pii_deleted = True
                pii_store.overwrite_all(new_records)

        # Remove user account
        users = [u for u in users if u["username"] != target_username]
        self._write_users_raw(users)

        audit(actor.username, "delete_account", f"{target_username} role={target_role} pii_deleted={pii_deleted}")
        write_deleted_file(target_username, target.get("name"), target_role, actor.username, pii_deleted)

        return pii_deleted

    # ---------- self-service password change ----------

    def change_own_password(self, user: User, current_password: str, new_password: str) -> None:
        """
        Allow any logged-in user to change their own password, after verifying
        their current password. This logs 'user_changed_own_password'.
        """
        users = self._load_users_raw()
        target = None
        for u in users:
            if u["username"] == user.username:
                target = u
                break
        if not target:
            raise ValueError("Current user not found in database.")

        if not verify_password(current_password, target["password"]):
            raise ValueError("Current password is incorrect.")

        target["password"] = hash_password(new_password)
        target["failed_attempts"] = 0
        target["locked_until"] = None
        self._write_users_raw(users)

        audit(user.username, "user_changed_own_password", "")


# ======================================================================
# Pretty PII helpers
# ======================================================================

def print_record_card(record: Dict[str, Any], show_secret: bool = False) -> None:
    """
    Print a single PII record in a pretty, card-like layout.
    """
    username = record.get("username", "(none)")
    name = record.get("name", "")
    phone = record.get("phone", "")
    tfn = record.get("tfn", "")
    cc = record.get("credit_card", "")
    email = record.get("email", "")
    notes = record.get("notes", "")

    tfn_display = tfn if show_secret else mask_tail(tfn, keep=3)
    cc_display = cc if show_secret else mask_tail(cc, keep=4)

    border = "═" * 50
    print(border)
    print(f" User: {username}")
    print(border)
    print(f"Full Name:      {name}")
    print(f"Phone:          {phone}")
    print(f"TFN:            {tfn_display}")
    print(f"Credit Card:    {cc_display}")
    print(f"Email:          {email}")
    print(f"Notes:          {notes}")
    print(border)


# ======================================================================
# Menu base + concrete role menus
# ======================================================================

class BaseMenu:
    """
    Base menu class shared by all role-specific menus.
    """

    def __init__(self, user: User, users: UserManager, pii: PiiSecure):
        self.user = user
        self.users = users
        self.pii = pii

    def run(self) -> None:
        """
        Run the menu loop for this role. Must be implemented by subclasses.
        """
        raise NotImplementedError

    # ----- new helper: prompt with validation & re-ask on error -----

    def _prompt_valid_input(self, prompt: str, validator) -> str:
        """
        Ask for input in a loop until `validator(value)` succeeds.

        Used so that if e.g. credit card is wrong, it will just re-ask that field.
        """
        while True:
            value = input(prompt).strip()
            try:
                return validator(value)
            except Exception as e:
                print(f"Error: {e}")
                print("Please try again.\n")

    # ----- shared PII helpers -----

    def _select_record_index(self, only_for_username: Optional[str] = None) -> Optional[int]:
        records = self.pii.load_all()
        if not records:
            print("No records.")
            return None
        visible = []
        for idx, r in enumerate(records):
            if only_for_username is None or r.get("username") == only_for_username:
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

    def _edit_record_by_index(self, idx: int, only_for_username: Optional[str] = None) -> None:
        records = self.pii.load_all()
        if idx < 0 or idx >= len(records):
            print("Invalid index.")
            return
        record = records[idx]
        if only_for_username is not None and record.get("username") != only_for_username:
            print("You can only edit your own record.")
            return

        print("\nLeave blank to keep the current value.")
        try:
            name = input(f"Name [{record.get('name')}]: ").strip() or record["name"]
            phone = input(f"Phone [{record.get('phone')}]: ").strip() or record["phone"]
            tfn = input(f"TFN [{record.get('tfn')}]: ").strip() or record["tfn"]
            cc_current_masked = mask_tail(record.get("credit_card", ""), keep=4)
            cc = input(f"Credit card [{cc_current_masked}]: ").strip() or record["credit_card"]
            email = input(f"Email [{record.get('email')}]: ").strip() or record["email"]
            notes = input(f"Notes [{record.get('notes')}]: ").strip() or record["notes"]

            name = validate_name(name)
            phone = validate_phone(phone)
            tfn = validate_tfn(tfn)
            cc = validate_credit_card(cc)
            email = sanitize_text(email)
            notes = sanitize_text(notes)

            updated = dict(record)
            updated.update(
                {
                    "name": name,
                    "phone": phone,
                    "tfn": tfn,
                    "credit_card": cc,
                    "email": email,
                    "notes": notes,
                }
            )
            records[idx] = updated
            self.pii.overwrite_all(records)
            audit(self.user.username, "edit_record", f"username={record.get('username')}")
            print("Record updated.")
        except Exception as e:
            print("Error updating record:", e)

    def _delete_record_by_index(self, idx: int) -> None:
        records = self.pii.load_all()
        if idx < 0 or idx >= len(records):
            print("Invalid index.")
            return
        rec = records[idx]
        print_record_card(rec)
        sure = input("Are you sure you want to delete this record? (yes/no): ").strip().lower()
        if sure != "yes":
            print("Deletion cancelled.")
            return
        confirm = input("Type DELETE to confirm deletion: ")
        if confirm != "DELETE":
            print("Deletion cancelled.")
            return
        deleted = records.pop(idx)
        self.pii.overwrite_all(records)
        audit(self.user.username, "delete_record", f"username={deleted.get('username')}")
        print(f"Record for username={deleted.get('username')} deleted.")

    def _search_records(self) -> None:
        records = self.pii.load_all()
        if not records:
            print("No records to search.")
            return
        term = input("Enter search term: ").strip().lower()
        if not term:
            print("Empty search term.")
            return
        matches = []
        for r in records:
            haystack = " ".join(str(r.get(k, "")) for k in ("username", "name", "email", "phone")).lower()
            if term in haystack:
                matches.append(r)
        if not matches:
            print("No records matched your search.")
            return
        print(f"\nFound {len(matches)} matching record(s):")
        for rec in matches:
            print_record_card(rec)

    def _view_all_records(self) -> None:
        records = self.pii.load_all()
        if not records:
            print("No PII records found.")
            return
        print("\nAll PII records:")
        for rec in records:
            print_record_card(rec)

    def _create_pii_and_user(self) -> None:
        """
        Shared helper: create a PII record and linked 'user' account.

        - ALL FIELDS are collected and validated FIRST.
        - If a field is invalid (e.g. credit card), it re-asks just that field.
        - Only AFTER everything succeeds is the user account created
          and the PII record written.
        """
        try:
            print("\n=== Create new PII record and user account (role=user) ===")

            # 1) Collect + validate full name (re-ask on error)
            full_name = self._prompt_valid_input(
                "Enter full name (first + last): ",
                validate_name,
            )

            # 2) Collect + validate other PII fields, with re-ask loops
            phone = self._prompt_valid_input(
                "Enter phone number (+61...): ",
                validate_phone,
            )
            tfn = self._prompt_valid_input(
                "Enter Tax File Number: ",
                validate_tfn,
            )
            credit_card = self._prompt_valid_input(
                "Enter credit card number: ",
                validate_credit_card,
            )

            # email + notes: sanitised but not "invalid", so no loop needed
            email_raw = input("Enter email address: ")
            email = sanitize_text(email_raw)
            notes_raw = input("Enter any notes (optional): ")
            notes = sanitize_text(notes_raw)

            # If we've reached here, ALL data is valid -> now create the user
            user, pw = self.users.create_pii_user_account(self.user, full_name)
            print(f"\nGenerated username: {user.username}")
            print(f"Generated password: {pw}")
            print("A welcome file has been created with these details.")

            # 3) Save PII record
            record = {
                "username": user.username,
                "name": full_name,
                "phone": phone,
                "tfn": tfn,
                "credit_card": credit_card,
                "email": email,
                "notes": notes,
            }
            confirmation = self.pii.add_record(record)
            audit(self.user.username, "create_pii_record", f"username={user.username}")
            print("\nRecord securely saved.")
            print("\nRedacted confirmation:")
            print(json.dumps(confirmation, indent=2))

        except Exception as e:
            print("Error creating PII + user:", e)

    # ----- shared account deletion helper for admin/manager -----

    def _delete_account_flow(self, allowed_roles: Optional[Set[str]] = None) -> None:
        """
        Shared deletion flow for admin/manager menus.

        allowed_roles:
            - None => show all users
            - set(...) => only show users whose role is in the set
        """
        all_users = self.users.list_users()
        if not all_users:
            print("No users found.")
            return

        # Filter list based on allowed roles for menu view (manager case)
        if allowed_roles is not None:
            display_users = [u for u in all_users if u.role in allowed_roles]
        else:
            display_users = all_users

        if not display_users:
            print("No accounts available for deletion.")
            return

        print("\n=== Delete account (and linked PII) ===")
        for i, u in enumerate(display_users, start=1):
            label = f"{u.username} ({u.role})"
            if u.name:
                label += f" – {u.name}"
            print(f"{i}. {label}")

        choice = input("Select a user to delete: ").strip()
        try:
            idx = int(choice) - 1
            target = display_users[idx]
        except Exception:
            print("Invalid selection.")
            return

        # Extra safety: prevent self-delete at menu level as well
        if target.username == self.user.username:
            print("You cannot delete your own account.")
            return

        print(f"\nYou are about to delete account: {target.username} ({target.role})")
        confirm1 = input("Type the username to confirm: ").strip()
        if confirm1 != target.username:
            print("Confirmation did not match. Deletion cancelled.")
            return

        confirm2 = input("Type DELETE to permanently delete this account and any linked PII: ").strip()
        if confirm2 != "DELETE":
            print("Deletion cancelled.")
            return

        try:
            pii_deleted = self.users.delete_account(self.user, target.username, self.pii)
            if pii_deleted:
                print(f"Account {target.username} deleted and linked PII removed.")
            else:
                print(f"Account {target.username} deleted (no linked PII found).")
            print("A deletion summary file has been created.")
        except PermissionError as e:
            print("Permission error:", e)
        except Exception as e:
            print("Error deleting account:", e)

    # ----- shared self-service password change -----

    def _change_my_password(self) -> None:
        """
        Let the currently logged-in user change their own password.
        """
        print("\n=== Change My Password ===")
        current_pw = getpass("Enter your current password: ")
        new_pw = getpass("Enter new password: ")
        new_pw2 = getpass("Confirm new password: ")
        if new_pw != new_pw2:
            print("New passwords do not match.")
            return
        if not new_pw:
            print("New password cannot be empty.")
            return

        try:
            self.users.change_own_password(self.user, current_pw, new_pw)
            print("Your password has been updated.")
        except Exception as e:
            print("Error changing password:", e)


class AdminMenu(BaseMenu):
    """
    Menu for admin users.
    """

    def run(self) -> None:
        while True:
            print("\nAdmin Menu")
            print("1.  Create PII record + user (role=user)")
            print("2.  Create staff account (admin/manager/employee)")
            print("3.  View all PII records")
            print("4.  Edit any PII record")
            print("5.  Delete PII record")
            print("6.  Change account role")
            print("7.  Reset user password")
            print("8.  Search PII records")
            print("9.  Delete account (and linked PII)")
            print("10. Change my password")
            print("11. Logout")
            choice = input("Choice: ").strip()

            if choice == "1":
                self._create_pii_and_user()
            elif choice == "2":
                self._create_staff_account()
            elif choice == "3":
                self._view_all_records()
            elif choice == "4":
                idx = self._select_record_index()
                if idx is not None:
                    self._edit_record_by_index(idx)
            elif choice == "5":
                idx = self._select_record_index()
                if idx is not None:
                    self._delete_record_by_index(idx)
            elif choice == "6":
                self._change_role()
            elif choice == "7":
                self._reset_password()
            elif choice == "8":
                self._search_records()
            elif choice == "9":
                # admin can delete any account (rules enforced in UserManager)
                self._delete_account_flow(allowed_roles=None)
            elif choice == "10":
                self._change_my_password()
            elif choice == "11":
                print("Logging out.")
                break
            else:
                print("Invalid choice.")

    def _create_staff_account(self) -> None:
        try:
            print("\n=== Create new staff account ===")
            full_name = input("Full name (first + last): ").strip()
            role = input("Role (admin/manager/employee): ").strip().lower()
            if role not in {"admin", "manager", "employee"}:
                print("Invalid role.")
                return
            staff, pw = self.users.create_staff_account(self.user, full_name, role)
            print(f"Created staff account: {staff.username} ({staff.role})")
            print(f"Generated password: {pw}")
            print("A welcome file has been created with these details.")
        except PermissionError as e:
            print("Permission error:", e)
        except Exception as e:
            print("Error creating staff:", e)

    def _change_role(self) -> None:
        users = self.users.list_users()
        if not users:
            print("No users found.")
            return
        print("\n=== Change account role ===")
        for i, u in enumerate(users, start=1):
            label = f"{u.username} ({u.role})"
            if u.name:
                label += f" – {u.name}"
            print(f"{i}. {label}")
        choice = input("Select a user: ").strip()
        try:
            idx = int(choice) - 1
            target = users[idx]
        except Exception:
            print("Invalid selection.")
            return

        new_role = input("New role (admin/manager/employee/user): ").strip().lower()
        if new_role not in {"admin", "manager", "employee", "user"}:
            print("Invalid role.")
            return
        try:
            self.users.change_role(self.user, target.username, new_role)
            print(f"Role updated: {target.username} is now {new_role}")
            print("A role-update file has been created for this user.")
        except Exception as e:
            print("Error changing role:", e)

    def _reset_password(self) -> None:
        users = self.users.list_users()
        if not users:
            print("No users found.")
            return
        print("\n=== Reset user password ===")
        for i, u in enumerate(users, start=1):
            label = f"{u.username} ({u.role})"
            if u.name:
                label += f" – {u.name}"
            print(f"{i}. {label}")
        choice = input("Select a user: ").strip()
        try:
            idx = int(choice) - 1
            target = users[idx]
        except Exception:
            print("Invalid selection.")
            return

        new_pw = getpass("New password: ")
        new_pw2 = getpass("Confirm new password: ")
        if new_pw != new_pw2:
            print("Passwords do not match.")
            return

        try:
            self.users.reset_password(self.user, target.username, new_pw)
            print("Password reset successfully.")
            print("A password-reset file has been created for this user.")
        except Exception as e:
            print("Error resetting password:", e)


class ManagerMenu(BaseMenu):
    """
    Menu for manager users.
    """

    def run(self) -> None:
        while True:
            print("\nManager Menu")
            print("1. Create PII record + user (role=user)")
            print("2. Create employee account")
            print("3. View all PII records")
            print("4. Edit any PII record")
            print("5. Search PII records")
            print("6. Delete account (employee/user + linked PII)")
            print("7. Change my password")
            print("8. Logout")
            choice = input("Choice: ").strip()

            if choice == "1":
                self._create_pii_and_user()
            elif choice == "2":
                self._create_employee_account()
            elif choice == "3":
                self._view_all_records()
            elif choice == "4":
                idx = self._select_record_index()
                if idx is not None:
                    self._edit_record_by_index(idx)
            elif choice == "5":
                self._search_records()
            elif choice == "6":
                # manager: allow deletion of employee + user accounts
                self._delete_account_flow(allowed_roles={"employee", "user"})
            elif choice == "7":
                self._change_my_password()
            elif choice == "8":
                print("Logging out.")
                break
            else:
                print("Invalid choice.")

    def _create_employee_account(self) -> None:
        try:
            print("\n=== Create employee account ===")
            full_name = input("Employee full name (first + last): ").strip()
            emp, pw = self.users.create_staff_account(self.user, full_name, "employee")
            print(f"Created employee account: {emp.username}")
            print(f"Generated password: {pw}")
            print("A welcome file has been created with these details.")
        except Exception as e:
            print("Error creating employee account:", e)


class EmployeeMenu(BaseMenu):
    """
    Menu for employee users.
    """

    def run(self) -> None:
        while True:
            print("\nEmployee Menu")
            print("1. Create PII record + user (role=user)")
            print("2. View all PII records")
            print("3. Edit any PII record")
            print("4. Search PII records")
            print("5. Change my password")
            print("6. Logout")
            choice = input("Choice: ").strip()
            if choice == "1":
                self._create_pii_and_user()
            elif choice == "2":
                self._view_all_records()
            elif choice == "3":
                idx = self._select_record_index()
                if idx is not None:
                    self._edit_record_by_index(idx)
            elif choice == "4":
                self._search_records()
            elif choice == "5":
                self._change_my_password()
            elif choice == "6":
                print("Logging out.")
                break
            else:
                print("Invalid choice.")


class UserMenu(BaseMenu):
    """
    Menu for normal end users (role='user').
    """

    def run(self) -> None:
        while True:
            print("\nUser Menu")
            print("1. View my record")
            print("2. Edit my record")
            print("3. Export my data")
            print("4. Change my password")
            print("5. Logout")
            choice = input("Choice: ").strip()

            if choice == "1":
                self._view_my_record()
            elif choice == "2":
                self._edit_my_record()
            elif choice == "3":
                self._export_my_data()
            elif choice == "4":
                self._change_my_password()
            elif choice == "5":
                print("Logging out.")
                break
            else:
                print("Invalid choice.")

    def _view_my_record(self) -> None:
        records = self.pii.load_all()
        mine = [r for r in records if r.get("username") == self.user.username]
        if not mine:
            print("No record found for your account.")
            return
        print_record_card(mine[0])

    def _edit_my_record(self) -> None:
        idx = self._select_record_index(only_for_username=self.user.username)
        if idx is None:
            return
        self._edit_record_by_index(idx, only_for_username=self.user.username)

    def _export_my_data(self) -> None:
        records = self.pii.load_all()
        mine = [r for r in records if r.get("username") == self.user.username]
        if not mine:
            print("No record found to export.")
            return
        rec = mine[0]
        filename = f"{self.user.username}_pii_export.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write("Your PII Data Export\n")
            f.write("====================\n\n")
            f.write(f"Username: {rec.get('username')}\n")
            f.write(f"Full Name: {rec.get('name')}\n")
            f.write(f"Phone: {rec.get('phone')}\n")
            f.write(f"TFN: {rec.get('tfn')}\n")
            f.write(f"Credit Card: {rec.get('credit_card')}\n")
            f.write(f"Email: {rec.get('email')}\n")
            f.write(f"Notes: {rec.get('notes')}\n")
        audit(self.user.username, "export_my_data", f"file={filename}")
        print(f"Your data has been exported to {filename}")


# ======================================================================
# AuthSystem – top level controller
# ======================================================================

class AuthSystem:
    """
    Top-level controller that ties together PiiSecure, UserManager and menus.

    - Prompts for the master encryption password.
    - Ensures an initial admin exists.
    - Runs the login loop and dispatches to the appropriate menu class.
    """

    def __init__(self, users_file: str, pii_file: str):
        self.users_manager = UserManager(users_file)

        print("Secure PII Storage System with RBAC\n-----------------------------------")
        master_pw = getpass("Enter master encryption password: ")
        self.pii_store = PiiSecure(pii_file, master_pw)

        # Make sure at least one admin exists (and one super admin).
        self.users_manager.ensure_initial_admin()

    def run(self) -> None:
        """
        Run the main login → menu → logout loop.
        """
        while True:
            user = self.users_manager.login()
            if user is None:
                ans = input(
                    "Press Enter to try login again, or type 'exit' to quit: "
                ).strip().lower()
                if ans == "exit":
                    print("Exiting program.")
                    break
                continue

            # Route to the correct menu.
            if user.role == "admin":
                menu = AdminMenu(user, self.users_manager, self.pii_store)
            elif user.role == "manager":
                menu = ManagerMenu(user, self.users_manager, self.pii_store)
            elif user.role == "employee":
                menu = EmployeeMenu(user, self.users_manager, self.pii_store)
            else:
                menu = UserMenu(user, self.users_manager, self.pii_store)

            menu.run()
            # After menu.run() returns, loop back to login again.


# ======================================================================
# Entry point
# ======================================================================

def main() -> None:
    system = AuthSystem(USERS_FILE, PII_FILE)
    system.run()


if __name__ == "__main__":
    main()
