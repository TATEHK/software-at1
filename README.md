Overview

This project is a secure, role-based PII (Personally Identifiable Information) management system designed for educational purposes. It demonstrates:

Defensive input validation

Secure password handling

Encrypted storage of sensitive PII

Role-based access control (RBAC)

Multi-role menu interfaces

Audit logging

Account lifecycle management

Separation of duties and privilege boundaries

The system runs entirely in a terminal and saves all user accounts, encrypted PII, and logs locally.

Features
🔐 Security Features

PII encryption using password-derived keys (PBKDF2-HMAC-SHA256).

MAC (HMAC-SHA256) for tamper detection.

Hashed passwords (PBKDF2-HMAC-SHA256 + per-user salts).

Failed login lockout:

5 failed attempts → 5-minute lock.

Audit logging of all security-relevant events.

🧑‍💼 Role-Based Access Control (RBAC)

Roles control access throughout the system:

Role	Permissions
Admin	Full system access. Create accounts, manage roles, reset passwords, delete accounts + PII. Super-admin required to reset other admins.
Manager	Create employees and PII users, edit/view all records, delete employee/user accounts.
Employee	Create PII records, edit/view all records.
User	End-user access to their own record only. View, edit, export, change password.

Additional rules:

First admin created automatically → flagged as super admin.

Only super admin may reset passwords for other admins.

Cannot demote or delete the last admin.

🗂 Account Lifecycle Features

Staff account creation (admin/manager/employee).

User account auto-creation when PII is created.

Auto-generated passwords for new accounts.

Welcome files, role-update files, deletion reports, and password-reset files generated automatically.

Users can update their own passwords.

🧾 PII Features

Create, edit, delete PII records.

All PII encrypted on disk.

Pretty card-style viewing.

Per-user export file (username_pii_export.txt).

Search PII by username/name/email/phone.
