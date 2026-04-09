# Spectre — Anonymous Secure Reporting System

## What is Spectre?

Spectre is a client-side reporting system that allows users to submit sensitive reports (fraud, harassment, misconduct) anonymously.

All data is encrypted in the browser before storage. The system never stores decryption keys, only their hashes.

---

## Key Features

* **End-to-End Encryption**
  Uses AES-256-GCM to encrypt reports on the client side.

* **Key-Based Access**
  Each report has a unique key. Without it, decryption is impossible.

* **Anonymous Reporting**
  No login required. No tracking or server-side logging.

* **Tamper Detection**
  Merkle tree structure ensures report integrity.

* **Dead Man’s Switch**
  Reports auto-release if the reporter becomes inactive.

* **Investigator Panel**
  Login-based access to view, decrypt, and manage reports.

---

## How It Works

### Reporter Flow

1. Verify identity (demo step)
2. Submit report with optional evidence
3. System:

   * Generates AES key
   * Encrypts report
   * Stores encrypted data
4. User receives:

   * Report ID
   * Secret key (must be saved)

Loss of key means permanent loss of access.

---

### Investigator Flow

1. Login with credentials
2. View report list
3. Enter key to decrypt
4. Access report details and files
5. Update status and add notes

---

## Tech Stack

* Frontend: Vanilla JavaScript
* Crypto: Web Crypto API
* Storage: localStorage (demo)
* Encryption: AES-256-GCM
* Hashing: SHA-256

---

## Project Structure

```
/index.html
/styles.css
/app.js
/db.js
```

---

## Security Highlights

* Strong encryption (AES-256-GCM)
* No plaintext key storage
* Constant-time comparisons
* Tamper detection via Merkle tree

---

## Limitations

* Uses localStorage (not secure for production)
* No backend or database
* Basic authentication system
* Demo-level identity verification

This is a prototype, not production-ready.

---

## Demo Credentials

Email: [investigator@spectre.internal](mailto:investigator@spectre.internal)
Password: investigator123

---

## Reality Check

This project shows solid understanding of cryptography and system design.

But it is still:

* A frontend-only prototype
* Not deployable in its current form

If you present it honestly as a secure prototype, it works.
If you oversell it, it will fall apart under questioning.
