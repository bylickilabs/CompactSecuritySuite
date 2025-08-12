# Usage Guide – Compact Security Suite

## Introduction
**Compact Security Suite** is a desktop application for hashing, encryption/decryption, secure deletion, and ZIP archive management.

---

## Features Overview
1. **Hashing** – Compute MD5, SHA1, SHA256, or SHA512 checksums for files.
2. **Encryption/Decryption** – Secure files with AES-256-GCM (scrypt KDF).
3. **Secure Delete** – Overwrite files with 1-pass or DoD 3-pass method.
4. **ZIP Tools** – Create and extract ZIP archives.

---

## Installation
1. Install Python 3.10+ and Tkinter.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   python app.py
   ```

---

## Using the Application

### Hashing
1. Select the **Hash** tab.
2. Choose a file and hashing algorithm.
3. Click **Start** to compute the hash.

### Encryption
1. Select the **Encrypt** tab.
2. Choose the input file and target `.enc` file.
3. Enter a strong password and click **Start**.

### Decryption
1. Select the **Decrypt** tab.
2. Choose the `.enc` file and target output.
3. Enter the password and click **Start**.

### Secure Delete
1. Select the **Secure Delete** tab.
2. Choose a file and deletion method.
3. Click **Shred/Delete**.

### ZIP
1. Select the **ZIP** tab.
2. Add files/folders to include.
3. Set output ZIP path and click **Create**.
4. For extraction, choose ZIP file and output directory, then click **Extract**.

---

## Support
- **Email**: `bylicki@mail.de`
- **GitHub Issues**: [Create an Issue](../../issues)
