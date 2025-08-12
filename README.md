# Compact Security Suite

|[Logo][./assets/logo.png]|
|---|

## Overview (EN)
**Compact Security Suite** is a lean desktop application designed for essential security workflows.  
It integrates hashing, AES-256-GCM encryption/decryption, secure file deletion, and ZIP archive management, all within a bilingual (EN/DE) GUI built with Tkinter.

### Features
- **Hashing:** MD5, SHA1, SHA256, SHA512 with progress display
- **Encryption:** AES-256-GCM with scrypt KDF (salt) and nonce
- **Decryption:** Secure .enc container parsing with authentication tag verification
- **Secure Delete:** 1-pass overwrite or DoD 5220.22-M (3-pass)
- **ZIP Tools:** Create and extract archives using Python's standard library
- **Full DE/EN language switch** without restart
- **GitHub button** linking to [bylickilabs](https://github.com/bylickilabs)
- **Threaded execution** to keep GUI responsive

### Technical Details
- **KDF:** `Scrypt (N=2^15, r=8, p=1)` → 256-bit AES key
- **Encryption:** AES-GCM with 96-bit nonce
- **Container format (.enc):**
  ```
  Offset  Size   Field
  0       4      MAGIC = 'BSEC'
  4       1      VERSION = 1
  5       1      SALT_LEN
  6       1      NONCE_LEN
  7       n      SALT
  7+n     m      NONCE
  ...     rest   CIPHERTEXT (includes GCM tag)
  ```

### Installation
```bash
pip install -r requirements.txt
python app.py
```

### Security Notes
- AES-GCM is authenticated; wrong passwords produce a clean failure.
- On SSD/NVMe, physical overwrite cannot be fully guaranteed due to wear-leveling/TRIM.
- No telemetry, no external network connections in core logic.

<br>

---

<br>

## Überblick (DE)
**Compact Security Suite** ist eine schlanke Desktop-Anwendung für zentrale Sicherheits-Workflows.  
Sie vereint Hashing, AES-256-GCM Verschlüsselung/Entschlüsselung, sicheres Löschen und ZIP-Archivverwaltung in einer zweisprachigen (DE/EN) Tkinter-Oberfläche.

### Funktionen
- **Hashing:** MD5, SHA1, SHA256, SHA512 mit Fortschrittsanzeige
- **Verschlüsselung:** AES-256-GCM mit scrypt KDF (Salt) und Nonce
- **Entschlüsselung:** Sicheres .enc-Containerformat mit Authentifizierungs-Tag-Überprüfung
- **Sicheres Löschen:** 1-Pass-Überschreiben oder DoD 5220.22-M (3-Pass)
- **ZIP-Tools:** Erstellen und Entpacken von Archiven mit Python-Standardbibliothek
- **Vollständige DE/EN-Sprachauswahl** ohne Neustart
- **GitHub-Button** mit Link zu [bylickilabs](https://github.com/bylickilabs)
- **Threaded Tasks** für reaktionsfähige GUI

### Technische Details
- **KDF:** `Scrypt (N=2^15, r=8, p=1)` → 256-bit AES-Schlüssel
- **Verschlüsselung:** AES-GCM mit 96-bit Nonce
- **Containerformat (.enc):**
  ```
  Offset  Größe  Feld
  0       4      MAGIC = 'BSEC'
  4       1      VERSION = 1
  5       1      SALT_LEN
  6       1      NONCE_LEN
  7       n      SALT
  7+n     m      NONCE
  ...     Rest   CIPHERTEXT (inkl. GCM-Tag)
  ```

### Installation
```bash
pip install -r requirements.txt
python app.py
```

### Sicherheitshinweise
- AES-GCM ist authentifiziert; falsche Passwörter führen zu einer klaren Fehlermeldung.
- Auf SSD/NVMe kann physisches Überschreiben aufgrund von Wear-Leveling/TRIM nicht garantiert werden.
- Keine Telemetrie, keine externen Netzwerkzugriffe in der Kernlogik.
