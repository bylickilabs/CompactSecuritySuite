import os
import hashlib
import zipfile
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from threading import Thread
from queue import Queue
from pathlib import Path
import secrets
import struct
import webbrowser

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APP_NAME = "Compact Security Suite"
APP_VERSION = "1.0.0"
APP_AUTHOR = "| ©Thorsten Bylicki | ©BYLICKILABS"
APP_TITLE_DE = " – Kompakte Sicherheit mit Hashing, Verschlüsselung und Löschfunktionen"
APP_TITLE_EN = " – Compact security with hashing, encryption and deletion features"

GITHUB_URL = "https://github.com/bylickilabs"

LANG = {
    "de": {
        "app_title": f"{APP_NAME} v{APP_VERSION} {APP_AUTHOR} {APP_TITLE_DE}",
        "ready": "Bereit.",
        "info": "Info",
        "language": "Sprache",
        "lang_de": "Deutsch",
        "lang_en": "Englisch",
        "github": "GitHub",
        "tab_hash": "Hash",
        "tab_encrypt": "Verschlüsseln",
        "tab_decrypt": "Entschlüsseln",
        "tab_shred": "Sicher löschen",
        "tab_zip": "ZIP",
        "hash_group": "Datei hashen",
        "btn_file": "Datei...",
        "btn_start": "Start",
        "hash_result": "Ergebnis",
        "enc_group": "Datei verschlüsseln (AES-256-GCM)",
        "pwd_group": "Passwort",
        "dec_group": "Datei entschlüsseln (.enc)",
        "btn_input": "Eingabe...",
        "btn_output": "Ziel...",
        "btn_run": "Start",
        "shred_group": "Sicheres Löschen",
        "shred_btn": "Löschen",
        "shred_note": "Hinweis: Auf SSDs/NVMe kann physisches Überschreiben wegen Wear-Leveling/Trim nicht garantiert werden.",
        "zip_make_group": "ZIP erstellen",
        "zip_add": "Datei/Ordner hinzufügen...",
        "zip_target": "Ziel...",
        "zip_create": "Erstellen",
        "zip_extract_group": "ZIP entpacken",
        "zip_pick": "ZIP...",
        "zip_outdir": "Zielordner...",
        "zip_extract": "Entpacken",
        "dlg_title_error": "Fehler",
        "dlg_title_confirm": "Bestätigen",
        "err_pick_valid": "Bitte eine gültige Datei wählen.",
        "err_input_invalid": "Eingabedatei ungültig.",
        "err_password_req": "Passwort erforderlich.",
        "confirm_shred": "Sicher löschen: {name} ({method})?",
        "status_hash": "Hashing {name} mit {algo}...",
        "status_encrypt": "Verschlüssele {name}...",
        "status_decrypt": "Entschlüssele {name}...",
        "status_shred": "Lösche sicher: {name}...",
        "status_zip_create": "ZIP erstellen: {name}...",
        "status_zip_extract": "ZIP entpacken: {name}...",
        "log_hash": "[Hash] {algo}({name}) = {digest}",
        "log_size": "[Hash] Größe: {size}",
        "log_enc_ok": "[Enc] OK: {name}",
        "log_dec_ok": "[Dec] OK: {name}",
        "log_dec_err_title": "Entschlüsselung fehlgeschlagen",
        "log_dec_err": "[Dec] Fehler: {err}",
        "log_zip_add": "[ZIP] + {name}",
        "log_zip_make": "[ZIP] Erstelle: {name}",
        "log_zip_done": "[ZIP] Fertig.",
        "log_zip_extract": "[ZIP] Entpacke: {src} → {dst}",
        "info_text": (
            f"{APP_NAME} v{APP_VERSION}\n\n"
            "- Hashing: MD5, SHA1, SHA256, SHA512\n"
            "- Verschlüsselung: AES-256-GCM (scrypt KDF, Salt/Nonce)\n"
            "- Entschlüsselung: .enc-Container\n"
            "- Sicheres Löschen: 1-Pass, DoD 3-Pass\n"
            "- ZIP: Erstellen & Entpacken\n\n"
            "Hinweis: AES-GCM ist authentifiziert. Falsches Passwort führt zu einem klaren Fehler."
        ),
        "algo_label": "Algorithmus:",
        "enc_pwd_placeholder": "Passwort",
        "dec_pwd_placeholder": "Passwort",
        "save_dialog_title": "Zieldatei",
        "open_dialog_title": "Datei auswählen",
        "open_dialog_enc_in": "Eingabedatei",
        "open_dialog_dec_in": "Verschlüsselte Datei",
        "zip_dialog_pick": "ZIP wählen",
        "zip_dialog_save": "ZIP speichern",
        "zip_dialog_folder": "Zielordner",
        "zip_err_invalid": "ZIP-Datei ungültig.",
        "zip_err_outdir": "Zielordner nicht erstellbar: {err}",
        "shred_method_1": "1-Pass (0x00)",
        "shred_method_dod": "DoD 5220.22-M (3-Pass)",
        "activity_log": "Aktivitätsprotokoll",
    },
    "en": {
        "app_title": f"{APP_NAME} v{APP_VERSION} {APP_AUTHOR} {APP_TITLE_EN}",
        "ready": "Ready.",
        "info": "Info",
        "language": "Language",
        "lang_de": "German",
        "lang_en": "English",
        "github": "GitHub",
        "tab_hash": "Hash",
        "tab_encrypt": "Encrypt",
        "tab_decrypt": "Decrypt",
        "tab_shred": "Secure Delete",
        "tab_zip": "ZIP",
        "hash_group": "Hash a file",
        "btn_file": "File...",
        "btn_start": "Start",
        "hash_result": "Result",
        "enc_group": "Encrypt file (AES-256-GCM)",
        "pwd_group": "Password",
        "dec_group": "Decrypt file (.enc)",
        "btn_input": "Input...",
        "btn_output": "Target...",
        "btn_run": "Run",
        "shred_group": "Secure deletion",
        "shred_btn": "Shred",
        "shred_note": "Note: On SSDs/NVMe, physical overwriting cannot be guaranteed (wear-leveling/TRIM).",
        "zip_make_group": "Create ZIP",
        "zip_add": "Add files/folders...",
        "zip_target": "Target...",
        "zip_create": "Create",
        "zip_extract_group": "Extract ZIP",
        "zip_pick": "ZIP...",
        "zip_outdir": "Output folder...",
        "zip_extract": "Extract",
        "dlg_title_error": "Error",
        "dlg_title_confirm": "Confirm",
        "err_pick_valid": "Please choose a valid file.",
        "err_input_invalid": "Invalid input file.",
        "err_password_req": "Password required.",
        "confirm_shred": "Securely delete: {name} ({method})?",
        "status_hash": "Hashing {name} with {algo}...",
        "status_encrypt": "Encrypting {name}...",
        "status_decrypt": "Decrypting {name}...",
        "status_shred": "Securely deleting: {name}...",
        "status_zip_create": "Creating ZIP: {name}...",
        "status_zip_extract": "Extracting ZIP: {name}...",
        "log_hash": "[Hash] {algo}({name}) = {digest}",
        "log_size": "[Hash] Size: {size}",
        "log_enc_ok": "[Enc] OK: {name}",
        "log_dec_ok": "[Dec] OK: {name}",
        "log_dec_err_title": "Decryption failed",
        "log_dec_err": "[Dec] Error: {err}",
        "log_zip_add": "[ZIP] + {name}",
        "log_zip_make": "[ZIP] Creating: {name}",
        "log_zip_done": "[ZIP] Done.",
        "log_zip_extract": "[ZIP] Extract: {src} → {dst}",
        "info_text": (
            f"{APP_NAME} v{APP_VERSION}\n\n"
            "- Hashing: MD5, SHA1, SHA256, SHA512\n"
            "- Encryption: AES-256-GCM (scrypt KDF, salt/nonce)\n"
            "- Decryption: .enc container\n"
            "- Secure delete: 1-pass, DoD 3-pass\n"
            "- ZIP: create & extract\n\n"
            "Note: AES-GCM is authenticated. Wrong password yields a clean error."
        ),
        "algo_label": "Algorithm:",
        "enc_pwd_placeholder": "Password",
        "dec_pwd_placeholder": "Password",
        "save_dialog_title": "Save as",
        "open_dialog_title": "Choose a file",
        "open_dialog_enc_in": "Input file",
        "open_dialog_dec_in": "Encrypted file",
        "zip_dialog_pick": "Pick ZIP",
        "zip_dialog_save": "Save ZIP",
        "zip_dialog_folder": "Output folder",
        "zip_err_invalid": "Invalid ZIP file.",
        "zip_err_outdir": "Cannot create output folder: {err}",
        "shred_method_1": "1-Pass (0x00)",
        "shred_method_dod": "DoD 5220.22-M (3-Pass)",
        "activity_log": "Activity Log",
    },
}

def human_size(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024:
            return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} PB"

def iter_files_rec(path: Path):
    if path.is_file():
        yield path
    else:
        for root, _, files in os.walk(path):
            for f in files:
                yield Path(root) / f

HASH_ALGOS = {
    "MD5": hashlib.md5,
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}

def hash_file(path: Path, algo_name: str, chunk=1024 * 1024):
    h = HASH_ALGOS[algo_name]()
    total = path.stat().st_size
    processed = 0
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
            processed += len(b)
            yield ("progress", processed, total)
    yield ("done", h.hexdigest())

MAGIC = b"BSEC"
FORMAT_VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))

def encrypt_file(in_path: Path, out_path: Path, password: str, chunk=1024 * 1024):
    salt = secrets.token_bytes(SALT_LEN)
    key = derive_key(password, salt)
    aes = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_LEN)

    data = b""
    total = in_path.stat().st_size
    processed = 0
    with open(in_path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            data += b
            processed += len(b)
            yield ("progress", processed, total)

    ct = aes.encrypt(nonce, data, None)
    with open(out_path, "wb") as o:
        o.write(MAGIC)
        o.write(struct.pack("BBB", FORMAT_VERSION, SALT_LEN, NONCE_LEN))
        o.write(salt)
        o.write(nonce)
        o.write(ct)
    yield ("done", out_path)

def decrypt_file(in_path: Path, out_path: Path, password: str):
    with open(in_path, "rb") as f:
        header = f.read(4)
        if header != MAGIC:
            raise ValueError("Invalid container (MAGIC).")
        ver, salt_len, nonce_len = struct.unpack("BBB", f.read(3))
        if ver != FORMAT_VERSION:
            raise ValueError("Unsupported container version.")
        salt = f.read(salt_len)
        nonce = f.read(nonce_len)
        ct = f.read()

    key = derive_key(password, salt)
    aes = AESGCM(key)
    data = aes.decrypt(nonce, ct, None)
    with open(out_path, "wb") as o:
        o.write(data)
    return out_path

def secure_delete(path: Path, method: str, queue: Queue, chunk=1024 * 1024):
    if not path.exists():
        queue.put(("log", f"[Shred] Missing: {path}"))
        return
    size = path.stat().st_size

    def overwrite(pattern: bytes, label: str):
        nonlocal path, size
        queue.put(("log", f"[Shred] Pass: {label}"))
        with open(path, "r+b") as f:
            written = 0
            while written < size:
                to_write = min(chunk, size - written)
                f.write(pattern * (to_write // len(pattern)) + pattern[: to_write % len(pattern)])
                written += to_write
        try:
            os.sync()
        except Exception:
            pass

    if "1-Pass" in method:
        overwrite(b"\x00", "1/1")
    else:
        overwrite(b"\x00", "1/3")
        overwrite(b"\xFF", "2/3")
        with open(path, "r+b") as f:
            written = 0
            while written < size:
                to_write = min(chunk, size - written)
                f.write(secrets.token_bytes(to_write))
                written += to_write
        try:
            os.sync()
        except Exception:
            pass

    try:
        with open(path, "r+b") as f:
            f.truncate(0)
    except Exception:
        pass
    try:
        os.remove(path)
        queue.put(("log", "[Shred] Deleted."))
    except Exception as e:
        queue.put(("log", f"[Shred] Remove failed: {e}"))

def zip_create(target_zip: Path, sources: list[Path], queue: Queue):
    queue.put(("log", f"[ZIP] Creating: {target_zip}"))
    with zipfile.ZipFile(target_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for src in sources:
            if src.is_file():
                zf.write(src, arcname=src.name)
                queue.put(("log", f"[ZIP] + {src.name}"))
            else:
                for f in iter_files_rec(src):
                    arc = f.relative_to(src.parent)
                    zf.write(f, arcname=str(arc))
                    queue.put(("log", f"[ZIP] + {arc}"))
    queue.put(("log", "[ZIP] Done."))

def zip_extract(zip_path: Path, out_dir: Path, queue: Queue):
    queue.put(("log", f"[ZIP] Extract: {zip_path} → {out_dir}"))
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(out_dir)
    queue.put(("log", "[ZIP] Done."))

class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.lang = "de"
        self.tr = LANG[self.lang]

        root.title(self.tr["app_title"])
        root.geometry("1020x690")
        root.minsize(980, 640)

        self.queue = Queue()
        self._build_ui()
        self._poll_queue()

    def _apply_i18n(self):
        self.tr = LANG[self.lang]
        self.root.title(self.tr["app_title"])

        self.lbl_title.config(text=self.tr["app_title"])
        self.lbl_lang.config(text=self.tr["language"])
        self.btn_info.config(text=self.tr["info"])
        self.btn_github.config(text=self.tr["github"])
        self.nb.tab(self.tab_hash, text=self.tr["tab_hash"])
        self.nb.tab(self.tab_encrypt, text=self.tr["tab_encrypt"])
        self.nb.tab(self.tab_decrypt, text=self.tr["tab_decrypt"])
        self.nb.tab(self.tab_shred, text=self.tr["tab_shred"])
        self.nb.tab(self.tab_zip, text=self.tr["tab_zip"])
        self.grp_hash.config(text=self.tr["hash_group"])
        self.btn_hash_file.config(text=self.tr["btn_file"])
        self.lbl_algo.config(text=self.tr["algo_label"])
        self.btn_hash_start.config(text=self.tr["btn_start"])
        self.grp_hash_result.config(text=self.tr["hash_result"])
        self.grp_enc.config(text=self.tr["enc_group"])
        self.btn_enc_in.config(text=self.tr["btn_input"])
        self.btn_enc_out.config(text=self.tr["btn_output"])
        self.grp_enc_pwd.config(text=self.tr["pwd_group"])
        self.entry_enc_pwd.configure()
        self.btn_enc_run.config(text=self.tr["btn_run"])
        self.grp_dec.config(text=self.tr["dec_group"])
        self.btn_dec_in.config(text=self.tr["btn_input"])
        self.btn_dec_out.config(text=self.tr["btn_output"])
        self.grp_dec_pwd.config(text=self.tr["pwd_group"])
        self.btn_dec_run.config(text=self.tr["btn_run"])
        self.grp_shred.config(text=self.tr["shred_group"])
        self.btn_shred_file.config(text=self.tr["btn_file"])
        self.cmb_shred_method.config(values=[self.tr["shred_method_1"], self.tr["shred_method_dod"]])
        if self.cmb_shred_method.get() not in self.cmb_shred_method["values"]:
            self.cmb_shred_method.current(1)
        self.btn_shred_run.config(text=self.tr["shred_btn"])
        self.lbl_shred_note.config(text=self.tr["shred_note"])
        self.grp_zip_make.config(text=self.tr["zip_make_group"])
        self.btn_zip_add.config(text=self.tr["zip_add"])
        self.btn_zip_target.config(text=self.tr["zip_target"])
        self.btn_zip_create.config(text=self.tr["zip_create"])
        self.grp_zip_extract.config(text=self.tr["zip_extract_group"])
        self.btn_zip_in.config(text=self.tr["zip_pick"])
        self.btn_zip_outdir.config(text=self.tr["zip_outdir"])
        self.btn_zip_extract.config(text=self.tr["zip_extract"])
        self.grp_log.config(text=self.tr["activity_log"])
        self.status.set(self.tr["ready"])
        self.cmb_lang.config(values=[self.tr["lang_de"], self.tr["lang_en"]])
        self._sync_lang_combo_label()

    def _sync_lang_combo_label(self):
        if self.lang == "de":
            self.cmb_lang.set(self.tr["lang_de"])
        else:
            self.cmb_lang.set(self.tr["lang_en"])

    def _set_lang_from_combo(self, _evt=None):
        val = self.cmb_lang.get().strip().lower()
        if val in ["deutsch", "german"]:
            self.lang = "de"
        elif val in ["englisch", "english"]:
            self.lang = "en"
        self._apply_i18n()

    def _build_ui(self):
        header = ttk.Frame(self.root)
        header.pack(fill="x", padx=10, pady=8)
        self.lbl_title = ttk.Label(header, text=self.tr["app_title"], font=("Segoe UI", 12, "bold"))        
        header_right = ttk.Frame(header)
        header_right.pack(side="right")
        self.btn_github = ttk.Button(header_right, text=self.tr["github"], command=lambda: webbrowser.open(GITHUB_URL))
        self.btn_github.pack(side="right", padx=(6, 0))
        self.btn_info = ttk.Button(header_right, text=self.tr["info"], command=self._show_info)
        self.btn_info.pack(side="right", padx=(6, 6))
        self.lbl_lang = ttk.Label(header_right, text=self.tr["language"])
        self.lbl_lang.pack(side="left", padx=(0, 6))
        self.cmb_lang = ttk.Combobox(header_right, state="readonly", width=12)
        self.cmb_lang.pack(side="left")
        self.cmb_lang.bind("<<ComboboxSelected>>", self._set_lang_from_combo)
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=10, pady=(0,10))
        self._build_tab_hash()
        self._build_tab_encrypt()
        self._build_tab_decrypt()
        self._build_tab_shred()
        self._build_tab_zip()
        self.grp_log = ttk.LabelFrame(self.root, text=self.tr["activity_log"])
        self.grp_log.pack(fill="both", expand=False, padx=10, pady=(0,10))
        self.log = tk.Text(self.grp_log, height=8)
        self.log.pack(fill="both", expand=True)
        self.log.configure(state="disabled")
        self.status = tk.StringVar(value=self.tr["ready"])
        sbar = ttk.Label(self.root, textvariable=self.status, anchor="w")
        sbar.pack(fill="x", padx=10, pady=(0,8))
        self._apply_i18n()

    def _log(self, msg: str):
        self.log.configure(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _poll_queue(self):
        try:
            while True:
                item = self.queue.get_nowait()
                kind = item[0]
                if kind == "log":
                    self._log(item[1])
                elif kind == "status":
                    self.status.set(item[1])
                elif kind == "progress":
                    tab, value, maxv = item[1], item[2], item[3]
                    if tab == "hash":
                        self.hash_prog["maximum"] = maxv
                        self.hash_prog["value"] = value
                    elif tab == "enc":
                        self.enc_prog["maximum"] = maxv
                        self.enc_prog["value"] = value
        except Exception:
            pass
        self.root.after(100, self._poll_queue)

    def _show_info(self):
        messagebox.showinfo(self.tr["info"], self.tr["info_text"])

    def _build_tab_hash(self):
        self.tab_hash = ttk.Frame(self.nb)
        self.nb.add(self.tab_hash, text=self.tr["tab_hash"])
        self.grp_hash = ttk.LabelFrame(self.tab_hash, text=self.tr["hash_group"])
        self.grp_hash.pack(fill="x", padx=10, pady=10)
        self.hash_path = tk.StringVar()
        ttk.Entry(self.grp_hash, textvariable=self.hash_path).pack(side="left", fill="x", expand=True, padx=(10,6), pady=10)
        self.btn_hash_file = ttk.Button(self.grp_hash, text=self.tr["btn_file"], command=self._pick_hash_file)
        self.btn_hash_file.pack(side="left", padx=(0,6))
        algoframe = ttk.Frame(self.grp_hash)
        algoframe.pack(side="left", padx=(0,6))
        self.lbl_algo = ttk.Label(algoframe, text=self.tr["algo_label"])
        self.lbl_algo.pack(side="left", padx=(0,6))
        self.hash_algo = tk.StringVar(value="SHA256")
        self.cmb_hash_algo = ttk.Combobox(algoframe, values=list(HASH_ALGOS.keys()), textvariable=self.hash_algo, state="readonly", width=10)
        self.cmb_hash_algo.pack(side="left")
        self.btn_hash_start = ttk.Button(self.grp_hash, text=self.tr["btn_start"], command=self._run_hash)
        self.btn_hash_start.pack(side="left", padx=(6,10))
        self.grp_hash_result = ttk.LabelFrame(self.tab_hash, text=self.tr["hash_result"])
        self.grp_hash_result.pack(fill="x", padx=10, pady=(0,10))
        self.hash_out = tk.Text(self.grp_hash_result, height=4)
        self.hash_out.pack(fill="x", padx=10, pady=10)
        self.hash_prog = ttk.Progressbar(self.tab_hash, mode="determinate")
        self.hash_prog.pack(fill="x", padx=10, pady=(0,10))

    def _pick_hash_file(self):
        title = self.tr["open_dialog_title"]
        p = filedialog.askopenfilename(title=title)
        if p:
            self.hash_path.set(p)

    def _run_hash(self):
        path = Path(self.hash_path.get())
        algo = self.hash_algo.get()
        if not path.exists() or not path.is_file():
            messagebox.showerror(self.tr["dlg_title_error"], self.tr["err_pick_valid"])
            return
        self.hash_out.delete("1.0", "end")
        self.hash_prog["value"] = 0

        def worker():
            self.queue.put(("status", self.tr["status_hash"].format(name=path.name, algo=algo)))
            for evt in hash_file(path, algo):
                if evt[0] == "progress":
                    _, done, total = evt
                    self.queue.put(("progress", ("hash", done, total)))
                else:
                    _, hexd = evt
                    self.queue.put(("log", self.tr["log_hash"].format(algo=algo, name=path.name, digest=hexd)))
                    self.queue.put(("status", self.tr["ready"]))
                    self.queue.put(("log", self.tr["log_size"].format(size=human_size(path.stat().st_size))))
                    self.root.after(0, lambda v=hexd: self.hash_out.insert("end", v))

        Thread(target=worker, daemon=True).start()

    def _build_tab_encrypt(self):
        self.tab_encrypt = ttk.Frame(self.nb)
        self.nb.add(self.tab_encrypt, text=self.tr["tab_encrypt"])
        self.grp_enc = ttk.LabelFrame(self.tab_encrypt, text=self.tr["enc_group"])
        self.grp_enc.pack(fill="x", padx=10, pady=10)
        self.enc_in = tk.StringVar()
        self.enc_out = tk.StringVar()
        ttk.Entry(self.grp_enc, textvariable=self.enc_in).pack(side="left", fill="x", expand=True, padx=(10,6), pady=10)
        self.btn_enc_in = ttk.Button(self.grp_enc, text=self.tr["btn_input"], command=self._pick_enc_in)
        self.btn_enc_in.pack(side="left", padx=(0,6))
        ttk.Entry(self.grp_enc, textvariable=self.enc_out, width=42).pack(side="left", padx=(0,6))
        self.btn_enc_out = ttk.Button(self.grp_enc, text=self.tr["btn_output"], command=self._pick_enc_out)
        self.btn_enc_out.pack(side="left", padx=(0,6))
        self.grp_enc_pwd = ttk.LabelFrame(self.tab_encrypt, text=self.tr["pwd_group"])
        self.grp_enc_pwd.pack(fill="x", padx=10, pady=(0,10))
        self.enc_pw = tk.StringVar()
        self.entry_enc_pwd = ttk.Entry(self.grp_enc_pwd, textvariable=self.enc_pw, show="•")
        self.entry_enc_pwd.pack(side="left", fill="x", expand=True, padx=10, pady=10)
        self.btn_enc_run = ttk.Button(self.grp_enc_pwd, text=self.tr["btn_run"], command=self._run_encrypt)
        self.btn_enc_run.pack(side="left", padx=10)
        self.enc_prog = ttk.Progressbar(self.tab_encrypt, mode="determinate")
        self.enc_prog.pack(fill="x", padx=10, pady=(0,10))

    def _pick_enc_in(self):
        p = filedialog.askopenfilename(title=self.tr["open_dialog_enc_in"])
        if p:
            self.enc_in.set(p)
            self.enc_out.set(p + ".enc")

    def _pick_enc_out(self):
        p = filedialog.asksaveasfilename(title=self.tr["save_dialog_title"], defaultextension=".enc",
                                         filetypes=[("Encrypted", "*.enc"), ("All", "*.*")])
        if p:
            self.enc_out.set(p)

    def _run_encrypt(self):
        in_p = Path(self.enc_in.get()); out_p = Path(self.enc_out.get()); pw = self.enc_pw.get()
        if not in_p.exists() or not in_p.is_file():
            messagebox.showerror(self.tr["dlg_title_error"], self.tr["err_input_invalid"])
            return
        if not pw:
            messagebox.showerror(self.tr["dlg_title_error"], self.tr["err_password_req"])
            return

        def worker():
            self.queue.put(("status", self.tr["status_encrypt"].format(name=in_p.name)))
            for evt in encrypt_file(in_p, out_p, pw):
                if evt[0] == "progress":
                    _, done, total = evt
                    self.queue.put(("progress", ("enc", done, total)))
                else:
                    _, outpath = evt
                    self.queue.put(("log", self.tr["log_enc_ok"].format(name=Path(outpath).name)))
                    self.queue.put(("status", self.tr["ready"]))

        Thread(target=worker, daemon=True).start()

    def _build_tab_decrypt(self):
        self.tab_decrypt = ttk.Frame(self.nb)
        self.nb.add(self.tab_decrypt, text=self.tr["tab_decrypt"])
        self.grp_dec = ttk.LabelFrame(self.tab_decrypt, text=self.tr["dec_group"])
        self.grp_dec.pack(fill="x", padx=10, pady=10)
        self.dec_in = tk.StringVar()
        self.dec_out = tk.StringVar()
        ttk.Entry(self.grp_dec, textvariable=self.dec_in).pack(side="left", fill="x", expand=True, padx=(10,6), pady=10)
        self.btn_dec_in = ttk.Button(self.grp_dec, text=self.tr["btn_input"], command=self._pick_dec_in)
        self.btn_dec_in.pack(side="left", padx=(0,6))
        ttk.Entry(self.grp_dec, textvariable=self.dec_out, width=42).pack(side="left", padx=(0,6))
        self.btn_dec_out = ttk.Button(self.grp_dec, text=self.tr["btn_output"], command=self._pick_dec_out)
        self.btn_dec_out.pack(side="left", padx=(0,6))
        self.grp_dec_pwd = ttk.LabelFrame(self.tab_decrypt, text=self.tr["pwd_group"])
        self.grp_dec_pwd.pack(fill="x", padx=10, pady=(0,10))
        self.dec_pw = tk.StringVar()
        self.entry_dec_pwd = ttk.Entry(self.grp_dec_pwd, textvariable=self.dec_pw, show="•")
        self.entry_dec_pwd.pack(side="left", fill="x", expand=True, padx=10, pady=10)
        self.btn_dec_run = ttk.Button(self.grp_dec_pwd, text=self.tr["btn_run"], command=self._run_decrypt)
        self.btn_dec_run.pack(side="left", padx=10)

    def _pick_dec_in(self):
        p = filedialog.askopenfilename(title=self.tr["open_dialog_dec_in"], filetypes=[("Encrypted", "*.enc"), ("All", "*.*")])
        if p:
            self.dec_in.set(p)
            base = Path(p).with_suffix("")
            self.dec_out.set(str(base))

    def _pick_dec_out(self):
        p = filedialog.asksaveasfilename(title=self.tr["save_dialog_title"])
        if p:
            self.dec_out.set(p)

    def _run_decrypt(self):
        in_p = Path(self.dec_in.get()); out_p = Path(self.dec_out.get()); pw = self.dec_pw.get()
        if not in_p.exists() or not in_p.is_file():
            messagebox.showerror(self.tr["dlg_title_error"], self.tr["err_input_invalid"])
            return
        if not pw:
            messagebox.showerror(self.tr["dlg_title_error"], self.tr["err_password_req"])
            return

        def worker():
            try:
                self.queue.put(("status", self.tr["status_decrypt"].format(name=in_p.name)))
                res = decrypt_file(in_p, out_p, pw)
                self.queue.put(("log", self.tr["log_dec_ok"].format(name=res.name)))
            except Exception as e:
                self.queue.put(("log", self.tr["log_dec_err"].format(err=e)))
                messagebox.showerror(self.tr["log_dec_err_title"], str(e))
            finally:
                self.queue.put(("status", self.tr["ready"]))

        Thread(target=worker, daemon=True).start()

    def _build_tab_shred(self):
        self.tab_shred = ttk.Frame(self.nb)
        self.nb.add(self.tab_shred, text=self.tr["tab_shred"])
        self.grp_shred = ttk.LabelFrame(self.tab_shred, text=self.tr["shred_group"])
        self.grp_shred.pack(fill="x", padx=10, pady=10)
        self.shred_path = tk.StringVar()
        ttk.Entry(self.grp_shred, textvariable=self.shred_path).pack(side="left", fill="x", expand=True, padx=(10,6), pady=10)
        self.btn_shred_file = ttk.Button(self.grp_shred, text=self.tr["btn_file"], command=self._pick_shred_file)
        self.btn_shred_file.pack(side="left", padx=(0,6))
        self.cmb_shred_method = ttk.Combobox(self.grp_shred, state="readonly", width=28, values=[self.tr["shred_method_1"], self.tr["shred_method_dod"]])
        self.cmb_shred_method.current(1)
        self.cmb_shred_method.pack(side="left", padx=(0,6))
        self.btn_shred_run = ttk.Button(self.grp_shred, text=self.tr["shred_btn"], command=self._run_shred)
        self.btn_shred_run.pack(side="left", padx=(0,6))
        self.lbl_shred_note = ttk.Label(self.tab_shred, text=self.tr["shred_note"])
        self.lbl_shred_note.pack(anchor="w", padx=12)

    def _pick_shred_file(self):
        p = filedialog.askopenfilename(title=self.tr["open_dialog_title"])
        if p:
            self.shred_path.set(p)

    def _run_shred(self):
        path = Path(self.shred_path.get())
        method = self.cmb_shred_method.get()
        if not path.exists() or not path.is_file():
            messagebox.showerror(self.tr["dlg_title_error"], self.tr["err_pick_valid"])
            return
        if not messagebox.askyesno(self.tr["dlg_title_confirm"], self.tr["confirm_shred"].format(name=path.name, method=method)):
            return

        def worker():
            self.queue.put(("status", self.tr["status_shred"].format(name=path.name)))
            secure_delete(path, method, self.queue)
            self.queue.put(("status", self.tr["ready"]))

        Thread(target=worker, daemon=True).start()

    def _build_tab_zip(self):
        self.tab_zip = ttk.Frame(self.nb)
        self.nb.add(self.tab_zip, text=self.tr["tab_zip"])
        self.grp_zip_make = ttk.LabelFrame(self.tab_zip, text=self.tr["zip_make_group"])
        self.grp_zip_make.pack(fill="x", padx=10, pady=10)
        self.zip_sources = []
        self.zip_target = tk.StringVar()
        self.btn_zip_add = ttk.Button(self.grp_zip_make, text=self.tr["zip_add"], command=self._add_zip_sources)
        self.btn_zip_add.pack(side="left", padx=10, pady=10)
        ttk.Entry(self.grp_zip_make, textvariable=self.zip_target).pack(side="left", fill="x", expand=True, padx=(6,6))
        self.btn_zip_target = ttk.Button(self.grp_zip_make, text=self.tr["zip_target"], command=self._pick_zip_target)
        self.btn_zip_target.pack(side="left", padx=(0,6))
        self.btn_zip_create = ttk.Button(self.grp_zip_make, text=self.tr["zip_create"], command=self._run_zip_create)
        self.btn_zip_create.pack(side="left", padx=(0,10))
        self.zip_list = tk.Listbox(self.tab_zip, height=6)
        self.zip_list.pack(fill="both", expand=False, padx=10, pady=(0,10))
        self.grp_zip_extract = ttk.LabelFrame(self.tab_zip, text=self.tr["zip_extract_group"])
        self.grp_zip_extract.pack(fill="x", padx=10, pady=10)
        self.zip_in = tk.StringVar()
        self.zip_outdir = tk.StringVar()
        ttk.Entry(self.grp_zip_extract, textvariable=self.zip_in).pack(side="left", fill="x", expand=True, padx=(10,6), pady=10)
        self.btn_zip_in = ttk.Button(self.grp_zip_extract, text=self.tr["zip_pick"], command=self._pick_zip_in)
        self.btn_zip_in.pack(side="left", padx=(0,6))
        ttk.Entry(self.grp_zip_extract, textvariable=self.zip_outdir, width=32).pack(side="left", padx=(0,6))
        self.btn_zip_outdir = ttk.Button(self.grp_zip_extract, text=self.tr["zip_outdir"], command=self._pick_zip_outdir)
        self.btn_zip_outdir.pack(side="left", padx=(0,6))
        self.btn_zip_extract = ttk.Button(self.grp_zip_extract, text=self.tr["zip_extract"], command=self._run_zip_extract)
        self.btn_zip_extract.pack(side="left", padx=(0,6))

    def _add_zip_sources(self):
        files = filedialog.askopenfilenames(title=self.tr["open_dialog_title"])
        for f in files:
            self.zip_sources.append(Path(f))
            self.zip_list.insert("end", f)
        dir_ = filedialog.askdirectory(title=self.tr["open_dialog_title"])
        if dir_:
            self.zip_sources.append(Path(dir_))
            self.zip_list.insert("end", dir_)

    def _pick_zip_target(self):
        p = filedialog.asksaveasfilename(title=self.tr["zip_dialog_save"], defaultextension=".zip", filetypes=[("ZIP", "*.zip")])
        if p:
            self.zip_target.set(p)

    def _run_zip_create(self):
        if not self.zip_sources:
            messagebox.showerror(self.tr["dlg_title_error"], self.tr["err_pick_valid"])
            return
        if not self.zip_target.get():
            messagebox.showerror(self.tr["dlg_title_error"], self.tr["err_pick_valid"])
            return
        tzip = Path(self.zip_target.get())
        sources = list(self.zip_sources)

        def worker():
            self.queue.put(("status", self.tr["status_zip_create"].format(name=tzip.name)))
            self._log(self.tr["log_zip_make"].format(name=tzip))
            zip_create(tzip, sources, self.queue)
            self.queue.put(("status", self.tr["ready"]))

        Thread(target=worker, daemon=True).start()

    def _pick_zip_in(self):
        p = filedialog.askopenfilename(title=self.tr["zip_dialog_pick"], filetypes=[("ZIP", "*.zip"), ("All", "*.*")])
        if p:
            self.zip_in.set(p)

    def _pick_zip_outdir(self):
        d = filedialog.askdirectory(title=self.tr["zip_dialog_folder"])
        if d:
            self.zip_outdir.set(d)

    def _run_zip_extract(self):
        zin = Path(self.zip_in.get()); outd = Path(self.zip_outdir.get())
        if not zin.exists():
            messagebox.showerror(self.tr["dlg_title_error"], self.tr["zip_err_invalid"])
            return
        if not outd.exists():
            try:
                outd.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                messagebox.showerror(self.tr["dlg_title_error"], self.tr["zip_err_outdir"].format(err=e))
                return

        def worker():
            self.queue.put(("status", self.tr["status_zip_extract"].format(name=zin.name)))
            self._log(self.tr["log_zip_extract"].format(src=zin, dst=outd))
            zip_extract(zin, outd, self.queue)
            self.queue.put(("status", self.tr["ready"]))

        Thread(target=worker, daemon=True).start()

def main():
    root = tk.Tk()
    App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
