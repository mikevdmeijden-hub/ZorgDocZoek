# zorgdoczoek_v1.py
# ZorgDocZoek 1.0 — encrypted document database with password, categories, drag & drop and document viewer
# Created by Michael van der Meijden
# Requires: pip install cryptography python-docx PyPDF2

import os
import io
import re
import json
import sqlite3
import base64
import hashlib
import secrets
import tempfile
import subprocess
import platform
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from collections import Counter
from uuid import uuid4
from pathlib import Path

from docx import Document
from PyPDF2 import PdfReader

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

APP_NAME = "ZorgDocZoek"
APP_VERSION = "1.0"
APP_CREATOR = "Michael van der Meijden"
APP_TITLE = f"{APP_NAME} {APP_VERSION}"
DB_FILE = "knowledgebase_secure.db"
PBKDF2_ITERATIONS = 390000

# ---------- Crypto ----------
class CryptoManager:
    def __init__(self, password: str, salt_b64: str):
        salt = base64.urlsafe_b64decode(salt_b64.encode("utf-8"))
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
        self.fernet = Fernet(key)

    def encrypt_bytes(self, data: bytes) -> bytes:
        return self.fernet.encrypt(data)

    def decrypt_bytes(self, data: bytes) -> bytes:
        return self.fernet.decrypt(data)

    def encrypt_text(self, text: str) -> bytes:
        return self.encrypt_bytes(text.encode("utf-8"))

    def decrypt_text(self, data: bytes) -> str:
        return self.decrypt_bytes(data).decode("utf-8", errors="ignore")


# ---------- Database ----------
def get_connection():
    con = sqlite3.connect(DB_FILE)
    con.row_factory = sqlite3.Row
    return con


def init_db(con):
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            original_path TEXT,
            mime_ext TEXT,
            encrypted_blob BLOB NOT NULL,
            encrypted_text BLOB NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    con.commit()


def db_get_meta(con, key):
    row = con.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def db_set_meta(con, key, value):
    con.execute("INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))
    con.commit()


def setup_or_unlock_crypto(root):
    con = get_connection()
    init_db(con)

    salt_b64 = db_get_meta(con, "salt")
    check_token = db_get_meta(con, "check_token")

    if not salt_b64 or not check_token:
        messagebox.showinfo("First run", "Choose a password for the encrypted document database.")
        while True:
            pw1 = simpledialog.askstring("New password", "Choose a database password:", show="*", parent=root)
            if pw1 is None:
                raise SystemExit("No password provided")
            pw2 = simpledialog.askstring("Confirm password", "Enter the same password again:", show="*", parent=root)
            if pw2 is None:
                raise SystemExit("No password provided")
            if not pw1.strip():
                messagebox.showwarning("Empty password", "The password cannot be empty.")
                continue
            if pw1 != pw2:
                messagebox.showwarning("Mismatch", "The passwords do not match.")
                continue
            salt = secrets.token_bytes(16)
            salt_b64 = base64.urlsafe_b64encode(salt).decode("utf-8")
            db_set_meta(con, "salt", salt_b64)
            crypto = CryptoManager(pw1, salt_b64)
            token = crypto.encrypt_text("knowledgebase-ok")
            db_set_meta(con, "check_token", base64.urlsafe_b64encode(token).decode("utf-8"))
            db_set_meta(con, "categories", base64.urlsafe_b64encode(crypto.encrypt_text(json.dumps({"_docs": []}, ensure_ascii=False))).decode("utf-8"))
            return con, crypto
    else:
        for _ in range(5):
            pw = simpledialog.askstring("Password", "Enter the database password:", show="*", parent=root)
            if pw is None:
                raise SystemExit("No password provided")
            try:
                crypto = CryptoManager(pw, salt_b64)
                token = base64.urlsafe_b64decode(check_token.encode("utf-8"))
                if crypto.decrypt_text(token) == "knowledgebase-ok":
                    return con, crypto
            except InvalidToken:
                pass
            except Exception:
                pass
            messagebox.showerror("Incorrect password", "The password you entered is incorrect.")
        raise SystemExit("Too many failed attempts")


# ---------- Categories in DB ----------
def normalize_categories(data):
    if not isinstance(data, dict):
        return {"_docs": []}
    normalized = {"_docs": []}
    for key, value in data.items():
        if key == "_docs":
            if isinstance(value, list):
                normalized[key] = list(dict.fromkeys(str(v) for v in value))
        elif isinstance(value, dict):
            child = normalize_categories(value)
            child.setdefault("_docs", [])
            normalized[str(key)] = child
    return normalized


def load_categories(con, crypto):
    raw = db_get_meta(con, "categories")
    if not raw:
        data = {"_docs": []}
        save_categories(con, crypto, data)
        return data
    try:
        decrypted = crypto.decrypt_text(base64.urlsafe_b64decode(raw.encode("utf-8")))
        return normalize_categories(json.loads(decrypted))
    except Exception:
        data = {"_docs": []}
        save_categories(con, crypto, data)
        return data


def save_categories(con, crypto, data):
    payload = json.dumps(normalize_categories(data), ensure_ascii=False)
    encrypted = crypto.encrypt_text(payload)
    db_set_meta(con, "categories", base64.urlsafe_b64encode(encrypted).decode("utf-8"))


# ---------- File handling ----------
def read_txt(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def read_docx(path):
    doc = Document(path)
    return "\n".join(p.text for p in doc.paragraphs if p.text.strip())


def read_pdf(path):
    reader = PdfReader(path)
    return "\n".join((page.extract_text() or "") for page in reader.pages)


def extract_text_from_path(path):
    lower = path.lower()
    try:
        if lower.endswith(".txt"):
            return read_txt(path)
        if lower.endswith(".docx"):
            return read_docx(path)
        if lower.endswith(".pdf"):
            return read_pdf(path)
    except Exception as exc:
        return f"Could not read document: {exc}"
    return ""


def open_file(path):
    try:
        if not os.path.exists(path):
            messagebox.showerror("File not found", f"Could not find this file:\n{path}")
            return
        system = platform.system()
        if system == "Windows":
            os.startfile(path)
        elif system == "Darwin":
            subprocess.call(["open", path])
        else:
            subprocess.call(["xdg-open", path])
    except Exception as e:
        messagebox.showerror("Open failed", f"Could not open file:\n{e}")


# ---------- Secure document storage ----------
def get_doc_by_id(con, doc_id):
    return con.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()


def list_secure_docs(con):
    rows = con.execute("SELECT id, filename, original_path, mime_ext, created_at FROM documents ORDER BY lower(filename)").fetchall()
    return [dict(r) for r in rows]


def delete_document(con, doc_id):
    con.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
    con.commit()


def add_document_from_path(con, crypto, file_path):
    file_path = os.path.abspath(file_path)
    filename = os.path.basename(file_path)
    ext = Path(filename).suffix.lower()
    with open(file_path, "rb") as f:
        raw_bytes = f.read()
    extracted_text = extract_text_from_path(file_path)
    encrypted_blob = crypto.encrypt_bytes(raw_bytes)
    encrypted_text = crypto.encrypt_text(extracted_text)

    # If same original_path exists, update it. Else new id.
    existing = con.execute("SELECT id FROM documents WHERE original_path = ?", (file_path,)).fetchone()
    doc_id = existing[0] if existing else str(uuid4())
    con.execute(
        """
        INSERT INTO documents(id, filename, original_path, mime_ext, encrypted_blob, encrypted_text)
        VALUES(?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            filename = excluded.filename,
            original_path = excluded.original_path,
            mime_ext = excluded.mime_ext,
            encrypted_blob = excluded.encrypted_blob,
            encrypted_text = excluded.encrypted_text
        """,
        (doc_id, filename, file_path, ext, encrypted_blob, encrypted_text),
    )
    con.commit()
    return doc_id


def decrypt_doc_text(con, crypto, doc_id):
    row = get_doc_by_id(con, doc_id)
    if not row:
        return ""
    return crypto.decrypt_text(row["encrypted_text"])


def decrypt_doc_bytes(con, crypto, doc_id):
    row = get_doc_by_id(con, doc_id)
    if not row:
        return None, None
    data = crypto.decrypt_bytes(row["encrypted_blob"])
    return data, row["mime_ext"]


def open_secure_document(con, crypto, doc_id):
    row = get_doc_by_id(con, doc_id)
    if not row:
        messagebox.showerror("Document not found", "This document could not be found in the database.")
        return
    data, ext = decrypt_doc_bytes(con, crypto, doc_id)
    if data is None:
        messagebox.showerror("Decryption failed", "The document could not be decrypted.")
        return
    suffix = ext or ".bin"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(data)
        temp_path = tmp.name
    open_file(temp_path)


# ---------- Summaries ----------
STOPWORDS = {
    # Dutch
    "de", "het", "een", "en", "van", "in", "op", "aan", "met", "voor", "is", "zijn", "dat", "die", "dit", "als",
    "te", "om", "bij", "door", "naar", "uit", "over", "wordt", "kan", "ook", "nog", "meer", "dan", "maar", "tot",
    "of", "niet", "wel", "er", "binnen", "tussen", "onder", "boven", "zoals", "dus", "al", "alle", "deze", "hun",
    "hem", "haar", "ons", "onze", "uw", "jouw", "mijn", "je", "we", "wij", "u", "hij", "zij",
    # English
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "at", "for", "with", "by", "from", "as", "is", "are",
    "was", "were", "be", "been", "being", "this", "that", "these", "those", "it", "its", "he", "she", "they",
    "them", "his", "her", "their", "our", "your", "my", "we", "you", "not", "no", "but", "so", "if", "than",
    "then", "there", "here", "which", "who", "whom", "what", "when", "where", "how", "can", "will", "would",
    "should", "could", "also", "more", "most", "such", "into", "over", "under", "between", "within", "about"
}


def summarize(text, max_sentences=8):
    cleaned = re.sub(r"\s+", " ", text or "").strip()
    if not cleaned:
        return "No content available."

    sentences = re.split(r'(?<=[.!?])\s+', cleaned)
    sentences = [s.strip() for s in sentences if len(s.strip()) > 25]
    if not sentences:
        return cleaned[:1600]

    words = [w for w in re.findall(r'\w+', cleaned.lower()) if w not in STOPWORDS and len(w) > 2]
    if not words:
        return "\n\n".join(sentences[:max_sentences])

    freq = Counter(words)
    scores = {}
    for idx, sentence in enumerate(sentences):
        s_words = [w for w in re.findall(r'\w+', sentence.lower()) if w not in STOPWORDS and len(w) > 2]
        if not s_words or len(s_words) > 40:
            continue
        score = sum(freq.get(w, 0) for w in s_words)
        if 0 < idx < 10:
            score *= 1.03
        scores[sentence] = score

    best = sorted(scores, key=scores.get, reverse=True)[:max_sentences]
    ordered = [s for s in sentences if s in best]
    return "\n\n".join(ordered) if ordered else "\n\n".join(sentences[:max_sentences])


def make_preview(text, max_chars=3500):
    if not text or not text.strip():
        return "No preview available."
    # Collapse runs of spaces/tabs within each line, but keep line breaks so that
    # headings, paragraphs and list items stay readable instead of one wall of text.
    lines = [re.sub(r"[ \t\u00a0]+", " ", ln).strip() for ln in text.splitlines()]
    # Group consecutive non-empty lines into paragraphs; blank lines separate them.
    paragraphs, buff = [], []
    for ln in lines:
        if ln:
            buff.append(ln)
        elif buff:
            paragraphs.append("\n".join(buff))
            buff = []
    if buff:
        paragraphs.append("\n".join(buff))
    cleaned = "\n\n".join(paragraphs).strip()
    if not cleaned:
        return "No preview available."
    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars].rstrip() + "…"
    return cleaned


# ---------- Category model helpers ----------
def get_node_at_path(data, path_parts):
    node = data
    for part in path_parts:
        node = node[part]
    return node


def get_parent_and_key(data, path_parts):
    if not path_parts:
        return None, None
    parent = data
    for part in path_parts[:-1]:
        parent = parent[part]
    return parent, path_parts[-1]


def ensure_docs_list(node):
    node.setdefault("_docs", [])
    return node["_docs"]


def add_category(data, path_parts, name):
    parent = get_node_at_path(data, path_parts)
    parent.setdefault(name, {"_docs": []})


def rename_category(data, path_parts, new_name):
    parent, key = get_parent_and_key(data, path_parts)
    if parent is None or key not in parent:
        return False
    if new_name in parent:
        return False
    parent[new_name] = parent.pop(key)
    return True


def delete_category(data, path_parts):
    parent, key = get_parent_and_key(data, path_parts)
    if parent is None or key not in parent:
        return False
    del parent[key]
    return True


def add_doc_assignment(data, path_parts, doc_id):
    node = get_node_at_path(data, path_parts)
    docs = ensure_docs_list(node)
    if doc_id not in docs:
        docs.append(doc_id)


def remove_doc_from_all(node, doc_id):
    docs = node.get("_docs", [])
    if doc_id in docs:
        docs.remove(doc_id)
        return True
    for key, value in node.items():
        if key == "_docs":
            continue
        if remove_doc_from_all(value, doc_id):
            return True
    return False


def move_doc(data, doc_id, target_path_parts):
    remove_doc_from_all(data, doc_id)
    add_doc_assignment(data, target_path_parts, doc_id)


def is_descendant_path(source_parts, target_parts):
    return len(target_parts) >= len(source_parts) and target_parts[:len(source_parts)] == source_parts


def move_category(data, source_parts, target_parts):
    if not source_parts or is_descendant_path(source_parts, target_parts):
        return False
    source_parent, source_key = get_parent_and_key(data, source_parts)
    if source_parent is None or source_key not in source_parent:
        return False
    moving = source_parent.pop(source_key)
    target_node = get_node_at_path(data, target_parts)
    if source_key in target_node:
        source_parent[source_key] = moving
        return False
    target_node[source_key] = moving
    return True


def find_category_paths_for_doc(node, current_path, doc_id, found):
    if doc_id in node.get("_docs", []):
        found.append(current_path)
    for key, value in node.items():
        if key == "_docs":
            continue
        find_category_paths_for_doc(value, current_path + [key], doc_id, found)


def get_category_label_for_doc(data, doc_id):
    found = []
    find_category_paths_for_doc(data, [], doc_id, found)
    if not found:
        return "Uncategorized"
    return " / ".join(found[0]) if found[0] else "Root"


def is_doc_assigned(data, doc_id):
    return get_category_label_for_doc(data, doc_id) != "Uncategorized"


class App:
    def __init__(self, root, con, crypto):
        self.root = root
        self.con = con
        self.crypto = crypto
        self.categories = load_categories(self.con, self.crypto)

        self.root.title(APP_TITLE)
        self.root.geometry("1500x920")
        self.root.minsize(1280, 800)
        self.theme = "dark"

        self.tree_meta = {}
        self.drag_payload = None
        self.docs_cache = []
        self.current_preview_doc_id = None
        self.search_terms = []

        self.setup_style()
        self.build_ui()
        self.refresh_everything()

    # ----- UI -----
    THEMES = {
        "dark": {
            "bg": "#0b1220",
            "panel": "#111827",
            "card": "#1f2937",
            "card_hover": "#263445",
            "entry": "#0f172a",
            "text": "#e5e7eb",
            "muted": "#94a3b8",
            "border": "#334155",
            "accent": "#38bdf8",
            "accent_hover": "#7dd3fc",
            "on_accent": "#041018",
            "warn": "#fbbf24"
        },
        "light": {
            "bg": "#eef2f7",
            "panel": "#ffffff",
            "card": "#e2e8f0",
            "card_hover": "#cbd5e1",
            "entry": "#f8fafc",
            "text": "#0f172a",
            "muted": "#64748b",
            "border": "#cbd5e1",
            "accent": "#0284c7",
            "accent_hover": "#0369a1",
            "on_accent": "#ffffff",
            "warn": "#b45309"
        }
    }

    def setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        self.style = style
        self.apply_theme(self.theme)

    def apply_theme(self, theme_name):
        self.theme = theme_name
        self.colors = dict(self.THEMES[theme_name])
        style = self.style

        style.configure("App.TFrame", background=self.colors["bg"])
        style.configure("Panel.TFrame", background=self.colors["panel"])
        style.configure("Card.TFrame", background=self.colors["card"])
        style.configure("Header.TLabel", background=self.colors["bg"], foreground=self.colors["text"], font=("Segoe UI", 22, "bold"))
        style.configure("Sub.TLabel", background=self.colors["bg"], foreground=self.colors["muted"], font=("Segoe UI", 10))
        style.configure("PanelTitle.TLabel", background=self.colors["panel"], foreground=self.colors["text"], font=("Segoe UI", 11, "bold"))
        style.configure("CardValue.TLabel", background=self.colors["card"], foreground=self.colors["text"], font=("Segoe UI", 18, "bold"))
        style.configure("CardLabel.TLabel", background=self.colors["card"], foreground=self.colors["muted"], font=("Segoe UI", 9))
        style.configure("Info.TLabel", background=self.colors["panel"], foreground=self.colors["muted"], font=("Segoe UI", 9))
        style.configure("Warn.TLabel", background=self.colors["panel"], foreground=self.colors["warn"], font=("Segoe UI", 9))
        style.configure("TEntry", fieldbackground=self.colors["entry"], foreground=self.colors["text"], insertcolor=self.colors["text"], bordercolor=self.colors["border"], padding=10)
        style.configure("Primary.TButton", background=self.colors["accent"], foreground=self.colors["on_accent"], borderwidth=0)
        style.map("Primary.TButton", background=[("active", self.colors["accent_hover"])])
        style.configure("Secondary.TButton", background=self.colors["card"], foreground=self.colors["text"], borderwidth=0)
        style.map("Secondary.TButton", background=[("active", self.colors["card_hover"])])
        style.configure("Treeview", background=self.colors["entry"], fieldbackground=self.colors["entry"], foreground=self.colors["text"], rowheight=28, bordercolor=self.colors["border"])
        style.map("Treeview", background=[("selected", self.colors["accent"])], foreground=[("selected", self.colors["on_accent"])])
        style.configure("Treeview.Heading", background=self.colors["card"], foreground=self.colors["text"], relief="flat", font=("Segoe UI", 10, "bold"))
        style.map("Treeview.Heading", background=[("active", self.colors["card_hover"])])
        style.configure("TNotebook", background=self.colors["panel"], borderwidth=0)
        style.configure("TNotebook.Tab", background=self.colors["card"], foreground=self.colors["text"], padding=(14, 8))
        style.map("TNotebook.Tab", background=[("selected", self.colors["accent"]), ("active", self.colors["card_hover"])], foreground=[("selected", self.colors["on_accent"])])
        style.configure("TSeparator", background=self.colors["border"])

        self.root.configure(bg=self.colors["bg"])

    def toggle_theme(self):
        new_theme = "light" if self.theme == "dark" else "dark"
        self.apply_theme(new_theme)
        self.update_manual_widget_colors()
        if hasattr(self, "theme_button"):
            self.theme_button.config(text=self.theme_button_label())
        self.set_status(f"Theme switched to {'light' if new_theme == 'light' else 'dark'} mode")

    def theme_button_label(self):
        return "☀️ Light mode" if self.theme == "dark" else "🌙 Dark mode"

    def update_manual_widget_colors(self):
        """Update tk widgets that do not use ttk styles (text fields and context menus)."""
        text_kwargs = dict(
            bg=self.colors["entry"], fg=self.colors["text"],
            insertbackground=self.colors["text"],
            selectbackground=self.colors["accent"], selectforeground=self.colors["on_accent"]
        )
        for widget in (getattr(self, "preview_text", None), getattr(self, "summary_text", None)):
            if widget is not None:
                widget.config(**text_kwargs)
        menu_kwargs = dict(
            bg=self.colors["card"], fg=self.colors["text"],
            activebackground=self.colors["accent"], activeforeground=self.colors["on_accent"]
        )
        for menu in (getattr(self, "tree_menu", None), getattr(self, "unassigned_menu", None), getattr(self, "results_menu", None)):
            if menu is not None:
                menu.config(**menu_kwargs)

    def build_ui(self):
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(2, weight=1)

        # Menu bar
        menubar = tk.Menu(self.root)

        categories_menu = tk.Menu(menubar, tearoff=0)
        categories_menu.add_command(label="📁 New category", command=self.add_category_dialog)
        categories_menu.add_command(label="✏️ Rename category", command=self.rename_selected_category)
        categories_menu.add_command(label="🗑️ Delete category", command=self.delete_selected_category)
        menubar.add_cascade(label="Categories", menu=categories_menu)

        documents_menu = tk.Menu(menubar, tearoff=0)
        documents_menu.add_command(label="📄 Upload to selected category", command=self.upload_documents_to_selected)
        documents_menu.add_command(label="⬆ Upload without category", command=self.upload_uncategorized_documents)
        documents_menu.add_separator()
        documents_menu.add_command(label="🗑️ Delete document", command=self.delete_current_document)
        menubar.add_cascade(label="Documents", menu=documents_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="User guide", command=self.show_help_window)
        help_menu.add_separator()
        help_menu.add_command(label=f"About {APP_NAME}", command=self.show_about_window)
        menubar.add_cascade(label="Help", menu=help_menu)

        menubar.add_command(label="🌓 Theme", command=self.toggle_theme)
        self.root.config(menu=menubar)

        header = ttk.Frame(self.root, style="App.TFrame", padding=(20, 18, 20, 10))
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        ttk.Label(header, text=f"{APP_NAME} {APP_VERSION}", style="Header.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(header, text="Securely search encrypted healthcare documents. Documents are stored encrypted in a SQLite database.", style="Sub.TLabel").grid(row=1, column=0, sticky="w", pady=(4, 0))

        header_buttons = ttk.Frame(header, style="App.TFrame")
        header_buttons.grid(row=0, column=1, rowspan=2, sticky="e")
        self.theme_button = ttk.Button(header_buttons, text=self.theme_button_label(), style="Secondary.TButton", command=self.toggle_theme)
        self.theme_button.grid(row=0, column=0, padx=(0, 8))
        ttk.Button(header_buttons, text="❓ Help", style="Secondary.TButton", command=self.show_help_window).grid(row=0, column=1, padx=(0, 8))
        ttk.Button(header_buttons, text="ℹ️ About", style="Secondary.TButton", command=self.show_about_window).grid(row=0, column=2)

        toolbar = ttk.Frame(self.root, style="App.TFrame", padding=(20, 0, 20, 12))
        toolbar.grid(row=1, column=0, sticky="ew")
        toolbar.grid_columnconfigure(1, weight=1)

        ttk.Label(toolbar, text="Search:", style="Sub.TLabel").grid(row=0, column=0, padx=(0, 8))
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(toolbar, textvariable=self.search_var)
        self.search_entry.grid(row=0, column=1, sticky="ew")
        self.search_entry.bind("<Return>", lambda e: self.run_search())
        ttk.Button(toolbar, text="Search", style="Primary.TButton", command=self.run_search).grid(row=0, column=2, padx=(8, 0))

        main = ttk.Frame(self.root, style="App.TFrame", padding=(20, 0, 20, 20))
        main.grid(row=2, column=0, sticky="nsew")
        main.grid_columnconfigure(0, weight=3)
        main.grid_columnconfigure(1, weight=4)
        main.grid_columnconfigure(2, weight=5)
        main.grid_rowconfigure(1, weight=1)

        self.docs_card = self.build_card(main, 0, 0, "0", "Indexed documents")
        self.uncat_card = self.build_card(main, 0, 1, "0", "Uncategorized")
        self.cats_card = self.build_card(main, 0, 2, "0", "Total categories")

        # Left panel: categories tree
        left = ttk.Frame(main, style="Panel.TFrame", padding=14)
        left.grid(row=1, column=0, sticky="nsew", padx=(0, 10), pady=(12, 0))
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)
        ttk.Label(left, text="Categories & documents", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 10))

        self.cat_tree = ttk.Treeview(left, show="tree")
        self.cat_tree.grid(row=1, column=0, sticky="nsew")
        self.cat_tree.bind("<<TreeviewSelect>>", self.on_tree_selected)
        self.cat_tree.bind("<ButtonPress-1>", self.start_tree_drag)
        self.cat_tree.bind("<ButtonRelease-1>", self.end_tree_drag)
        self.cat_tree.bind("<Double-1>", self.on_tree_double_click)

        left_scroll = ttk.Scrollbar(left, orient="vertical", command=self.cat_tree.yview)
        self.cat_tree.configure(yscrollcommand=left_scroll.set)
        left_scroll.grid(row=1, column=1, sticky="ns")

        ttk.Label(left, text="Double-click a document to open it. Right-click for more options.", style="Info.TLabel").grid(row=2, column=0, sticky="w", pady=(10, 0))

        # Center panel: uncategorized + search results
        center = ttk.Frame(main, style="Panel.TFrame", padding=14)
        center.grid(row=1, column=1, sticky="nsew", padx=(0, 10), pady=(12, 0))
        center.grid_rowconfigure(3, weight=1)
        center.grid_columnconfigure(0, weight=1)
        ttk.Label(center, text="Uncategorized + search", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 10))

        ttk.Label(center, text="Drag new or loose uploads from below onto a category in the left tree.", style="Info.TLabel").grid(row=1, column=0, sticky="w")
        ttk.Label(center, text="Search is privacy-friendly: decrypted text is used only in memory (no plaintext index on disk).", style="Warn.TLabel").grid(row=1, column=0, sticky="e")

        self.unassigned_tree = ttk.Treeview(center, columns=("title", "id"), show="headings", height=8, selectmode="browse")
        self.unassigned_tree.heading("title", text="Uncategorized document")
        self.unassigned_tree.heading("id", text="ID")
        self.unassigned_tree.column("title", width=280, anchor="w")
        self.unassigned_tree.column("id", width=160, anchor="w")
        self.unassigned_tree.grid(row=2, column=0, sticky="ew", pady=(8, 10))
        self.unassigned_tree.bind("<<TreeviewSelect>>", self.on_unassigned_selected)
        self.unassigned_tree.bind("<ButtonPress-1>", self.start_unassigned_drag)
        self.unassigned_tree.bind("<ButtonRelease-1>", self.end_unassigned_drag)
        self.unassigned_tree.bind("<Double-1>", self.on_unassigned_double_click)

        notebook_frame = ttk.Frame(center, style="Panel.TFrame")
        notebook_frame.grid(row=3, column=0, sticky="nsew")
        notebook_frame.grid_rowconfigure(0, weight=1)
        notebook_frame.grid_columnconfigure(0, weight=1)
        self.center_notebook = ttk.Notebook(notebook_frame)
        self.center_notebook.grid(row=0, column=0, sticky="nsew")

        search_tab = ttk.Frame(self.center_notebook, style="Panel.TFrame")
        self.center_notebook.add(search_tab, text="Search results")
        search_tab.grid_rowconfigure(1, weight=1)
        search_tab.grid_columnconfigure(0, weight=1)

        self.results_tree = ttk.Treeview(search_tab, columns=("title", "category", "id"), show="headings", selectmode="browse")
        self.results_tree.heading("title", text="Document")
        self.results_tree.heading("category", text="Category")
        self.results_tree.heading("id", text="ID")
        self.results_tree.column("title", width=220, anchor="w")
        self.results_tree.column("category", width=200, anchor="w")
        self.results_tree.column("id", width=150, anchor="w")
        self.results_tree.grid(row=1, column=0, sticky="nsew")
        self.results_tree.bind("<<TreeviewSelect>>", self.on_result_selected)
        self.results_tree.bind("<Double-1>", self.on_result_double_click)

        results_scroll = ttk.Scrollbar(search_tab, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=results_scroll.set)
        results_scroll.grid(row=1, column=1, sticky="ns")

        results_actions = ttk.Frame(search_tab, style="Panel.TFrame")
        results_actions.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        ttk.Button(results_actions, text="Show summary", style="Primary.TButton", command=self.show_summary_tab).pack(side="left")
        ttk.Button(results_actions, text="Open document", style="Secondary.TButton", command=self.open_selected_result_document).pack(side="left", padx=(8, 0))

        # Right panel: detail
        right = ttk.Frame(main, style="Panel.TFrame", padding=14)
        right.grid(row=1, column=2, sticky="nsew", pady=(12, 0))
        right.grid_rowconfigure(2, weight=1)
        right.grid_columnconfigure(0, weight=1)
        ttk.Label(right, text="Document detail", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))
        self.meta_label = ttk.Label(right, text="Select a document in the left tree, the uncategorized list or the search results.", style="Info.TLabel")
        self.meta_label.grid(row=1, column=0, sticky="w")

        self.detail_notebook = ttk.Notebook(right)
        self.detail_notebook.grid(row=2, column=0, sticky="nsew", pady=(10, 0))

        preview_tab = ttk.Frame(self.detail_notebook, style="Panel.TFrame")
        summary_tab = ttk.Frame(self.detail_notebook, style="Panel.TFrame")
        self.detail_notebook.add(preview_tab, text="Preview")
        self.detail_notebook.add(summary_tab, text="Summary")

        self.preview_text = tk.Text(preview_tab, wrap=tk.WORD, bg=self.colors["entry"], fg=self.colors["text"], insertbackground=self.colors["text"], relief="flat", padx=16, pady=16, font=("Segoe UI", 10), selectbackground=self.colors["accent"], selectforeground=self.colors["on_accent"])
        # Yellow highlight for search terms — dark text keeps it readable in both themes
        self.preview_text.tag_configure("search_hl", background="#fde047", foreground="#111111")
        self.preview_text.pack(side="left", fill="both", expand=True)
        self.preview_text.config(state="disabled")
        preview_scroll = ttk.Scrollbar(preview_tab, orient="vertical", command=self.preview_text.yview)
        self.preview_text.configure(yscrollcommand=preview_scroll.set)
        preview_scroll.pack(side="right", fill="y")

        self.summary_text = tk.Text(summary_tab, wrap=tk.WORD, bg=self.colors["entry"], fg=self.colors["text"], insertbackground=self.colors["text"], relief="flat", padx=16, pady=16, font=("Segoe UI", 10), selectbackground=self.colors["accent"], selectforeground=self.colors["on_accent"])
        self.summary_text.pack(side="left", fill="both", expand=True)
        self.summary_text.config(state="disabled")
        summary_scroll = ttk.Scrollbar(summary_tab, orient="vertical", command=self.summary_text.yview)
        self.summary_text.configure(yscrollcommand=summary_scroll.set)
        summary_scroll.pack(side="right", fill="y")

        status = ttk.Frame(self.root, style="App.TFrame", padding=(20, 0, 20, 14))
        status.grid(row=3, column=0, sticky="ew")
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status, textvariable=self.status_var, style="Sub.TLabel").pack(side="left")

        self.build_context_menus()

    def build_card(self, parent, row, col, value, label):
        card = ttk.Frame(parent, style="Card.TFrame", padding=16)
        card.grid(row=row, column=col, sticky="ew", padx=(0, 10 if col < 2 else 0))
        value_lbl = ttk.Label(card, text=value, style="CardValue.TLabel")
        value_lbl.pack(anchor="w")
        ttk.Label(card, text=label, style="CardLabel.TLabel").pack(anchor="w", pady=(4, 0))
        return value_lbl

    def build_context_menus(self):
        # Menus are built fresh on each right-click (see the show_* handlers below),
        # so here we only wire up the bindings.
        self.cat_tree.bind("<Button-3>", self.show_tree_context_menu)
        self.cat_tree.bind("<Delete>", self.on_tree_delete_key)
        self.cat_tree.bind("<BackSpace>", self.on_tree_delete_key)

        self.unassigned_tree.bind("<Button-3>", self.show_unassigned_context_menu)
        self.unassigned_tree.bind("<Delete>", lambda e: self.delete_selected_unassigned_document())
        self.unassigned_tree.bind("<BackSpace>", lambda e: self.delete_selected_unassigned_document())

        self.results_tree.bind("<Button-3>", self.show_results_context_menu)
        self.results_tree.bind("<Delete>", lambda e: self.delete_selected_result_document())
        self.results_tree.bind("<BackSpace>", lambda e: self.delete_selected_result_document())

    def _new_menu(self):
        return tk.Menu(
            self.root, tearoff=0,
            bg=self.colors["card"], fg=self.colors["text"],
            activebackground=self.colors["accent"], activeforeground=self.colors["on_accent"]
        )

    def show_tree_context_menu(self, event):
        row_id = self.cat_tree.identify_row(event.y)
        if not row_id:
            return
        self.cat_tree.selection_set(row_id)
        self.cat_tree.focus(row_id)
        self.cat_tree.focus_set()
        meta = self.tree_meta.get(row_id)
        menu = self._new_menu()
        if meta and meta.get("type") == "doc":
            menu.add_command(label="📂 Open", command=self.open_selected_tree_document)
            menu.add_separator()
            menu.add_command(label="🗑️ Delete document", command=self.delete_selected_tree_document)
        else:
            menu.add_command(label="New subcategory", command=self.add_category_dialog)
            menu.add_command(label="Rename", command=self.rename_selected_category)
            menu.add_command(label="Delete category", command=self.delete_selected_category)
            menu.add_separator()
            menu.add_command(label="Upload document(s) to this category", command=self.upload_documents_to_selected)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def show_unassigned_context_menu(self, event):
        row_id = self.unassigned_tree.identify_row(event.y)
        if not row_id:
            return
        self.unassigned_tree.selection_set(row_id)
        self.unassigned_tree.focus(row_id)
        self.unassigned_tree.focus_set()
        menu = self._new_menu()
        menu.add_command(label="📂 Open", command=self.open_selected_unassigned_document)
        menu.add_command(label="👁 Preview", command=self.preview_selected_unassigned)
        menu.add_separator()
        menu.add_command(label="🗑️ Delete document", command=self.delete_selected_unassigned_document)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def show_results_context_menu(self, event):
        row_id = self.results_tree.identify_row(event.y)
        if not row_id:
            return
        self.results_tree.selection_set(row_id)
        self.results_tree.focus(row_id)
        self.results_tree.focus_set()
        menu = self._new_menu()
        menu.add_command(label="📂 Open", command=self.open_selected_result_document)
        menu.add_command(label="👁 Preview", command=self.preview_selected_result)
        menu.add_command(label="🧠 Summary", command=self.show_summary_tab)
        menu.add_separator()
        menu.add_command(label="🗑️ Delete document", command=self.delete_selected_result_document)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    # ----- Refresh -----
    def set_status(self, text):
        self.status_var.set(text)

    def count_categories(self, node):
        total = 0
        for key, value in node.items():
            if key == "_docs":
                continue
            total += 1 + self.count_categories(value)
        return total

    def refresh_everything(self):
        self.categories = normalize_categories(self.categories)
        save_categories(self.con, self.crypto, self.categories)
        self.docs_cache = list_secure_docs(self.con)
        self.build_category_tree()
        self.fill_unassigned()
        self.fill_results(self.docs_cache)
        self.docs_card.config(text=str(len(self.docs_cache)))
        self.uncat_card.config(text=str(len(self.get_unassigned_docs())))
        self.cats_card.config(text=str(self.count_categories(self.categories)))
        self.set_status(f"{len(self.docs_cache)} document(s) loaded from encrypted database")

    def get_unassigned_docs(self):
        return [d for d in self.docs_cache if not is_doc_assigned(self.categories, d["id"])]

    def build_category_tree(self):
        self.cat_tree.delete(*self.cat_tree.get_children())
        self.tree_meta.clear()

        def add_category_nodes(parent_item, node, path_parts):
            for cat_name in sorted([k for k in node.keys() if k != "_docs"], key=str.lower):
                tree_id = self.cat_tree.insert(parent_item, "end", text=f"📁 {cat_name}", open=True)
                cat_path = path_parts + [cat_name]
                self.tree_meta[tree_id] = {"type": "category", "path": cat_path}
                add_category_nodes(tree_id, node[cat_name], cat_path)
                for doc_id in sorted(node[cat_name].get("_docs", [])):
                    row = get_doc_by_id(self.con, doc_id)
                    if row:
                        doc_id_item = self.cat_tree.insert(tree_id, "end", text=f"📄 {row['filename']}", open=False)
                        self.tree_meta[doc_id_item] = {"type": "doc", "id": doc_id, "category_path": cat_path}

        add_category_nodes("", self.categories, [])

    def fill_unassigned(self):
        for item in self.unassigned_tree.get_children():
            self.unassigned_tree.delete(item)
        for doc in self.get_unassigned_docs():
            iid = str(uuid4())
            self.unassigned_tree.insert("", "end", iid=iid, values=(doc["filename"], doc["id"]))

    def fill_results(self, docs):
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        for doc in docs:
            iid = str(uuid4())
            cat_label = get_category_label_for_doc(self.categories, doc["id"])
            self.results_tree.insert("", "end", iid=iid, values=(doc["filename"], cat_label, doc["id"]))

    # ----- Category actions -----
    def selected_tree_meta(self):
        selected = self.cat_tree.selection()
        if not selected:
            return None
        return self.tree_meta.get(selected[0])

    def add_category_dialog(self):
        meta = self.selected_tree_meta()
        parent_path = []
        if meta:
            if meta["type"] == "category":
                parent_path = meta["path"]
            elif meta["type"] == "doc":
                parent_path = meta["category_path"]
        name = simpledialog.askstring("New category", "Category name:", parent=self.root)
        if not name:
            return
        name = name.strip()
        if not name:
            return
        target = get_node_at_path(self.categories, parent_path)
        if name in target:
            messagebox.showwarning("Already exists", "A category with this name already exists at this level.")
            return
        add_category(self.categories, parent_path, name)
        save_categories(self.con, self.crypto, self.categories)
        self.refresh_everything()
        self.set_status(f"Category '{name}' added")

    def rename_selected_category(self):
        meta = self.selected_tree_meta()
        if not meta or meta["type"] != "category":
            messagebox.showinfo("Selection required", "Select a category to rename first.")
            return
        old = meta["path"][-1]
        new_name = simpledialog.askstring("Rename", f"New name for '{old}':", initialvalue=old, parent=self.root)
        if not new_name:
            return
        new_name = new_name.strip()
        if not new_name or new_name == old:
            return
        ok = rename_category(self.categories, meta["path"], new_name)
        if not ok:
            messagebox.showwarning("Failed", "That name already exists at this level, or the category could not be found.")
            return
        save_categories(self.con, self.crypto, self.categories)
        self.refresh_everything()
        self.set_status(f"Category renamed to '{new_name}'")

    def delete_selected_category(self):
        meta = self.selected_tree_meta()
        if not meta or meta["type"] != "category":
            messagebox.showinfo("Selection required", "Select a category to delete first.")
            return
        name = meta["path"][-1]
        if not messagebox.askyesno("Delete", f"Are you sure you want to delete '{name}'?\nAll subcategories and document assignments in this branch will also be removed."):
            return
        if delete_category(self.categories, meta["path"]):
            save_categories(self.con, self.crypto, self.categories)
            self.refresh_everything()
            self.set_status(f"Category '{name}' deleted")

    def upload_documents_to_selected(self):
        meta = self.selected_tree_meta()
        if not meta or meta["type"] != "category":
            messagebox.showwarning("No category", "Select a category in the left tree first.")
            return
        files = filedialog.askopenfilenames(title="Select document(s)", filetypes=[("Documents", "*.pdf *.docx *.txt")])
        if not files:
            return
        added = 0
        for file_path in files:
            try:
                doc_id = add_document_from_path(self.con, self.crypto, file_path)
                add_doc_assignment(self.categories, meta["path"], doc_id)
                added += 1
            except Exception as exc:
                messagebox.showerror("Upload error", f"Could not add this document:\n{file_path}\n\n{exc}")
        save_categories(self.con, self.crypto, self.categories)
        self.refresh_everything()
        self.set_status(f"{added} document(s) stored encrypted in {' / '.join(meta['path'])}")

    def upload_uncategorized_documents(self):
        files = filedialog.askopenfilenames(title="Select document(s) to upload loose", filetypes=[("Documents", "*.pdf *.docx *.txt")])
        if not files:
            return
        added = 0
        for file_path in files:
            try:
                doc_id = add_document_from_path(self.con, self.crypto, file_path)
                remove_doc_from_all(self.categories, doc_id)
                added += 1
            except Exception as exc:
                messagebox.showerror("Upload error", f"Could not add this document:\n{file_path}\n\n{exc}")
        save_categories(self.con, self.crypto, self.categories)
        self.refresh_everything()
        self.set_status(f"{added} document(s) uploaded loose and encrypted — now drag them onto a category")
        self.center_notebook.select(0)

    # ----- Help & Over -----
    def _make_dialog_window(self, title, width, height):
        win = tk.Toplevel(self.root)
        win.title(title)
        win.configure(bg=self.colors["bg"])
        win.transient(self.root)
        win.grab_set()
        # Center relative to the main window
        self.root.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - width) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - height) // 2
        win.geometry(f"{width}x{height}+{max(x, 0)}+{max(y, 0)}")
        win.minsize(min(width, 480), min(height, 360))
        return win

    def show_help_window(self):
        win = self._make_dialog_window(f"User guide – {APP_NAME}", 760, 640)
        win.grid_columnconfigure(0, weight=1)
        win.grid_rowconfigure(1, weight=1)

        ttk.Label(win, text=f"❓ {APP_NAME} user guide", style="Header.TLabel").grid(row=0, column=0, sticky="w", padx=20, pady=(18, 8))

        frame = ttk.Frame(win, style="Panel.TFrame", padding=6)
        frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 10))
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)

        text = tk.Text(
            frame, wrap="word", bg=self.colors["entry"], fg=self.colors["text"],
            insertbackground=self.colors["text"], relief="flat", padx=16, pady=14,
            font=("Segoe UI", 10), spacing1=2, spacing3=6
        )
        scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")

        text.tag_configure("h", font=("Segoe UI", 12, "bold"), foreground=self.colors["accent"], spacing1=10, spacing3=4)

        help_sections = [
            ("What is ZorgDocZoek?",
             "ZorgDocZoek is a secure, local knowledge base for healthcare documents. All documents and the category "
             "structure are stored encrypted (AES via Fernet) in a single SQLite database file (knowledgebase_secure.db). "
             "No readable content is ever written to disk.\n"),
            ("Password",
             "On first run you choose a database password. On every following start you enter this password to unlock the "
             "database (up to 5 attempts).\n\n"
             "Note: the password cannot be recovered. If you lose it, the contents of the database are permanently "
             "unreadable. Keep it somewhere safe, for example in a password manager.\n"),
            ("The menus",
             "Most actions live in the menu bar at the top of the window:\n"
             "• Categories menu — New category, Rename category, Delete category.\n"
             "• Documents menu — Upload to selected category, Upload without category, Delete document.\n"
             "• Help menu — this user guide and the About window.\n"
             "• Theme — switch between light and dark mode.\n"
             "The only thing on the toolbar below the menus is the search box.\n"),
            ("Adding documents",
             "• Documents ▸ Upload to selected category: first select a category in the left tree, then add documents "
             "straight into it.\n"
             "• Documents ▸ Upload without category: add documents without a category; they appear in the "
             "'Uncategorized' list.\n"
             "Supported file types: PDF (.pdf), Word (.docx) and text (.txt). The text of each document is read "
             "automatically so you can search it. If you upload the same file again, the existing version in the "
             "database is updated.\n"),
            ("Deleting documents",
             "You can delete a document in several ways:\n"
             "• Select it, then choose Documents ▸ Delete document from the menu.\n"
             "• Right-click it in the tree, the 'Uncategorized' list or the search results and choose 'Delete document'.\n"
             "• Select it and press the Delete key.\n"
             "Each delete asks for confirmation. It permanently removes the document from the encrypted database and "
             "cannot be undone.\n"),
            ("Categories",
             "• Categories ▸ New category: creates a category under the selected category (or in the root).\n"
             "• Categories ▸ Rename category and Categories ▸ Delete category act on the selected category.\n"
             "• Drag and drop: drag documents or whole categories onto another category to move them. "
             "You can also drag documents out of 'Uncategorized' onto the tree to file them.\n"),
            ("Searching and highlighting",
             "Type one or more search terms in the search field and press Enter or click 'Search'. A document is a match "
             "when all terms appear in it. Searching works by decrypting documents in memory; no unencrypted search "
             "index is kept on disk (privacy-first).\n\n"
             "When you open a matching document, your search terms are highlighted in yellow in the preview, and the "
             "preview jumps to the first match. A whole phrase (e.g. 'blood pressure') is highlighted as one block, and "
             "single words are highlighted wherever they appear. Matching ignores upper/lower case. Clearing the search "
             "field removes the highlighting and shows the full list again.\n"),
            ("Viewing and summarizing",
             "• Click a document once (in the tree, the search results or 'Uncategorized') for a preview and an "
             "automatic summary in the right-hand panel. The preview keeps the document's paragraphs, headings and "
             "lists readable instead of running everything together.\n"
             "• Use the 'Show summary' button (in the search results panel) to jump to the summary of the selected "
             "document, and 'Open document' to open the original.\n"
             "• Double-click a document to open the original. The file is then temporarily decrypted to a temporary "
             "file and opened in the default program (e.g. Word or your PDF reader).\n"),
            ("Light and dark mode",
             "Switch between light and dark appearance with the 🌙/☀️ button at the top right, or via the 'Theme' menu. "
             "The whole interface, including the Help and About windows, follows your choice.\n"),
            ("Backup",
             "Everything lives in a single file: knowledgebase_secure.db. Copy this file regularly to a safe backup "
             "location. Together with your password, that is all you need to restore your knowledge base.\n"),
        ]
        for title, body in help_sections:
            text.insert(tk.END, title + "\n", "h")
            text.insert(tk.END, body + "\n")
        text.config(state="disabled")

        ttk.Button(win, text="Close", style="Primary.TButton", command=win.destroy).grid(row=2, column=0, pady=(0, 16))

    def show_about_window(self):
        win = self._make_dialog_window(f"About {APP_NAME}", 600, 520)
        win.grid_columnconfigure(0, weight=1)
        win.grid_rowconfigure(0, weight=1)

        panel = ttk.Frame(win, style="Panel.TFrame", padding=32)
        panel.grid(row=0, column=0, sticky="nsew", padx=24, pady=(24, 12))
        panel.grid_columnconfigure(0, weight=1)

        tk.Label(panel, text="🔒", bg=self.colors["panel"], fg=self.colors["accent"], font=("Segoe UI", 36)).grid(row=0, column=0)
        tk.Label(panel, text=APP_NAME, bg=self.colors["panel"], fg=self.colors["text"], font=("Segoe UI", 24, "bold")).grid(row=1, column=0, pady=(8, 0))
        tk.Label(panel, text=f"Version {APP_VERSION}", bg=self.colors["panel"], fg=self.colors["muted"], font=("Segoe UI", 12)).grid(row=2, column=0, pady=(2, 16))
        tk.Label(
            panel,
            text="Secure, encrypted knowledge base for healthcare documents.\nSearch, categorize and view — all local and private.",
            bg=self.colors["panel"], fg=self.colors["text"], font=("Segoe UI", 11), justify="center", wraplength=480
        ).grid(row=3, column=0, pady=(0, 18))
        ttk.Separator(panel, orient="horizontal").grid(row=4, column=0, sticky="ew", pady=(0, 16))
        tk.Label(panel, text="Created by", bg=self.colors["panel"], fg=self.colors["muted"], font=("Segoe UI", 10)).grid(row=5, column=0)
        tk.Label(panel, text=APP_CREATOR, bg=self.colors["panel"], fg=self.colors["accent"], font=("Segoe UI", 15, "bold")).grid(row=6, column=0, pady=(4, 0))

        ttk.Button(win, text="Close", style="Primary.TButton", command=win.destroy).grid(row=1, column=0, pady=(0, 20), ipadx=16, ipady=2)

    # ----- Drag & drop -----
    def start_tree_drag(self, event):
        item = self.cat_tree.identify_row(event.y)
        if item:
            self.drag_payload = {"source": "cat_tree", "item": item, "meta": self.tree_meta.get(item)}
        else:
            self.drag_payload = None

    def end_tree_drag(self, event):
        if not self.drag_payload or self.drag_payload.get("source") != "cat_tree":
            self.drag_payload = None
            return
        target_item = self.cat_tree.identify_row(event.y)
        source = self.drag_payload
        self.drag_payload = None
        if not target_item or target_item == source["item"]:
            return

        source_meta = source.get("meta")
        target_meta = self.tree_meta.get(target_item)
        if not source_meta or not target_meta:
            return

        if source_meta["type"] == "doc":
            target_path = target_meta["category_path"] if target_meta["type"] == "doc" else target_meta["path"]
            move_doc(self.categories, source_meta["id"], target_path)
            save_categories(self.con, self.crypto, self.categories)
            self.refresh_everything()
            self.set_status(f"Document moved to {' / '.join(target_path)}")
            return

        if source_meta["type"] == "category" and target_meta["type"] == "category":
            if is_descendant_path(source_meta["path"], target_meta["path"]):
                messagebox.showwarning("Invalid move", "You cannot place a category inside itself or one of its subcategories.")
                return
            if move_category(self.categories, source_meta["path"], target_meta["path"]):
                save_categories(self.con, self.crypto, self.categories)
                self.refresh_everything()
                self.set_status(f"Category moved to {' / '.join(target_meta['path'])}")
            else:
                messagebox.showwarning("Failed", "The category could not be moved. The name may already exist at the target level.")

    def start_unassigned_drag(self, event):
        item = self.unassigned_tree.identify_row(event.y)
        if item:
            values = self.unassigned_tree.item(item, "values")
            if values:
                self.drag_payload = {"source": "unassigned", "id": values[1], "title": values[0]}
        else:
            self.drag_payload = None

    def end_unassigned_drag(self, event):
        if not self.drag_payload or self.drag_payload.get("source") != "unassigned":
            self.drag_payload = None
            return
        x_root = self.unassigned_tree.winfo_pointerx()
        y_root = self.unassigned_tree.winfo_pointery()
        widget = self.root.winfo_containing(x_root, y_root)
        if widget is not self.cat_tree:
            self.drag_payload = None
            return
        rel_y = y_root - self.cat_tree.winfo_rooty()
        target_item = self.cat_tree.identify_row(rel_y)
        payload = self.drag_payload
        self.drag_payload = None
        if not target_item:
            return
        target_meta = self.tree_meta.get(target_item)
        if not target_meta:
            return
        target_path = target_meta["category_path"] if target_meta["type"] == "doc" else target_meta["path"]
        move_doc(self.categories, payload["id"], target_path)
        save_categories(self.con, self.crypto, self.categories)
        self.refresh_everything()
        self.set_status(f"New document assigned to {' / '.join(target_path)}")

    # ----- Preview / search -----
    def set_text_widget(self, widget, text):
        widget.config(state="normal")
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, text)
        widget.config(state="disabled")

    def set_preview_text(self, text):
        """Fill the preview and highlight the current search terms in yellow."""
        w = self.preview_text
        w.config(state="normal")
        w.delete("1.0", tk.END)
        w.insert(tk.END, text)
        w.tag_remove("search_hl", "1.0", tk.END)
        for term in self.search_terms:
            term = (term or "").strip()
            if not term:
                continue
            start = "1.0"
            while True:
                idx = w.search(term, start, stopindex=tk.END, nocase=True)
                if not idx:
                    break
                end = f"{idx}+{len(term)}c"
                w.tag_add("search_hl", idx, end)
                start = end
        w.config(state="disabled")
        # Scroll to the first highlighted match, if any
        ranges = w.tag_ranges("search_hl")
        if ranges:
            w.see(ranges[0])

    def load_doc_into_preview(self, doc_id):
        row = get_doc_by_id(self.con, doc_id)
        if not row:
            return
        title = row["filename"]
        category_label = get_category_label_for_doc(self.categories, doc_id)
        raw = decrypt_doc_text(self.con, self.crypto, doc_id)
        self.current_preview_doc_id = doc_id
        self.meta_label.config(text=f"{title}\nCategory: {category_label}\nDB ID: {doc_id}")
        self.set_preview_text(make_preview(raw))
        self.set_text_widget(self.summary_text, summarize(raw))
        self.set_status(f"Document loaded: {title}")

    def on_tree_selected(self, _event=None):
        meta = self.selected_tree_meta()
        if not meta:
            return
        if meta["type"] == "doc":
            self.load_doc_into_preview(meta["id"])
        else:
            label = " / ".join(meta["path"]) if meta["path"] else "Root"
            self.meta_label.config(text=f"Category selected: {label}")

    def on_tree_double_click(self, _event=None):
        meta = self.selected_tree_meta()
        if meta and meta["type"] == "doc":
            open_secure_document(self.con, self.crypto, meta["id"])

    def on_unassigned_selected(self, _event=None):
        self.preview_selected_unassigned()

    def preview_selected_unassigned(self):
        selected = self.unassigned_tree.selection()
        if not selected:
            return
        values = self.unassigned_tree.item(selected[0], "values")
        if values:
            self.load_doc_into_preview(values[1])

    def on_unassigned_double_click(self, _event=None):
        self.open_selected_unassigned_document()

    def run_search(self):
        raw_query = self.search_var.get().strip()
        query = raw_query.lower()
        if not query:
            self.search_terms = []
            self.fill_results(self.docs_cache)
            if self.current_preview_doc_id:
                self.load_doc_into_preview(self.current_preview_doc_id)
            self.set_status("Search field empty: showing full list")
            return

        # Search by decrypting text in memory (privacy-first; no plaintext index on disk)
        terms = [t for t in query.split() if t]
        # Highlight the whole phrase first (for multi-word searches), then each word.
        self.search_terms = ([raw_query] if len(terms) > 1 else []) + terms
        hits = []
        for doc in self.docs_cache:
            text = decrypt_doc_text(self.con, self.crypto, doc["id"]).lower()
            if all(term in text for term in terms):
                hits.append(doc)
        self.fill_results(hits)
        self.center_notebook.select(0)
        # Refresh the preview so highlights reflect the new search
        if self.current_preview_doc_id:
            self.load_doc_into_preview(self.current_preview_doc_id)
        self.set_status(f"{len(hits)} result(s) for: {query}")

    def selected_result_id(self):
        selected = self.results_tree.selection()
        if not selected:
            return None
        values = self.results_tree.item(selected[0], "values")
        return values[2] if values else None

    def on_result_selected(self, _event=None):
        self.preview_selected_result()

    def preview_selected_result(self):
        doc_id = self.selected_result_id()
        if doc_id:
            self.load_doc_into_preview(doc_id)

    def on_result_double_click(self, _event=None):
        self.open_selected_result_document()

    def _resolve_active_doc_id(self):
        """Find the currently relevant document id from any selection source."""
        doc_id = self.selected_result_id()
        if doc_id:
            return doc_id
        sel = self.unassigned_tree.selection()
        if sel:
            values = self.unassigned_tree.item(sel[0], "values")
            if values:
                return values[1]
        meta = self.selected_tree_meta()
        if meta and meta.get("type") == "doc":
            return meta["id"]
        return self.current_preview_doc_id

    def show_preview_tab(self):
        doc_id = self._resolve_active_doc_id()
        if not doc_id:
            messagebox.showinfo("No document", "Select a document first.")
            return
        self.load_doc_into_preview(doc_id)
        self.detail_notebook.select(0)

    def show_summary_tab(self):
        doc_id = self.current_preview_doc_id or self._resolve_active_doc_id()
        if not doc_id:
            messagebox.showinfo("No document", "Select a document first.")
            return
        self.load_doc_into_preview(doc_id)
        self.detail_notebook.select(1)

    # ----- Delete documents -----
    def delete_current_document(self):
        """Delete whichever document is currently selected (tree, uncategorized list,
        search results) or shown in the preview. Used by the toolbar button."""
        # 1) Tree selection
        meta = self.selected_tree_meta()
        if meta and meta.get("type") == "doc":
            self.delete_document_by_id(meta["id"])
            return
        # 2) Uncategorized list selection
        sel = self.unassigned_tree.selection()
        if sel:
            values = self.unassigned_tree.item(sel[0], "values")
            if values:
                self.delete_document_by_id(values[1])
                return
        # 3) Search results selection
        doc_id = self.selected_result_id()
        if doc_id:
            self.delete_document_by_id(doc_id)
            return
        # 4) Whatever is loaded in the preview panel
        if self.current_preview_doc_id:
            self.delete_document_by_id(self.current_preview_doc_id)
            return
        messagebox.showinfo(
            "No document",
            "Select a document first — in the left tree, the 'Uncategorized' list, or the search results."
        )

    def delete_document_by_id(self, doc_id):
        row = get_doc_by_id(self.con, doc_id)
        if not row:
            messagebox.showinfo("No document", "This document could not be found.")
            return
        title = row["filename"]
        if not messagebox.askyesno(
            "Delete document",
            f"Are you sure you want to permanently delete this document?\n\n{title}\n\n"
            "This removes it from the encrypted database and cannot be undone."
        ):
            return
        remove_doc_from_all(self.categories, doc_id)
        delete_document(self.con, doc_id)
        save_categories(self.con, self.crypto, self.categories)
        if self.current_preview_doc_id == doc_id:
            self.current_preview_doc_id = None
            self.set_text_widget(self.preview_text, "")
            self.set_text_widget(self.summary_text, "")
            self.meta_label.config(text="Select a document in the left tree, the uncategorized list or the search results.")
        self.refresh_everything()
        self.set_status(f"Document deleted: {title}")

    def delete_selected_tree_document(self):
        meta = self.selected_tree_meta()
        if not meta or meta.get("type") != "doc":
            messagebox.showinfo("No document", "Select a document in the left tree first.")
            return
        self.delete_document_by_id(meta["id"])

    def delete_selected_unassigned_document(self):
        selected = self.unassigned_tree.selection()
        if not selected:
            messagebox.showinfo("No document", "Select a document in the 'Uncategorized' list first.")
            return
        values = self.unassigned_tree.item(selected[0], "values")
        if not values:
            return
        self.delete_document_by_id(values[1])

    def delete_selected_result_document(self):
        doc_id = self.selected_result_id()
        if not doc_id:
            messagebox.showinfo("No document", "Select a document in the search results first.")
            return
        self.delete_document_by_id(doc_id)

    def on_tree_delete_key(self, _event=None):
        meta = self.selected_tree_meta()
        if not meta:
            return
        if meta.get("type") == "doc":
            self.delete_selected_tree_document()
        else:
            self.delete_selected_category()

    # ----- Open selected docs -----
    def open_selected_tree_document(self):
        meta = self.selected_tree_meta()
        if not meta or meta.get("type") != "doc":
            messagebox.showinfo("No document", "Select a document in the left tree first.")
            return
        open_secure_document(self.con, self.crypto, meta["id"])

    def open_selected_unassigned_document(self):
        selected = self.unassigned_tree.selection()
        if not selected:
            messagebox.showinfo("No document", "Select a document in the 'Uncategorized' list first.")
            return
        values = self.unassigned_tree.item(selected[0], "values")
        if not values:
            return
        open_secure_document(self.con, self.crypto, values[1])

    def open_selected_result_document(self):
        doc_id = self.selected_result_id()
        if not doc_id:
            messagebox.showinfo("No document", "Select a document in the search results first.")
            return
        open_secure_document(self.con, self.crypto, doc_id)


if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()
    con, crypto = setup_or_unlock_crypto(root)
    root.deiconify()
    app = App(root, con, crypto)
    root.mainloop()