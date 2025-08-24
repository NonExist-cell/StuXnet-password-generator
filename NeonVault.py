#!/usr/bin/env python3
"""
Offline Password Manager – GUI Edition
- Clean, minimalist, "hackerish" dark theme
- DejaVu Sans Mono (fallback to any monospace if unavailable)
- Strong crypto: AES-256-GCM + scrypt KDF
- Fully offline; single encrypted vault file
- Features: search, add/edit/delete, generate strong passwords, copy to clipboard

Dependencies:
  pip install cryptography

Optional:
  Linux users may want: sudo apt install fonts-dejavu

Run:
  python vault_gui.py

Security notes:
  • Master password is never stored; losing it means losing the vault.
  • Clipboard clears automatically after 25s (best-effort).
  • CSV export is plaintext and disabled in the GUI for safety; add at your own risk.
"""
from __future__ import annotations
import os
import sys
import json
import time
import base64
import secrets
import string
import getpass
import hashlib
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

# --- Crypto -----------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception as e:
    print("[!] Missing dependency 'cryptography'. Install with: pip install cryptography", file=sys.stderr)
    raise

VAULT_PATH = os.environ.get("VAULT_FILE", os.path.join(os.path.expanduser("~"), ".opm_vault.dat"))
VERSION = 1

# Base64 helpers
b64e = lambda b: base64.b64encode(b).decode("utf-8")
b64d = lambda s: base64.b64decode(s.encode("utf-8"))

@dataclass
class ScryptParams:
    N: int = 2**14
    r: int = 8
    p: int = 1
    def derive_key(self, password: str, salt: bytes, key_len: int = 32) -> bytes:
        return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=self.N, r=self.r, p=self.p, dklen=key_len)

# --- Model ------------------------------------------------------------------
now = lambda: int(time.time())

@dataclass
class Entry:
    id: str
    site: str
    username: str
    password: str
    notes: str = ""
    created: int = now()
    updated: int = now()

@dataclass
class VaultPayload:
    entries: List[Entry]
    pwgen: Dict[str, Any]
    @staticmethod
    def empty() -> 'VaultPayload':
        return VaultPayload(entries=[], pwgen={
            "length": 20,
            "sets": ["lower", "upper", "digits", "symbols"],
            "avoid_ambiguous": True
        })

# Password generator
AMBIGUOUS = set("O0Il1|`'\"{}[]()<>;:,.\u2013\u2014")
CHARSETS = {
    "lower": list(string.ascii_lowercase),
    "upper": list(string.ascii_uppercase),
    "digits": list(string.digits),
    "symbols": list("!@#$%^&*-=+_?~")
}

def gen_password(length: int = 20, sets: Optional[List[str]] = None, avoid_ambiguous: bool = True) -> str:
    sets = sets or ["lower", "upper", "digits", "symbols"]
    pools, musts = [], []
    for s in sets:
        pool = CHARSETS.get(s, [])
        if avoid_ambiguous:
            pool = [c for c in pool if c not in AMBIGUOUS]
        if not pool:
            continue
        pools.extend(pool)
        musts.append(secrets.choice(pool))
    if not pools:
        raise ValueError("No character sets available")
    if length < len(musts):
        raise ValueError(f"length must be >= {len(musts)}")
    pwd_chars = musts + [secrets.choice(pools) for _ in range(length - len(musts))]
    for i in range(len(pwd_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        pwd_chars[i], pwd_chars[j] = pwd_chars[j], pwd_chars[i]
    return ''.join(pwd_chars)

# Vault I/O

def _new_header(sparams: ScryptParams, salt: bytes) -> Dict[str, Any]:
    return {
        "version": VERSION,
        "kdf": "scrypt",
        "scrypt": {"N": sparams.N, "r": sparams.r, "p": sparams.p},
        "salt": b64e(salt)
    }


def encrypt_payload(master_password: str, payload: VaultPayload, sparams: Optional[ScryptParams] = None) -> Dict[str, Any]:
    sparams = sparams or ScryptParams()
    salt = secrets.token_bytes(16)
    key = sparams.derive_key(master_password, salt)
    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps({
        "entries": [asdict(e) for e in payload.entries],
        "pwgen": payload.pwgen
    }, separators=(',', ':')).encode('utf-8')
    ciphertext = aes.encrypt(nonce, plaintext, associated_data=None)
    return {"header": _new_header(sparams, salt), "nonce": b64e(nonce), "ciphertext": b64e(ciphertext)}


def decrypt_payload(master_password: str, blob: Dict[str, Any]) -> VaultPayload:
    header = blob["header"]
    svals = header["scrypt"]
    sparams = ScryptParams(N=int(svals["N"]), r=int(svals["r"]), p=int(svals["p"]))
    salt = b64d(header["salt"])  
    key = sparams.derive_key(master_password, salt)
    aes = AESGCM(key)
    nonce = b64d(blob["nonce"]) 
    ciphertext = b64d(blob["ciphertext"]) 
    plaintext = aes.decrypt(nonce, ciphertext, associated_data=None)
    data = json.loads(plaintext.decode('utf-8'))
    entries = [Entry(**e) for e in data.get("entries", [])]
    return VaultPayload(entries=entries, pwgen=data.get("pwgen", VaultPayload.empty().pwgen))


def save_vault(path: str, master_password: str, payload: VaultPayload) -> None:
    blob = encrypt_payload(master_password, payload)
    tmp = path + ".tmp"
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(blob, f, separators=(',', ':'))
    os.replace(tmp, path)


def load_vault(path: str) -> Dict[str, Any]:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

# --- GUI --------------------------------------------------------------------
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from tkinter import filedialog

class Fonts:
    def __init__(self, root: tk.Tk):
        # Try DejaVu Sans Mono, fallback to any monospace
        try:
            import tkinter.font as tkfont
            available = set(tkfont.families())
            if "DejaVu Sans Mono" in available:
                family = "DejaVu Sans Mono"
            elif "DejaVu Sans Mono Book" in available:
                family = "DejaVu Sans Mono Book"
            elif "Menlo" in available:
                family = "Menlo"
            elif "Consolas" in available:
                family = "Consolas"
            else:
                family = "Courier"
        except Exception:
            family = "Courier"
        self.mono = (family, 11)
        self.mono_small = (family, 10)
        self.mono_big = (family, 12)

class DarkStyle:
    def __init__(self, root: tk.Tk, fonts: Fonts):
        style = ttk.Style(root)
        # Use built-in theme as base
        base = 'clam' if 'clam' in style.theme_names() else style.theme_use()
        style.theme_use(base)
        # Palette
        bg = "#0b0f14"      # near-black
        panel = "#11161d"   # dark slate
        acc = "#00d1b2"     # teal neon accent
        text = "#d3e1e8"    # pale
        sub = "#7aa2b2"     # muted cyan
        danger = "#ff657a"  # pink-red
        warn = "#f6c177"    # amber
        entrybg = "#0e131a"
        focus = "#1d2a36"

        root.configure(bg=bg)
        style.configure('.',
            background=panel,
            foreground=text,
            fieldbackground=entrybg,
            bordercolor=focus,
            focuscolor=acc,
            font=fonts.mono
        )
        style.map('.', highlightcolor=[('focus', acc)], foreground=[('disabled', sub)])
        style.configure('TEntry', padding=6)
        style.configure('TButton', padding=(10,6), relief='flat')
        style.map('TButton', background=[('active', focus)], foreground=[('active', text)])
        style.configure('Acc.TButton', background=acc, foreground="#001318")
        style.map('Acc.TButton', background=[('pressed', acc), ('active', acc)])
        style.configure('Danger.TButton', background=danger, foreground="#1a0e12")
        style.configure('Warn.TButton', background=warn, foreground="#1a1306")
        style.configure('Treeview', background=panel, fieldbackground=panel, foreground=text, rowheight=26)
        style.configure('Treeview.Heading', background=panel, foreground=sub)
        style.map('Treeview', background=[('selected', focus)])
        style.configure('TLabel', background=panel, foreground=text)
        style.configure('Status.TLabel', background=bg, foreground=sub)

class VaultGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("NeonVault")
        self.fonts = Fonts(root)
        self.style = DarkStyle(root, self.fonts)

        # State
        self.master_password: Optional[str] = None
        self.payload: VaultPayload = VaultPayload.empty()
        self.vault_path: str = VAULT_PATH
        self.clipboard_clear_after_ms = 25_000

        # UI
        self._build_ui()
        self._unlock_flow()

    # --- UI building --------------------------------------------------------
    def _build_ui(self):
        root = self.root
        # Top bar (search + buttons)
        top = ttk.Frame(root)
        top.pack(fill='x', padx=12, pady=10)

        self.search_var = tk.StringVar()
        e = ttk.Entry(top, textvariable=self.search_var, width=40, font=self.fonts.mono)
        e.pack(side='left', padx=(0,10))
        e.insert(0, "type to search…")
        e.bind('<FocusIn>', lambda _e: self._placeholder_clear(e, "type to search…"))
        e.bind('<KeyRelease>', lambda _e: self._refresh_table())

        ttk.Button(top, text="Generate", command=self._generate_and_copy, style='Acc.TButton').pack(side='left', padx=4)
        ttk.Button(top, text="Add", command=self._add_dialog).pack(side='left', padx=4)
        ttk.Button(top, text="Edit", command=self._edit_selected).pack(side='left', padx=4)
        ttk.Button(top, text="Delete", command=self._delete_selected, style='Danger.TButton').pack(side='left', padx=4)
        ttk.Button(top, text="Copy", command=self._copy_selected).pack(side='left', padx=4)
        ttk.Button(top, text="Lock", command=self._lock, style='Warn.TButton').pack(side='left', padx=12)
        ttk.Button(top, text="Save", command=self._save, style='Acc.TButton').pack(side='left', padx=4)
        ttk.Button(top, text="Vault…", command=self._choose_vault).pack(side='right', padx=4)

        # Table
        self.tree = ttk.Treeview(root, columns=("site","username","id"), show='headings')
        self.tree.pack(fill='both', expand=True, padx=12, pady=(0,10))
        self.tree.heading('site', text='Website / App')
        self.tree.heading('username', text='Account')
        self.tree.heading('id', text='ID')
        self.tree.column('site', width=380)
        self.tree.column('username', width=260)
        self.tree.column('id', width=120)
        self.tree.bind('<Double-1>', lambda _e: self._copy_selected())

        # Status bar
        self.status = ttk.Label(root, text="ready", style='Status.TLabel', anchor='w')
        self.status.pack(fill='x', padx=12, pady=(0,10))

        # Keybinds
        root.bind('<Control-f>', lambda _e: self._focus_search())
        root.bind('<Control-n>', lambda _e: self._add_dialog())
        root.bind('<Control-c>', lambda _e: self._copy_selected())
        root.bind('<Control-g>', lambda _e: self._generate_and_copy())
        root.bind('<Control-s>', lambda _e: self._save())

    def _placeholder_clear(self, entry: ttk.Entry, text: str):
        if entry.get() == text:
            entry.delete(0, 'end')

    # --- Vault flows ---------------------------------------------------------
    def _unlock_flow(self):
        if not os.path.exists(self.vault_path):
            res = messagebox.askyesno("Create Vault", f"No vault found at:\n{self.vault_path}\n\nCreate a new one?")
            if not res:
                self._choose_vault()
                return
            p1 = self._prompt_secret("Create Master Password")
            if not p1 or len(p1) < 10:
                messagebox.showwarning("Weak Password", "Use at least 10 characters.")
                self._unlock_flow(); return
            p2 = self._prompt_secret("Confirm Master Password")
            if p1 != p2:
                messagebox.showerror("Mismatch", "Passwords do not match.")
                self._unlock_flow(); return
            self.master_password = p1
            self.payload = VaultPayload.empty()
            self._save()
            self._flash("new vault created")
        else:
            # Unlock existing
            for _ in range(5):
                pw = self._prompt_secret("Master Password", allow_empty=False)
                if pw is None:
                    return
                try:
                    blob = load_vault(self.vault_path)
                    self.payload = decrypt_payload(pw, blob)
                    self.master_password = pw
                    self._flash("vault unlocked")
                    self._refresh_table()
                    return
                except Exception as e:
                    messagebox.showerror("Unlock Failed", f"{e}")
            messagebox.showwarning("Locked Out", "Too many failures.")

    def _choose_vault(self):
        path = filedialog.asksaveasfilename(initialfile=os.path.basename(self.vault_path), defaultextension=".dat", filetypes=[("Vault Files","*.dat"), ("All Files","*.*")])
        if path:
            self.vault_path = path
            self._unlock_flow()

    def _lock(self):
        self.master_password = None
        self.payload = VaultPayload.empty()
        for i in self.tree.get_children():
            self.tree.delete(i)
        self._flash("vault locked")
        self._unlock_flow()

    def _save(self):
        if not self.master_password:
            messagebox.showwarning("Locked", "Unlock the vault first.")
            return
        save_vault(self.vault_path, self.master_password, self.payload)
        self._flash("saved")

    # --- Table ops ----------------------------------------------------------
    def _refresh_table(self):
        q = self.search_var.get().strip().lower()
        for i in self.tree.get_children():
            self.tree.delete(i)
        for e in self._filtered(q):
            self.tree.insert('', 'end', iid=e.id, values=(e.site, e.username, e.id))

    def _filtered(self, q: str) -> List[Entry]:
        if not q or q == "type to search…":
            return sorted(self.payload.entries, key=lambda e: (e.site.lower(), e.username.lower()))
        return [e for e in self.payload.entries if q in e.site.lower() or q in e.username.lower() or q in e.id.lower()]

    def _get_selected(self) -> Optional[Entry]:
        sel = self.tree.selection()
        if not sel:
            return None
        eid = sel[0]
        for e in self.payload.entries:
            if e.id == eid:
                return e
        return None

    # --- Actions ------------------------------------------------------------
    def _add_dialog(self):
        self._entry_dialog()

    def _edit_selected(self):
        e = self._get_selected()
        if not e:
            self._flash("select an entry")
            return
        self._entry_dialog(e)

    def _delete_selected(self):
        e = self._get_selected()
        if not e:
            self._flash("select an entry")
            return
        if messagebox.askyesno("Delete", f"Delete {e.site}/{e.username}? This cannot be undone."):
            self.payload.entries = [x for x in self.payload.entries if x.id != e.id]
            self._save(); self._refresh_table()

    def _copy_selected(self):
        e = self._get_selected()
        if not e:
            self._flash("select an entry")
            return
        self._copy_to_clipboard(e.password)
        self._flash("password copied (auto-clears)")

    def _generate_and_copy(self):
        cfg = self.payload.pwgen
        pwd = gen_password(cfg.get('length', 20), cfg.get('sets'), cfg.get('avoid_ambiguous', True))
        self._copy_to_clipboard(pwd)
        self._flash("generated + copied (auto-clears)")

    # --- Dialogs ------------------------------------------------------------
    def _entry_dialog(self, entry: Optional[Entry]=None):
        dlg = tk.Toplevel(self.root)
        dlg.title("Edit Entry" if entry else "Add Entry")
        dlg.configure(bg="#0b0f14")
        dlg.transient(self.root)
        dlg.grab_set()

        def row(parent, label):
            frm = ttk.Frame(parent)
            ttk.Label(frm, text=label).pack(side='left', padx=(0,8))
            return frm

        p = ttk.Frame(dlg)
        p.pack(fill='both', expand=True, padx=14, pady=14)

        # Site
        r1 = row(p, "Website/App:")
        site_var = tk.StringVar(value=entry.site if entry else "")
        e_site = ttk.Entry(r1, textvariable=site_var, width=44, font=self.fonts.mono)
        e_site.pack(side='left', fill='x', expand=True)
        r1.pack(fill='x', pady=6)

        # Username
        r2 = row(p, "Account/User:")
        user_var = tk.StringVar(value=entry.username if entry else "")
        e_user = ttk.Entry(r2, textvariable=user_var, width=44, font=self.fonts.mono)
        e_user.pack(side='left', fill='x', expand=True)
        r2.pack(fill='x', pady=6)

        # Password
        r3 = row(p, "Password:")
        pwd_var = tk.StringVar(value=entry.password if entry else "")
        e_pwd = ttk.Entry(r3, textvariable=pwd_var, width=44, font=self.fonts.mono, show='•')
        e_pwd.pack(side='left', fill='x', expand=True)
        def toggle():
            e_pwd.configure(show='' if e_pwd.cget('show') == '•' else '•')
        ttk.Button(r3, text="show", command=toggle).pack(side='left', padx=6)
        def regen():
            cfg = self.payload.pwgen
            pwd_var.set(gen_password(cfg.get('length', 20), cfg.get('sets'), cfg.get('avoid_ambiguous', True)))
        ttk.Button(r3, text="generate", command=regen, style='Acc.TButton').pack(side='left', padx=6)
        ttk.Button(r3, text="copy", command=lambda: self._copy_to_clipboard(pwd_var.get())).pack(side='left', padx=6)
        r3.pack(fill='x', pady=6)

        # Notes
        r4 = row(p, "Notes:")
        notes_var = tk.StringVar(value=entry.notes if entry else "")
        e_notes = ttk.Entry(r4, textvariable=notes_var, width=44, font=self.fonts.mono)
        e_notes.pack(side='left', fill='x', expand=True)
        r4.pack(fill='x', pady=6)

        # Buttons
        btns = ttk.Frame(p)
        ttk.Button(btns, text="Cancel", command=dlg.destroy).pack(side='right', padx=6)
        def save_and_close():
            site = site_var.get().strip()
            user = user_var.get().strip()
            pwd = pwd_var.get()
            notes = notes_var.get()
            if not site or not user or not pwd:
                messagebox.showwarning("Missing", "Site, Account, and Password are required.")
                return
            if entry:
                entry.site = site
                entry.username = user
                entry.password = pwd
                entry.notes = notes
                entry.updated = now()
            else:
                eid = secrets.token_hex(4)
                self.payload.entries.append(Entry(id=eid, site=site, username=user, password=pwd, notes=notes))
            self._save(); self._refresh_table(); dlg.destroy()
        ttk.Button(btns, text="Save", command=save_and_close, style='Acc.TButton').pack(side='right', padx=6)
        btns.pack(fill='x', pady=(10,0))

        e_site.focus_set()
        dlg.wait_window()

    def _prompt_secret(self, title: str, allow_empty: bool = False) -> Optional[str]:
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.configure(bg="#0b0f14")
        dlg.transient(self.root)
        dlg.grab_set()
        frm = ttk.Frame(dlg); frm.pack(padx=14, pady=14)
        ttk.Label(frm, text=title).pack(anchor='w', pady=(0,8))
        var = tk.StringVar()
        e = ttk.Entry(frm, textvariable=var, show='•', width=36, font=self.fonts.mono_big)
        e.pack()
        e.focus_set()
        out = {"val": None}
        def ok():
            if not allow_empty and not var.get():
                return
            out["val"] = var.get(); dlg.destroy()
        def cancel():
            out["val"] = None; dlg.destroy()
        btns = ttk.Frame(frm)
        ttk.Button(btns, text="Cancel", command=cancel).pack(side='right', padx=6)
        ttk.Button(btns, text="OK", command=ok, style='Acc.TButton').pack(side='right', padx=6)
        btns.pack(fill='x', pady=(10,0))
        dlg.wait_window()
        return out["val"]

    # --- Utilities ----------------------------------------------------------
    def _focus_search(self):
        self.root.after(0, lambda: self.root.focus_force())
        for w in self.root.winfo_children():
            if isinstance(w, ttk.Frame):
                for child in w.winfo_children():
                    if isinstance(child, ttk.Entry):
                        child.focus_set(); child.select_range(0, 'end'); return

    def _copy_to_clipboard(self, text: str):
        if not text:
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            # schedule clear
            self.root.after(self.clipboard_clear_after_ms, self._clear_clipboard_if_match, text)
        except Exception:
            pass

    def _clear_clipboard_if_match(self, text: str):
        try:
            cur = self.root.clipboard_get()
            if cur == text:
                self.root.clipboard_clear()
                self._flash("clipboard cleared")
        except Exception:
            pass

    def _flash(self, msg: str):
        self.status.configure(text=msg)
        self.root.after(4000, lambda: self.status.configure(text="ready"))

# --- Main -------------------------------------------------------------------

def main():
    root = tk.Tk()
    # HiDPI friendly sizing
    try:
        if sys.platform == 'darwin':
            from ctypes import cdll
            # no-op on macOS with Tk 8.6+ which is HiDPI aware
        elif sys.platform.startswith('win'):
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    app = VaultGUI(root)
    root.minsize(760, 420)
    root.mainloop()

if __name__ == "__main__":
    main()
