#!/usr/bin/env python3
"""
secure password manager gui
all comments are lowercase as requested.
prerequisites: pip install cryptography
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json, os, base64, secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# ---------------- cryptographic helpers ----------------
# derive a 32-byte fernet-compatible key from a password and salt
def derive_key(password: str, salt: bytes, iterations: int = 390000) -> bytes:
    # password must be bytes for kdf
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key

# encrypt a json-serializable object and return bytes
def encrypt_data(obj, key: bytes) -> bytes:
    f = Fernet(key)
    raw = json.dumps(obj, ensure_ascii=False).encode('utf-8')
    return f.encrypt(raw)

# decrypt bytes and return python object
def decrypt_data(token: bytes, key: bytes):
    f = Fernet(key)
    plain = f.decrypt(token)
    return json.loads(plain.decode('utf-8'))

# ---------------- file format helpers ----------------
# file layout: 16 bytes salt length prefix? simpler: store a small json envelope:
# { "salt": base64, "iterations": n, "payload": base64(encrypted) }
def save_encrypted_file(path: str, payload_bytes: bytes, salt: bytes, iterations: int):
    envelope = {
        "salt": base64.b64encode(salt).decode('ascii'),
        "iterations": iterations,
        "payload": base64.b64encode(payload_bytes).decode('ascii')
    }
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(envelope, f)
    return True

def load_encrypted_file(path: str):
    with open(path, 'r', encoding='utf-8') as f:
        envelope = json.load(f)
    salt = base64.b64decode(envelope['salt'])
    iterations = envelope.get('iterations', 390000)
    payload = base64.b64decode(envelope['payload'])
    return salt, iterations, payload

# ---------------- password manager data model ----------------
# data structure: {"entries": [ { "id": <id>, "service": "", "username": "", "password": "", "notes": "" }, ... ] }
def make_empty_db():
    return {"entries": []}

def generate_id():
    return secrets.token_hex(8)

# ---------------- gui app ----------------
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("cybersecurity tool: secure password manager")
        self.db = make_empty_db()
        self.current_file = None
        self.fernet_key = None
        self.salt = None
        self.iterations = 390000

        # build ui
        self.build_menu()
        self.build_main_ui()
        self.update_title()

    def build_menu(self):
        menubar = tk.Menu(self.root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="new database", command=self.new_database)
        filemenu.add_command(label="open database", command=self.open_database)
        filemenu.add_command(label="save database", command=self.save_database)
        filemenu.add_command(label="save database as...", command=self.save_as_database)
        filemenu.add_separator()
        filemenu.add_command(label="exit", command=self.root.quit)
        menubar.add_cascade(label="file", menu=filemenu)
        self.root.config(menu=menubar)

    def build_main_ui(self):
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        # left: list of services
        left = ttk.Frame(frame)
        left.pack(side=tk.LEFT, fill=tk.Y)
        ttk.Label(left, text="services").pack(anchor='w')
        self.service_list = tk.Listbox(left, width=30)
        self.service_list.pack(fill=tk.Y, expand=True)
        self.service_list.bind('<<ListboxSelect>>', self.on_select)

        # right: details and actions
        right = ttk.Frame(frame)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10,0))

        # fields
        ttk.Label(right, text="service:").grid(row=0, column=0, sticky='w')
        self.entry_service = ttk.Entry(right, width=40)
        self.entry_service.grid(row=0, column=1, sticky='w')

        ttk.Label(right, text="username:").grid(row=1, column=0, sticky='w')
        self.entry_username = ttk.Entry(right, width=40)
        self.entry_username.grid(row=1, column=1, sticky='w')

        ttk.Label(right, text="password:").grid(row=2, column=0, sticky='w')
        self.entry_password = ttk.Entry(right, width=40, show='*')
        self.entry_password.grid(row=2, column=1, sticky='w')

        ttk.Button(right, text="generate password", command=self.generate_password_ui).grid(row=2, column=2, padx=5)

        ttk.Label(right, text="notes:").grid(row=3, column=0, sticky='nw')
        self.text_notes = tk.Text(right, width=40, height=6)
        self.text_notes.grid(row=3, column=1, columnspan=2, sticky='w')

        # action buttons
        btn_frame = ttk.Frame(right)
        btn_frame.grid(row=4, column=1, pady=10, sticky='w')

        ttk.Button(btn_frame, text="add / update entry", command=self.add_or_update_entry).grid(row=0, column=0, padx=3)
        ttk.Button(btn_frame, text="delete entry", command=self.delete_entry).grid(row=0, column=1, padx=3)
        ttk.Button(btn_frame, text="copy password", command=self.copy_password).grid(row=0, column=2, padx=3)

        # status bar
        self.status_var = tk.StringVar(value="no database loaded")
        status = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor='w')
        status.pack(side=tk.BOTTOM, fill=tk.X)

    # ---------------- ui actions ----------------
    def update_title(self):
        name = self.current_file if self.current_file else "untitled"
        locked = "locked" if not self.fernet_key else "unlocked"
        self.root.title(f"secure password manager - {name} ({locked})")

    def set_status(self, text):
        self.status_var.set(text)

    def new_database(self):
        # create new empty db and prompt for master password to lock it
        if not messagebox.askyesno("new", "create new encrypted database?"):
            return
        # choose file to save later
        path = filedialog.asksaveasfilename(defaultextension=".spm", filetypes=[("secure db","*.spm"), ("json","*.json")])
        if not path:
            return
        # ask for master password
        pw = self.prompt_password("set master password")
        if not pw:
            return
        # generate random salt and derive key
        self.salt = os.urandom(16)
        self.iterations = 390000
        self.fernet_key = derive_key(pw, self.salt, self.iterations)
        self.db = make_empty_db()
        self.current_file = path
        # save immediately (encrypted)
        payload = encrypt_data(self.db, self.fernet_key)
        save_encrypted_file(self.current_file, payload, self.salt, self.iterations)
        self.refresh_list()
        self.set_status(f"new database created and saved: {self.current_file}")
        self.update_title()

    def open_database(self):
        path = filedialog.askopenfilename(filetypes=[("secure db","*.spm"), ("json","*.json"), ("all files","*.*")])
        if not path:
            return
        try:
            salt, iterations, payload = load_encrypted_file(path)
        except Exception as e:
            messagebox.showerror("error", f"failed to read file: {e}")
            return
        # prompt for master password to derive key
        pw = self.prompt_password("enter master password to unlock")
        if not pw:
            return
        key = derive_key(pw, salt, iterations)
        # try decrypt
        try:
            db = decrypt_data(payload, key)
        except Exception:
            messagebox.showerror("error", "incorrect password or corrupted file")
            return
        # load into memory
        self.salt = salt
        self.iterations = iterations
        self.fernet_key = key
        self.db = db
        self.current_file = path
        self.refresh_list()
        self.set_status(f"database loaded: {self.current_file}")
        self.update_title()

    def save_database(self):
        if not self.current_file:
            return self.save_as_database()
        if not self.fernet_key:
            messagebox.showerror("error", "no unlocked key to encrypt with")
            return
        payload = encrypt_data(self.db, self.fernet_key)
        save_encrypted_file(self.current_file, payload, self.salt, self.iterations)
        self.set_status(f"database saved: {self.current_file}")

    def save_as_database(self):
        path = filedialog.asksaveasfilename(defaultextension=".spm", filetypes=[("secure db","*.spm"), ("json","*.json")])
        if not path:
            return
        self.current_file = path
        self.save_database()
        self.update_title()

    def prompt_password(self, title="master password"):
        # ask for password in a modal dialog using tkinter simpledialog-like approach
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.transient(self.root)
        dlg.grab_set()
        tk.Label(dlg, text=title + ":").pack(padx=10, pady=(10,0))
        ent = ttk.Entry(dlg, show='*', width=30)
        ent.pack(padx=10, pady=5)
        pw = {'value': None}

        def on_ok():
            pw['value'] = ent.get()
            dlg.destroy()

        def on_cancel():
            dlg.destroy()

        btnf = ttk.Frame(dlg)
        btnf.pack(pady=10)
        ttk.Button(btnf, text="ok", command=on_ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(btnf, text="cancel", command=on_cancel).pack(side=tk.LEFT, padx=5)
        self.root.wait_window(dlg)
        return pw['value']

    def refresh_list(self):
        # repopulate listbox from db entries
        self.service_list.delete(0, tk.END)
        for e in self.db.get('entries', []):
            display = f"{e.get('service','(no service)')} - {e.get('username','')}"
            self.service_list.insert(tk.END, display)

    def on_select(self, evt):
        sel = self.service_list.curselection()
        if not sel:
            return
        idx = sel[0]
        entry = self.db['entries'][idx]
        self.entry_service.delete(0, tk.END)
        self.entry_service.insert(0, entry.get('service',''))
        self.entry_username.delete(0, tk.END)
        self.entry_username.insert(0, entry.get('username',''))
        self.entry_password.delete(0, tk.END)
        self.entry_password.insert(0, entry.get('password',''))
        self.text_notes.delete('1.0', tk.END)
        self.text_notes.insert(tk.END, entry.get('notes',''))

    def add_or_update_entry(self):
        svc = self.entry_service.get().strip()
        user = self.entry_username.get().strip()
        pwd = self.entry_password.get().strip()
        notes = self.text_notes.get('1.0', tk.END).strip()
        if not svc:
            messagebox.showerror("error", "service name required")
            return
        # if an item is selected, update it; else add new
        sel = self.service_list.curselection()
        if sel:
            idx = sel[0]
            self.db['entries'][idx].update({"service": svc, "username": user, "password": pwd, "notes": notes})
            self.set_status(f"entry updated: {svc}")
        else:
            new_entry = {"id": generate_id(), "service": svc, "username": user, "password": pwd, "notes": notes}
            self.db['entries'].append(new_entry)
            self.set_status(f"entry added: {svc}")
        self.refresh_list()

    def delete_entry(self):
        sel = self.service_list.curselection()
        if not sel:
            messagebox.showerror("error", "select an entry to delete")
            return
        idx = sel[0]
        svc = self.db['entries'][idx].get('service','')
        if not messagebox.askyesno("confirm", f"delete entry for '{svc}'?"):
            return
        del self.db['entries'][idx]
        self.refresh_list()
        self.set_status(f"entry deleted: {svc}")

    def copy_password(self):
        sel = self.service_list.curselection()
        if not sel:
            messagebox.showerror("error", "select an entry first")
            return
        idx = sel[0]
        pwd = self.db['entries'][idx].get('password','')
        if not pwd:
            messagebox.showinfo("info", "no password stored for this entry")
            return
        # copy to clipboard
        self.root.clipboard_clear()
        self.root.clipboard_append(pwd)
        self.set_status("password copied to clipboard (paste within 30s)")
        # optionally clear clipboard after 30s for safety
        self.root.after(30000, self.clear_clipboard)

    def clear_clipboard(self):
        try:
            self.root.clipboard_clear()
            self.set_status("clipboard cleared")
        except Exception:
            pass

    def generate_password_ui(self):
        # simple generator dialog
        dlg = tk.Toplevel(self.root)
        dlg.title("generate password")
        dlg.transient(self.root)
        dlg.grab_set()

        tk.Label(dlg, text="length:").grid(row=0, column=0, padx=5, pady=5)
        len_ent = ttk.Entry(dlg, width=6)
        len_ent.grid(row=0, column=1, padx=5, pady=5)
        len_ent.insert(0, "16")

        var_upper = tk.BooleanVar(value=True)
        var_digits = tk.BooleanVar(value=True)
        var_symbols = tk.BooleanVar(value=True)
        ttk.Checkbutton(dlg, text="upper", variable=var_upper).grid(row=1, column=0, padx=5, sticky='w')
        ttk.Checkbutton(dlg, text="digits", variable=var_digits).grid(row=1, column=1, padx=5, sticky='w')
        ttk.Checkbutton(dlg, text="symbols", variable=var_symbols).grid(row=1, column=2, padx=5, sticky='w')

        def on_gen():
            try:
                length = int(len_ent.get())
                chars = "abcdefghijklmnopqrstuvwxyz"
                if var_upper.get(): chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                if var_digits.get(): chars += "0123456789"
                if var_symbols.get(): chars += "!@#$%^&*()-_=+[]{};:,.<>/?"
                pwd = ''.join(secrets.choice(chars) for _ in range(max(4, length)))
                # put generated password into password entry
                self.entry_password.delete(0, tk.END)
                self.entry_password.insert(0, pwd)
                dlg.destroy()
            except Exception:
                messagebox.showerror("error", "invalid length")

        ttk.Button(dlg, text="generate", command=on_gen).grid(row=2, column=0, columnspan=3, pady=10)
        self.root.wait_window(dlg)

# ---------------- run app ----------------
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
