#!/usr/bin/env python3
"""
cybersec_tool_gui.py - Cybersecurity Utility with GUI
"""

import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib, secrets, string, math, os

COMMON_PASSWORDS = {
    'sunshine','qwerty','iloveyou','princess','admin','welcome','666666',
    'abc123','football','monkey','login','starwars'
}

# ---------------- Core Functions ---------------- #
def estimate_entropy(password: str) -> float:
    charset = 0
    if any(c.islower() for c in password): charset += 26
    if any(c.isupper() for c in password): charset += 26
    if any(c.isdigit() for c in password): charset += 10
    if any(c in string.punctuation for c in password): charset += len(string.punctuation)
    if charset == 0:
        return 0.0
    return len(password) * math.log2(charset)

def classify_entropy(bits: float) -> str:
    if bits < 28: return "Very weak"
    if bits < 36: return "Weak"
    if bits < 60: return "Reasonable"
    if bits < 128: return "Strong"
    return "Very strong"

def password_strength(password: str):
    ent = estimate_entropy(password)
    classification = classify_entropy(ent)
    is_common = password.lower() in COMMON_PASSWORDS
    return round(ent, 2), classification, is_common

def generate_password(length: int = 16, use_upper=True, use_digits=True, use_symbols=True) -> str:
    if length < 4:
        raise ValueError('Password length too short')
    alphabet = string.ascii_lowercase
    if use_upper: alphabet += string.ascii_uppercase
    if use_digits: alphabet += string.digits
    if use_symbols: alphabet += string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def compute_hash(text: str, algorithm: str = 'sha256') -> str:
    h = hashlib.new(algorithm)
    h.update(text.encode('utf-8'))
    return h.hexdigest()

def file_hash(path: str, algorithm: str = 'sha256') -> str:
    h = hashlib.new(algorithm)
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

# ---------------- GUI Functions ---------------- #
def check_password():
    pwd = entry_password.get()
    if not pwd:
        messagebox.showwarning("Input Error", "Enter a password to check")
        return
    ent, classification, is_common = password_strength(pwd)
    result = f"Entropy: {ent} bits\nStrength: {classification}\nCommon Password: {is_common}"
    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, result)

def make_password():
    try:
        length = int(entry_length.get())
        pwd = generate_password(length)
        entry_password.delete(0, tk.END)
        entry_password.insert(0, pwd)
        messagebox.showinfo("Generated Password", pwd)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def hash_text():
    text = entry_text.get()
    algo = var_algo.get()
    if not text:
        messagebox.showwarning("Input Error", "Enter text to hash")
        return
    digest = compute_hash(text, algo)
    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, f"{algo.upper()}:\n{digest}")

def hash_file():
    algo = var_algo.get()
    filepath = filedialog.askopenfilename()
    if not filepath:
        return
    digest = file_hash(filepath, algo)
    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, f"{algo.upper()}:\n{digest}\n\nFile: {os.path.basename(filepath)}")

# ---------------- Build GUI ---------------- #
root = tk.Tk()
root.title("Cybersecurity Tool")

# Password frame
frame_pwd = tk.LabelFrame(root, text="Password Tools", padx=10, pady=10)
frame_pwd.pack(padx=10, pady=5, fill="x")

tk.Label(frame_pwd, text="Password:").grid(row=0, column=0, sticky="w")
entry_password = tk.Entry(frame_pwd, width=40, show="*")
entry_password.grid(row=0, column=1)

btn_check = tk.Button(frame_pwd, text="Check Strength", command=check_password)
btn_check.grid(row=0, column=2, padx=5)

tk.Label(frame_pwd, text="Length:").grid(row=1, column=0, sticky="w")
entry_length = tk.Entry(frame_pwd, width=5)
entry_length.insert(0, "16")
entry_length.grid(row=1, column=1, sticky="w")

btn_generate = tk.Button(frame_pwd, text="Generate Password", command=make_password)
btn_generate.grid(row=1, column=2, padx=5)

# Hash frame
frame_hash = tk.LabelFrame(root, text="Hash Tools", padx=10, pady=10)
frame_hash.pack(padx=10, pady=5, fill="x")

tk.Label(frame_hash, text="Text:").grid(row=0, column=0, sticky="w")
entry_text = tk.Entry(frame_hash, width=40)
entry_text.grid(row=0, column=1)

var_algo = tk.StringVar(value="sha256")
tk.OptionMenu(frame_hash, var_algo, "sha1", "sha256", "sha512").grid(row=0, column=2)

btn_hash_text = tk.Button(frame_hash, text="Hash Text", command=hash_text)
btn_hash_text.grid(row=1, column=1, sticky="w", pady=5)

btn_hash_file = tk.Button(frame_hash, text="Hash File", command=hash_file)
btn_hash_file.grid(row=1, column=2, padx=5)

# Output frame
frame_output = tk.LabelFrame(root, text="Output", padx=10, pady=10)
frame_output.pack(padx=10, pady=5, fill="both", expand=True)

text_output = tk.Text(frame_output, height=10, wrap="word")
text_output.pack(fill="both", expand=True)

root.mainloop()
