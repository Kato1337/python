import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from cryptography.fernet import Fernet

current_key = None  # store loaded key

# function to generate a unique key and save it
def generate_key():
    global current_key
    key = Fernet.generate_key()
    file_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("key files", "*.key")])
    if file_path:
        with open(file_path, "wb") as key_file:
            key_file.write(key)
        current_key = key
        update_status(f"new key generated and saved as: {file_path}")

# function to load a key file
def load_key():
    global current_key
    file_path = filedialog.askopenfilename(filetypes=[("key files", "*.key")])
    if file_path:
        try:
            with open(file_path, "rb") as key_file:
                current_key = key_file.read()
            update_status(f"key loaded from: {file_path}")
        except Exception as e:
            messagebox.showerror("error", f"could not load key: {e}")

# encrypt the selected file
def encrypt_file():
    if not current_key:
        messagebox.showerror("error", "please load or generate a key first")
        return
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    fernet = Fernet(current_key)
    try:
        with open(file_path, "rb") as file:
            original = file.read()
        encrypted = fernet.encrypt(original)
        new_path = file_path + ".encrypted"
        with open(new_path, "wb") as enc_file:
            enc_file.write(encrypted)
        update_status(f"file encrypted and saved as: {new_path}")
    except Exception as e:
        messagebox.showerror("error", str(e))

# decrypt the selected file
def decrypt_file():
    if not current_key:
        messagebox.showerror("error", "please load or generate a key first")
        return
    file_path = filedialog.askopenfilename(filetypes=[("encrypted files", "*.encrypted"), ("all files", "*.*")])
    if not file_path:
        return
    fernet = Fernet(current_key)
    try:
        with open(file_path, "rb") as enc_file:
            encrypted = enc_file.read()
        decrypted = fernet.decrypt(encrypted)
        new_path = file_path.replace(".encrypted", "") + ".decrypted"
        with open(new_path, "wb") as dec_file:
            dec_file.write(decrypted)
        update_status(f"file decrypted and saved as: {new_path}")
    except Exception as e:
        messagebox.showerror("error", str(e))

# function to update the status box
def update_status(message):
    status_box.config(state=tk.NORMAL)
    status_box.insert(tk.END, message + "\n")
    status_box.config(state=tk.DISABLED)
    status_box.see(tk.END)

# gui setup
root = tk.Tk()
root.title("cybersecurity tool: advanced file encryption & decryption")
root.geometry("600x400")

frame = tk.Frame(root)
frame.pack(pady=10)

btn_generate = tk.Button(frame, text="generate key", width=20, command=generate_key)
btn_generate.grid(row=0, column=0, padx=5, pady=5)

btn_load = tk.Button(frame, text="load key", width=20, command=load_key)
btn_load.grid(row=0, column=1, padx=5, pady=5)

btn_encrypt = tk.Button(frame, text="encrypt file", width=20, command=encrypt_file)
btn_encrypt.grid(row=1, column=0, padx=5, pady=5)

btn_decrypt = tk.Button(frame, text="decrypt file", width=20, command=decrypt_file)
btn_decrypt.grid(row=1, column=1, padx=5, pady=5)

tk.Label(root, text="status:").pack(pady=5)
status_box = scrolledtext.ScrolledText(root, width=70, height=10, state=tk.DISABLED)
status_box.pack(pady=5)

root.mainloop()
