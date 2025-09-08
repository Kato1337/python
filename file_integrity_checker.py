import hashlib
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox

# function to calculate sha256 hash of a file
def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        return None

# function to browse and select a file
def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        entry_file.delete(0, tk.END)
        entry_file.insert(0, file_path)

# function to generate baseline hash
def generate_baseline():
    file_path = entry_file.get().strip()
    if not file_path:
        messagebox.showerror("error", "please select a file first")
        return
    hash_value = calculate_hash(file_path)
    if hash_value:
        baseline_box.delete(1.0, tk.END)
        baseline_box.insert(tk.END, hash_value)
        messagebox.showinfo("baseline saved", "baseline hash generated successfully")
    else:
        messagebox.showerror("error", "could not read file")

# function to check file integrity
def check_integrity():
    file_path = entry_file.get().strip()
    if not file_path:
        messagebox.showerror("error", "please select a file first")
        return
    baseline = baseline_box.get(1.0, tk.END).strip()
    if not baseline:
        messagebox.showerror("error", "please generate or paste a baseline hash first")
        return
    current_hash = calculate_hash(file_path)
    if not current_hash:
        messagebox.showerror("error", "could not read file")
        return
    if current_hash == baseline:
        messagebox.showinfo("integrity check", "file is unchanged ✅")
    else:
        messagebox.showwarning("integrity check", "file has been modified ❌")

# main gui setup
root = tk.Tk()
root.title("cybersecurity tool: file integrity checker")
root.geometry("600x400")

frame = tk.Frame(root)
frame.pack(pady=10)

tk.Label(frame, text="file path:").grid(row=0, column=0, sticky="w")
entry_file = tk.Entry(frame, width=40)
entry_file.grid(row=0, column=1, padx=5)
browse_button = tk.Button(frame, text="browse", command=browse_file)
browse_button.grid(row=0, column=2)

baseline_button = tk.Button(root, text="generate baseline", command=generate_baseline)
baseline_button.pack(pady=5)

tk.Label(root, text="baseline hash (sha256):").pack()
baseline_box = scrolledtext.ScrolledText(root, width=70, height=5)
baseline_box.pack(pady=5)

check_button = tk.Button(root, text="check integrity", command=check_integrity)
check_button.pack(pady=10)

root.mainloop()
