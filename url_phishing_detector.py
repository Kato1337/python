import tkinter as tk
from tkinter import messagebox
import re

# function to check if url looks suspicious
def check_url():
    url = entry_url.get().strip()

    if not url:
        messagebox.showerror("error", "please enter a url")
        return

    issues = []

    # check if url uses ip address instead of domain
    if re.match(r"^(http[s]?://)?\d+\.\d+\.\d+\.\d+", url):
        issues.append("url uses ip address instead of domain")

    # check if url has '@' symbol
    if "@" in url:
        issues.append("url contains '@' symbol, might redirect")

    # check if url length is too long
    if len(url) > 100:
        issues.append("url is unusually long")

    # check if url has too many subdomains
    if url.count(".") > 4:
        issues.append("url contains excessive subdomains")

    # check for common phishing keywords
    phishing_keywords = ["secure", "account", "update", "login", "verify", "banking"]
    for keyword in phishing_keywords:
        if keyword in url.lower():
            issues.append(f"url contains suspicious keyword: '{keyword}'")

    # result
    if issues:
        result = "⚠️ suspicious url detected"
        feedback = "\n".join(f"- {i}" for i in issues)
    else:
        result = "✅ url looks safe"
        feedback = "no common phishing indicators found"

    messagebox.showinfo("url analysis", f"{result}\n\n{feedback}")

# gui setup
root = tk.Tk()
root.title("cybersecurity tool: url phishing detector")
root.geometry("500x200")

tk.Label(root, text="enter url:").pack(pady=5)
entry_url = tk.Entry(root, width=50)
entry_url.pack(pady=5)

check_button = tk.Button(root, text="check url", command=check_url)
check_button.pack(pady=10)

root.mainloop()
