import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
import time

# function to scan a single port
def scan_port(host, port, output_box):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # 1 second timeout
        result = sock.connect_ex((host, port))  # 0 means open
        if result == 0:
            output_box.insert(tk.END, f"[+] port {port} is open\n")
        sock.close()
    except Exception:
        pass  # ignore errors

# function to scan a range of ports
def port_scanner(host, start_port, end_port, output_box, loading_label):
    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, f"scanning host: {host}\n")
    output_box.insert(tk.END, f"scanning ports {start_port} to {end_port}...\n\n")

    threads = []
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(host, port, output_box))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    loading_label.config(text="")  # clear loading text
    output_box.insert(tk.END, "\nscan complete.\n")

# function for showing a loading spinner if scan takes longer than 3s
def show_loading(loading_label, stop_event):
    spinner = ["|", "/", "-", "\\"]
    idx = 0
    while not stop_event.is_set():
        loading_label.config(text=f"scanning... {spinner[idx % len(spinner)]}")
        idx += 1
        time.sleep(0.2)

# function triggered by gui button
def start_scan():
    host = entry_host.get().strip()
    try:
        # try resolving the host first
        try:
            socket.gethostbyname(host)
        except socket.gaierror:
            messagebox.showerror("error", "invalid ip address or domain")
            return

        start = int(entry_start.get())
        end = int(entry_end.get())
        if start < 1 or end > 65535 or start > end:
            messagebox.showerror("error", "invalid port range")
            return

        stop_event = threading.Event()
        loading_thread = threading.Thread(target=show_loading, args=(loading_label, stop_event))
        loading_thread.daemon = True

        # start delayed loading indicator
        def delayed_start():
            time.sleep(3)
            if not stop_event.is_set():
                loading_thread.start()

        threading.Thread(target=delayed_start, daemon=True).start()

        # start scanning in another thread
        scan_thread = threading.Thread(
            target=lambda: (port_scanner(host, start, end, output_box, loading_label), stop_event.set())
        )
        scan_thread.start()

    except ValueError:
        messagebox.showerror("error", "please enter valid numbers for ports")

# main gui setup
root = tk.Tk()
root.title("cybersecurity tool: port scanner")
root.geometry("500x450")

frame = tk.Frame(root)
frame.pack(pady=10)

tk.Label(frame, text="target host:").grid(row=0, column=0, sticky="w")
entry_host = tk.Entry(frame, width=30)
entry_host.grid(row=0, column=1)

tk.Label(frame, text="start port:").grid(row=1, column=0, sticky="w")
entry_start = tk.Entry(frame, width=10)
entry_start.grid(row=1, column=1, sticky="w")
entry_start.insert(0, "1")

tk.Label(frame, text="end port:").grid(row=2, column=0, sticky="w")
entry_end = tk.Entry(frame, width=10)
entry_end.grid(row=2, column=1, sticky="w")
entry_end.insert(0, "1024")

scan_button = tk.Button(root, text="start scan", command=start_scan)
scan_button.pack(pady=5)

loading_label = tk.Label(root, text="", fg="blue")
loading_label.pack()

output_box = scrolledtext.ScrolledText(root, width=60, height=15)
output_box.pack(pady=10)

root.mainloop()
