import tkinter as tk
from tkinter import ttk, messagebox

class ATMGUI:
    def __init__(self, master):
        self.master = master
        master.title("ATM Simulation")
        master.geometry("400x350")
        self.balance = 1000.0
        self.transactions = []

        self.notebook = ttk.Notebook(master)
        self.notebook.pack(expand=True, fill='both')

        # Balance Tab
        self.balance_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.balance_tab, text="Balance")

        self.balance_label = ttk.Label(self.balance_tab, text=f"Balance: ${self.balance:.2f}", font=("Arial", 16))
        self.balance_label.pack(pady=20)

        self.refresh_button = ttk.Button(self.balance_tab, text="Refresh", command=self.update_balance)
        self.refresh_button.pack(pady=5)

        # Deposit Tab
        self.deposit_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.deposit_tab, text="Deposit")

        ttk.Label(self.deposit_tab, text="Amount to Deposit:").pack(pady=10)
        self.deposit_entry = ttk.Entry(self.deposit_tab)
        self.deposit_entry.pack()
        self.deposit_button = ttk.Button(self.deposit_tab, text="Deposit", command=self.deposit)
        self.deposit_button.pack(pady=10)

        # Withdraw Tab
        self.withdraw_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.withdraw_tab, text="Withdraw")

        ttk.Label(self.withdraw_tab, text="Amount to Withdraw:").pack(pady=10)
        self.withdraw_entry = ttk.Entry(self.withdraw_tab)
        self.withdraw_entry.pack()
        self.withdraw_button = ttk.Button(self.withdraw_tab, text="Withdraw", command=self.withdraw)
        self.withdraw_button.pack(pady=10)

        # Transaction History Tab
        self.history_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.history_tab, text="History")

        self.history_listbox = tk.Listbox(self.history_tab, width=50, height=10)
        self.history_listbox.pack(pady=10)

        self.exit_button = ttk.Button(master, text="Exit", command=master.quit)
        self.exit_button.pack(pady=10)

        self.update_history()

    def update_balance(self):
        self.balance_label.config(text=f"Balance: ${self.balance:.2f}")

    def deposit(self):
        amount_str = self.deposit_entry.get()
        try:
            amount = float(amount_str)
            if amount > 0:
                self.balance += amount
                self.transactions.append(f"Deposited: ${amount:.2f}")
                self.update_balance()
                self.update_history()
                messagebox.showinfo("Deposit", f"${amount:.2f} deposited.")
                self.deposit_entry.delete(0, tk.END)
            else:
                messagebox.showerror("Error", "Enter a positive amount.")
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number.")

    def withdraw(self):
        amount_str = self.withdraw_entry.get()
        try:
            amount = float(amount_str)
            if amount <= 0:
                messagebox.showerror("Error", "Enter a positive amount.")
            elif amount > self.balance:
                messagebox.showerror("Error", "Insufficient funds.")
            else:
                self.balance -= amount
                self.transactions.append(f"Withdrew: ${amount:.2f}")
                self.update_balance()
                self.update_history()
                messagebox.showinfo("Withdraw", f"${amount:.2f} withdrawn.")
                self.withdraw_entry.delete(0, tk.END)
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number.")

    def update_history(self):
        self.history_listbox.delete(0, tk.END)
        for txn in self.transactions[-10:]:
            self.history_listbox.insert(tk.END, txn)

if __name__ == "__main__":
    root = tk.Tk()
    atm_gui = ATMGUI(root)
    root.mainloop()