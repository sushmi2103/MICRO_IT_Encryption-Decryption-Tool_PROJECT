import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import os

# 1. Generate and save encryption key
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    messagebox.showinfo("Success", "Encryption key generated as 'secret.key'")

# 2. Load the encryption key
def load_key():
    if not os.path.exists("secret.key"):
        messagebox.showerror("Error", "Key file not found. Please generate the key first.")
        return None
    return open("secret.key", "rb").read()

# 3. Encrypt a selected file
def encrypt_file():
    filepath = filedialog.askopenfilename()
    if filepath:
        key = load_key()
        if not key:
            return
        fernet = Fernet(key)
        try:
            with open(filepath, "rb") as file:
                original = file.read()
            encrypted = fernet.encrypt(original)
            with open(filepath, "wb") as encrypted_file:
                encrypted_file.write(encrypted)
            messagebox.showinfo("Success", f"File '{os.path.basename(filepath)}' encrypted successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

# 4. Decrypt a selected file
def decrypt_file():
    filepath = filedialog.askopenfilename()
    if filepath:
        key = load_key()
        if not key:
            return
        fernet = Fernet(key)
        try:
            with open(filepath, "rb") as encrypted_file:
                encrypted = encrypted_file.read()
            decrypted = fernet.decrypt(encrypted)
            with open(filepath, "wb") as decrypted_file:
                decrypted_file.write(decrypted)
            messagebox.showinfo("Success", f"File '{os.path.basename(filepath)}' decrypted successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

# 5. Build the GUI
def create_gui():
    root = tk.Tk()
    root.title("File Encryption/Decryption Tool")
    root.geometry("400x300")
    root.resizable(False, False)

    tk.Label(root, text="File Encryption/Decryption Tool", font=("Arial", 16, "bold")).pack(pady=20)

    tk.Button(root, text="Generate Key", width=25, command=generate_key).pack(pady=10)
    tk.Button(root, text="Encrypt File", width=25, command=encrypt_file).pack(pady=10)
    tk.Button(root, text="Decrypt File", width=25, command=decrypt_file).pack(pady=10)

    tk.Label(root, text="Keep your 'secret.key' file safe!", font=("Arial", 10, "italic")).pack(pady=20)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
