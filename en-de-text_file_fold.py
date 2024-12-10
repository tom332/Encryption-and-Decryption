import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64

# Function to derive a key from a password
def derive_key(password):
    salt = b'\x00' * 16  # Use a fixed salt (for simplicity)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to encrypt data
def encrypt(data, key):
    iv = os.urandom(12)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return base64.b64encode(iv + encryptor.tag + ciphertext).decode()

# Function to decrypt data
def decrypt(data, key):
    raw_data = base64.b64decode(data)
    iv = raw_data[:12]
    tag = raw_data[12:28]
    ciphertext = raw_data[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Encrypt a single file
def encrypt_file():
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password!")
        return
    key = derive_key(password)
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        encrypted_data = encrypt(data, key)
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, "w") as f:
            f.write(encrypted_data)
        os.remove(file_path)  # Remove original file after encryption
        messagebox.showinfo("Success", f"File encrypted: {encrypted_file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"File encryption failed: {e}")

# Decrypt a single file
def decrypt_file():
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password!")
        return
    key = derive_key(password)
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    try:
        with open(file_path, "r") as f:
            data = f.read()
        decrypted_data = decrypt(data, key)
        decrypted_file_path = file_path.replace(".enc", "")
        with open(decrypted_file_path, "wb") as f:
            f.write(decrypted_data)
        os.remove(file_path)  # Remove encrypted file after decryption
        messagebox.showinfo("Success", f"File decrypted: {decrypted_file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"File decryption failed: {e}")

# Encrypt all files in a folder and its subfolders
def encrypt_folder():
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password!")
        return
    key = derive_key(password)
    folder_path = filedialog.askdirectory()
    if not folder_path:
        return
    try:
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                with open(file_path, "rb") as f:
                    data = f.read()
                encrypted_data = encrypt(data, key)
                with open(file_path + ".enc", "w") as f:
                    f.write(encrypted_data)
                os.remove(file_path)  # Remove original file after encryption
        messagebox.showinfo("Success", f"Folder encrypted successfully, including subfolders: {folder_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Folder encryption failed: {e}")

# Decrypt all files in a folder and its subfolders
def decrypt_folder():
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password!")
        return
    key = derive_key(password)
    folder_path = filedialog.askdirectory()
    if not folder_path:
        return
    try:
        for root, _, files in os.walk(folder_path):
            for file in files:
                if file.endswith(".enc"):
                    file_path = os.path.join(root, file)
                    with open(file_path, "r") as f:
                        data = f.read()
                    decrypted_data = decrypt(data, key)
                    original_file_path = file_path.replace(".enc", "")
                    with open(original_file_path, "wb") as f:
                        f.write(decrypted_data)
                    os.remove(file_path)  # Remove encrypted file after decryption
        messagebox.showinfo("Success", f"Folder decrypted successfully, including subfolders: {folder_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Folder decryption failed: {e}")

# GUI implementation
def encrypt_text():
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password!")
        return
    key = derive_key(password)
    input_text = text_input.get("1.0", tk.END).strip()
    if not input_text:
        messagebox.showerror("Error", "Input text is empty!")
        return
    try:
        encrypted_text = encrypt(input_text.encode(), key)
        text_output.delete("1.0", tk.END)
        text_output.insert(tk.END, encrypted_text)
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

def decrypt_text():
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password!")
        return
    key = derive_key(password)
    input_text = text_input.get("1.0", tk.END).strip()
    if not input_text:
        messagebox.showerror("Error", "Input text is empty!")
        return
    try:
        decrypted_text = decrypt(input_text, key).decode()
        text_output.delete("1.0", tk.END)
        text_output.insert(tk.END, decrypted_text)
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

# Create the main window
root = tk.Tk()
root.title("Symmetric Encryption Tool")

# Password
tk.Label(root, text="Password:").grid(row=0, column=0, padx=10, pady=5)
password_entry = tk.Entry(root, show="*")
password_entry.grid(row=0, column=1, columnspan=3, padx=10, pady=5)

# Text input/output
tk.Label(root, text="Input Text:").grid(row=1, column=0, padx=10, pady=5)
text_input = tk.Text(root, height=10, width=50)
text_input.grid(row=1, column=1, columnspan=3, padx=10, pady=5)

tk.Label(root, text="Output Text:").grid(row=2, column=0, padx=10, pady=5)
text_output = tk.Text(root, height=10, width=50)
text_output.grid(row=2, column=1, columnspan=3, padx=10, pady=5)

# Buttons
tk.Button(root, text="Encrypt Text", command=encrypt_text).grid(row=3, column=0, padx=10, pady=5)
tk.Button(root, text="Decrypt Text", command=decrypt_text).grid(row=3, column=1, padx=10, pady=5)
tk.Button(root, text="Encrypt File", command=encrypt_file).grid(row=3, column=2, padx=10, pady=5)
tk.Button(root, text="Decrypt File", command=decrypt_file).grid(row=3, column=3, padx=10, pady=5)
tk.Button(root, text="Encrypt Folder", command=encrypt_folder).grid(row=4, column=1, padx=10, pady=5)
tk.Button(root, text="Decrypt Folder", command=decrypt_folder).grid(row=4, column=2, padx=10, pady=5)

# Run the main loop
root.mainloop()
