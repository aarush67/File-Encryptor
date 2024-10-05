import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()

def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    with open(file_path, 'wb') as file:
        file.write(encrypted)

def decrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        encrypted = file.read()
    decrypted = fernet.decrypt(encrypted)
    with open(file_path, 'wb') as file:
        file.write(decrypted)

def encrypt_folder(folder_path, key):
    for dirpath, _, filenames in os.walk(folder_path):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            encrypt_file(file_path, key)

def decrypt_folder(folder_path, key):
    for dirpath, _, filenames in os.walk(folder_path):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            decrypt_file(file_path, key)

def select_file_to_encrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        key = generate_key()
        encrypt_file(file_path, key)
        messagebox.showinfo("Success", f"File encrypted. ⚠️ WARNING: Store this key securely. You will not be able to decrypt without it.\nKey: {key.decode()}")

def select_folder_to_encrypt():
    folder_path = filedialog.askdirectory()
    if folder_path:
        key = generate_key()
        encrypt_folder(folder_path, key)
        messagebox.showinfo("Success", f"Folder encrypted. ⚠️ WARNING: Store this key securely. You will not be able to decrypt without it.\nKey: {key.decode()}")

def select_file_to_decrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        key = simpledialog.askstring("Input", "Enter the decryption key:")
        if key:
            decrypt_file(file_path, key.encode())
            messagebox.showinfo("Success", "File decrypted.")

def select_folder_to_decrypt():
    folder_path = filedialog.askdirectory()
    if folder_path:
        key = simpledialog.askstring("Input", "Enter the decryption key:")
        if key:
            decrypt_folder(folder_path, key.encode())
            messagebox.showinfo("Success", "Folder decrypted.")

def create_gui():
    root = tk.Tk()
    root.title("Modern File Encryptor")
    root.geometry("600x500")
    root.configure(bg="#ffffff")  # White background for the app

    # Header (Navigation Bar)
    header = tk.Frame(root, bg="#007acc", height=50)
    header.pack(fill=tk.X)

    nav_home = tk.Button(header, text="Home", font=("Helvetica", 14), bg="#007acc", fg="black",
                         command=lambda: switch_page(home_page))
    nav_home.pack(side=tk.LEFT, padx=20, pady=10)

    nav_encrypt = tk.Button(header, text="Encrypt", font=("Helvetica", 14), bg="#007acc", fg="black",
                            command=lambda: switch_page(encrypt_page))
    nav_encrypt.pack(side=tk.LEFT, padx=20, pady=10)

    nav_decrypt = tk.Button(header, text="Decrypt", font=("Helvetica", 14), bg="#007acc", fg="black",
                            command=lambda: switch_page(decrypt_page))
    nav_decrypt.pack(side=tk.LEFT, padx=20, pady=10)

    # Body Frame
    body = tk.Frame(root, bg="#ffffff", padx=20, pady=20)  # White background for body
    body.pack(expand=True, fill=tk.BOTH)

    def switch_page(page_function):
        """Helper function to switch between pages."""
        for widget in body.winfo_children():
            widget.destroy()
        page_function()

    def home_page():
        welcome_label = tk.Label(body, text="Welcome to File Encryptor", font=("Helvetica", 18), bg="#ffffff", fg="#000000")
        welcome_label.pack(pady=20)

        instructions = tk.Label(body, text="Choose an option below or use the navigation bar.", font=("Helvetica", 12), bg="#ffffff", fg="#333333")
        instructions.pack(pady=10)

        encrypt_button = tk.Button(body, text="Encrypt Files/Folders", font=("Helvetica", 14), bg="#ffffff", fg="#000000",  # White button with black text
                                   padx=10, pady=5, width=25, command=lambda: switch_page(encrypt_page))
        encrypt_button.pack(pady=10)

        decrypt_button = tk.Button(body, text="Decrypt Files/Folders", font=("Helvetica", 14), bg="#ffffff", fg="#000000",  # White button with black text
                                   padx=10, pady=5, width=25, command=lambda: switch_page(decrypt_page))
        decrypt_button.pack(pady=10)

    def encrypt_page():
        encrypt_label = tk.Label(body, text="Encrypt Files or Folders", font=("Helvetica", 18), bg="#ffffff", fg="#000000")
        encrypt_label.pack(pady=20)

        file_button = tk.Button(body, text="Select File to Encrypt", font=("Helvetica", 14), bg="#ffffff", fg="#000000",  # White button with black text
                                padx=10, pady=5, width=25, command=select_file_to_encrypt)
        file_button.pack(pady=10)

        folder_button = tk.Button(body, text="Select Folder to Encrypt", font=("Helvetica", 14), bg="#ffffff", fg="#000000",  # White button with black text
                                  padx=10, pady=5, width=25, command=select_folder_to_encrypt)
        folder_button.pack(pady=10)

    def decrypt_page():
        decrypt_label = tk.Label(body, text="Decrypt Files or Folders", font=("Helvetica", 18), bg="#ffffff", fg="#000000")
        decrypt_label.pack(pady=20)

        file_button = tk.Button(body, text="Select File to Decrypt", font=("Helvetica", 14), bg="#ffffff", fg="#000000",  # White button with black text
                                padx=10, pady=5, width=25, command=select_file_to_decrypt)
        file_button.pack(pady=10)

        folder_button = tk.Button(body, text="Select Folder to Decrypt", font=("Helvetica", 14), bg="#ffffff", fg="#000000",  # White button with black text
                                  padx=10, pady=5, width=25, command=select_folder_to_decrypt)
        folder_button.pack(pady=10)

    home_page()  # Start on the home page
    root.mainloop()

if __name__ == "__main__":
    create_gui()