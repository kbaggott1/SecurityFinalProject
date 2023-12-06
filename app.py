import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText

from main import *

# Tkinter UI class
class EncryptionApp:
    def __init__(self, root):
        self.root = root
        root.title('Encryption Tool')
        root.geometry('800x500')
        root.resizable(False, False)  

        # Styling
        style = ttk.Style()
        style.configure('TLabel', font=('Arial', 12))
        style.configure('TButton', font=('Arial', 12))
        style.configure('TEntry', font=('Arial', 12))
        style.configure('TCombobox', font=('Arial', 12))
        
        # Create a frame for layout management
        frame = ttk.Frame(root, padding="20 20 20 20")
        frame.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        # Dropdown for choosing encryption method
        self.method_var = tk.StringVar()
        self.methods = ['Caesar', 'RSA', 'DES', 'AES', 'Blowfish', 'CAST5', 'ChaCha20', 'TwoFish', 'DSA', 'ECC']
        default_method = self.methods[0]
        ttk.Label(frame, text='Choose encryption method:').grid(column=0, row=0, sticky=tk.W)
        self.method_menu = ttk.Combobox(frame, textvariable=self.method_var, values=self.methods, state='readonly', width=20)
        self.method_menu.grid(column=1, row=0, sticky=tk.W)
        self.method_var.set(default_method)

        # Dropdown for choosing mode
        self.mode_var = tk.StringVar()
        self.modes = ['encrypt', 'decrypt']
        default_mode = self.modes[0]
        ttk.Label(frame, text=default_mode).grid(column=0, row=1, sticky=tk.W)
        self.mode_menu = ttk.Combobox(frame, textvariable=self.mode_var, values=self.modes, state='readonly', width=20)
        self.mode_menu.grid(column=1, row=1, sticky=tk.W)
        self.mode_var.set(default_mode)

        # Input for keys
        ttk.Label(frame, text='Key:').grid(column=0, row=2, sticky=tk.W)
        self.key_var = tk.StringVar()
        self.key_input = tk.Entry(frame, textvariable=self.key_var, width=30)
        self.key_input.grid(column=1, row=2, sticky=tk.W)

        # Submit button
        self.submit_button = ttk.Button(frame, text=self.mode_var.get(), command=self.submit)
        self.submit_button.grid(column=1, row=3, sticky=tk.W, pady=10, padx=5)

        # Text widget for input
        ttk.Label(frame, text='Input:').grid(column=0, row=4, sticky=tk.W)
        self.text_input = ScrolledText(frame, wrap=tk.WORD, width=50, height=15, font=('Arial', 10))
        self.text_input.grid(column=0, row=5, columnspan=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10, padx=5)

        #Text widget for signature
        self.singature_label = ttk.Label(frame, text='Signature:')
        self.singature_var = tk.StringVar()
        self.singature_input = tk.Entry(frame, textvariable=self.singature_var, width=30)
        self.singature_label.grid_remove()
        self.singature_input.grid_remove()

        #Text widget for nonce
        self.nonce_label = ttk.Label(frame, text='Nonce:')
        self.nonce_var = tk.StringVar()
        self.nonce_input = tk.Entry(frame, textvariable=self.nonce_var, width=30)
        self.nonce_label.grid_remove()
        self.nonce_input.grid_remove()

        # Text widget for output
        ttk.Label(frame, text='Output:').grid(column=1, row=4, sticky=tk.W)
        self.result_text = ScrolledText(frame, wrap=tk.WORD, width=50, height=15, font=('Arial', 10))
        self.result_text.grid(column=1, row=5, columnspan=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10, padx=5)

        # Update UI based on method selection
        self.method_menu.bind('<<ComboboxSelected>>', self.update_ui)
        self.mode_menu.bind('<<ComboboxSelected>>', self.update_button)

    def update_ui(self, event=None):
        selected_method = self.method_var.get()
        self.key_var.set("")

        if selected_method == 'DSA' or selected_method == 'ECC':
            self.modes = ['sign', 'verify']
            self.singature_label.grid(column=0, row=6, sticky=tk.W)
            self.singature_input.grid(column=0, row=7, sticky=tk.W)
        else:
            self.modes = ['encrypt', 'decrypt']
            self.singature_label.grid_remove()
            self.singature_input.grid_remove()
        
        if selected_method == 'ChaCha20':
            self.nonce_label.grid(column=0, row=6, sticky=tk.W)
            self.nonce_input.grid(column=0, row=7, sticky=tk.W)
        else:
            self.nonce_label.grid_remove()
            self.nonce_input.grid_remove()

        self.mode_menu.config(values=self.modes)
        self.mode_var.set(self.modes[0])
        self.update_button(self)
    
    def update_button(self, event=None):
        selected_mode = self.mode_var.get().lower()
        self.submit_button.config(text=selected_mode)

    def submit(self):
        method = self.method_var.get().lower()
        mode = self.mode_var.get().lower()
        text = self.text_input.get("1.0", tk.END)
        key = self.key_var.get()
        signature = self.singature_var.get()
        nonce = self.nonce_var.get()

        result = ""
        try:
            if method == 'caesar':
                shift = int(key)
                result = caesar_cipher(text, shift, mode)
                key_result = shift
            elif method == 'rsa':
                result = rsa_encryption(text, mode)
            elif method == 'des':
                result, key_result = des_encryption(text, key, mode)
            elif method == 'aes':
                result, key_result = aes_encryption(text, key, mode)
            elif method == 'blowfish':
                result, key_result = blowfish_encryption(text, key, mode)
            elif method == 'cast5':
                result, key_result = cast_encryption(text, key, mode)
            elif method == 'chacha20':
                result, key_result, nonce = chacha20_encryption(text, key, nonce, mode)
            elif method == 'twofish':
                result, key_result = twofish_encryption(text, key, mode)
            elif method == 'dsa':
                result, key_result = dsa_signing(text, signature, key, mode)
            elif method == 'ecc':
                result, key_result = ecc_operations(text, signature, key, mode)
        except Exception as e:
            result = f"An error occurred: {e}"
        
        #Display results and keys
        if method == 'dsa' or method == 'ecc':
            self.result_text.config(state='normal')  # Enable the text widget for editing
            self.result_text.delete(1.0, tk.END)  # Clear existing text
            self.result_text.insert(tk.END, result if mode == "verify" else "Input has been signed.")  # Insert the result
            self.result_text.config(state='disabled')  # Disable the text widget to prevent editing
        else:
            self.result_text.config(state='normal')
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, result)
            self.result_text.config(state='disabled')

        if method == 'chacha20':
            self.nonce_var.set("")
            self.nonce_input.insert(tk.END, nonce)

        if mode == 'encrypt' or mode == 'sign':
            self.key_var.set("")
            self.key_input.insert(tk.END, key_result)
        if mode == 'sign':
            self.singature_var.set("")
            self.singature_input.insert(tk.END, result)

# Main function to run the app
def main():
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
