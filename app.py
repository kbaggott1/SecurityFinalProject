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
        root.geometry('600x500')
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
        self.methods = ['Caesar', 'RSA', 'DES', 'AES', 'Camellia', 'CAST5', 'ChaCha20', 'TwoFish', 'DSA', 'ECC']
        ttk.Label(frame, text='Choose encryption method:').grid(column=0, row=0, sticky=tk.W)
        self.method_menu = ttk.Combobox(frame, textvariable=self.method_var, values=self.methods, state='readonly', width=20)
        self.method_menu.grid(column=1, row=0, sticky=tk.W)

        # Dropdown for choosing mode
        self.mode_var = tk.StringVar()
        self.modes = ['encrypt', 'decrypt', 'sign', 'verify']
        ttk.Label(frame, text='Choose mode:').grid(column=0, row=1, sticky=tk.W)
        self.mode_menu = ttk.Combobox(frame, textvariable=self.mode_var, values=self.modes, state='readonly', width=20)
        self.mode_menu.grid(column=1, row=1, sticky=tk.W)

        # Text input
        ttk.Label(frame, text='Enter text:').grid(column=0, row=2, sticky=tk.W)
        self.text_input = tk.Entry(frame, width=30)
        self.text_input.grid(column=1, row=2, sticky=tk.W)

        # Additional input for Caesar
        self.shift_var = tk.IntVar()
        self.shift_input = tk.Entry(frame, textvariable=self.shift_var, width=30)
        self.shift_input.grid(column=1, row=3, sticky=tk.W)
        self.shift_input.grid_remove()

        # Submit button
        self.submit_button = ttk.Button(frame, text='Submit', command=self.submit)
        self.submit_button.grid(column=1, row=4, sticky=tk.W, pady=10, padx=5)

        # Text widget for displaying results
        self.result_text = ScrolledText(frame, wrap=tk.WORD, width=50, height=15, font=('Arial', 10))
        self.result_text.grid(column=0, row=5, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10, padx=5)

        # Update UI based on method selection
        self.method_menu.bind('<<ComboboxSelected>>', self.update_ui)

    def update_ui(self, event=None):
        selected_method = self.method_var.get()
        if selected_method == 'Caesar':
            self.shift_input.grid()
        else:
            self.shift_input.grid_remove()

    def submit(self):
        method = self.method_var.get().lower()
        mode = self.mode_var.get().lower()
        text = self.text_input.get()

        result = ""
        try:
            if method == 'caesar':
                shift = self.shift_var.get()
                result = caesar_cipher(text, shift, mode)
            elif method == 'rsa':
                result = rsa_encryption(text, mode)
            elif method == 'des':
                result = des_encryption(text, mode)
            elif method == 'aes':
                result = aes_encryption(text, mode)
            elif method == 'camellia':
                result = camellia_encryption(text, mode)
            elif method == 'cast5':
                result = cast_encryption(text, mode)
            elif method == 'chacha20':
                result = chacha20_encryption(text, mode)
            elif method == 'twofish':
                result = twofish_encryption(text, mode)
            elif method == 'dsa':
                result = dsa_signing(text, mode)
            elif method == 'ecc':
                result = ecc_operations(text, mode)
        except Exception as e:
            result = f"An error occurred: {e}"

        # Display result in the text widget
        self.result_text.config(state='normal')  # Enable the text widget for editing
        self.result_text.delete(1.0, tk.END)  # Clear existing text
        self.result_text.insert(tk.END, result)  # Insert the result
        self.result_text.config(state='disabled')  # Disable the text widget to prevent editing

# Main function to run the app
def main():
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
