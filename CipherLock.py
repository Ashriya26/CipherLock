import tkinter as tk
from tkinter import simpledialog, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# Caesar Cipher
def caesar_encrypt(plaintext, shift):
    encrypted_text = ""
    for char in plaintext:
        if char.isalpha():
            shift_amount = shift % 26
            shifted = ord(char) + shift_amount
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                encrypted_text += chr(shifted)
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)

# Vigenère Cipher
def vigenere_encrypt(plaintext, keyword):
    encrypted_text = ""
    keyword_repeated = ""
    keyword_length = len(keyword)
    for i in range(len(plaintext)):
        keyword_repeated += keyword[i % keyword_length]
    
    for p, k in zip(plaintext, keyword_repeated):
        if p.isalpha():
            shift_amount = ord(k.lower()) - ord('a')
            if p.islower():
                encrypted_char = chr((ord(p) - ord('a') + shift_amount) % 26 + ord('a'))
            elif p.isupper():
                encrypted_char = chr((ord(p) - ord('A') + shift_amount) % 26 + ord('A'))
            encrypted_text += encrypted_char
        else:
            encrypted_text += p
    
    return encrypted_text

def vigenere_decrypt(ciphertext, keyword):
    decrypted_text = ""
    keyword_repeated = ""
    keyword_length = len(keyword)
    for i in range(len(ciphertext)):
        keyword_repeated += keyword[i % keyword_length]
    
    for c, k in zip(ciphertext, keyword_repeated):
        if c.isalpha():
            shift_amount = ord(k.lower()) - ord('a')
            if c.islower():
                decrypted_char = chr((ord(c) - ord('a') - shift_amount + 26) % 26 + ord('a'))
            elif c.isupper():
                decrypted_char = chr((ord(c) - ord('A') - shift_amount + 26) % 26 + ord('A'))
            decrypted_text += decrypted_char
        else:
            decrypted_text += c
    
    return decrypted_text

# AES
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ciphertext).decode('utf-8')

def aes_decrypt(ciphertext, key):
    raw_data = base64.b64decode(ciphertext)
    iv = raw_data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(raw_data[AES.block_size:]), AES.block_size)
    return plaintext.decode()

# GUI
def encrypt_message():
    algorithm = algorithm_var.get()
    plaintext = simpledialog.askstring("Input", "Enter the message to encrypt:")
    if not plaintext:
        return
    if algorithm == "Caesar Cipher":
        shift = int(simpledialog.askstring("Input", "Enter the skey value:"))
        encrypted_message = caesar_encrypt(plaintext, shift)
    elif algorithm == "Vigenère Cipher":
        keyword = simpledialog.askstring("Input", "Enter the keyword:")
        encrypted_message = vigenere_encrypt(plaintext, keyword)
    elif algorithm == "AES":
        key = get_random_bytes(16)  # AES-128
        encrypted_message = aes_encrypt(plaintext, key)
        keys_storage[plaintext] = key  # Store key for decryption
    messagebox.showinfo("Encrypted Message", encrypted_message)

def decrypt_message():
    algorithm = algorithm_var.get()
    ciphertext = simpledialog.askstring("Input", "Enter the message to decrypt:")
    if not ciphertext:
        return
    if algorithm == "Caesar Cipher":
        shift = int(simpledialog.askstring("Input", "Enter the key value:"))
        decrypted_message = caesar_decrypt(ciphertext, shift)
    elif algorithm == "Vigenère Cipher":
        keyword = simpledialog.askstring("Input", "Enter the keyword:")
        decrypted_message = vigenere_decrypt(ciphertext, keyword)
    elif algorithm == "AES":
        plaintext = simpledialog.askstring("Input", "Enter the original plaintext for AES key retrieval:")
        key = keys_storage.get(plaintext)
        if key:
            decrypted_message = aes_decrypt(ciphertext, key)
        else:
            decrypted_message = "Key not found for the provided plaintext."
    messagebox.showinfo("Decrypted Message", decrypted_message)

# Main window
root = tk.Tk()
root.title("Encryption/Decryption Tool")

algorithm_var = tk.StringVar(value="Caesar Cipher")

tk.Label(root, text="Choose Encryption Algorithm:").pack()
tk.Radiobutton(root, text="Caesar Cipher", variable=algorithm_var, value="Caesar Cipher").pack(anchor=tk.W)
tk.Radiobutton(root, text="Vigenère Cipher", variable=algorithm_var, value="Vigenère Cipher").pack(anchor=tk.W)
tk.Radiobutton(root, text="AES", variable=algorithm_var, value="AES").pack(anchor=tk.W)

tk.Button(root, text="Encrypt", command=encrypt_message).pack()
tk.Button(root, text="Decrypt", command=decrypt_message).pack()

keys_storage = {}

root.mainloop()
