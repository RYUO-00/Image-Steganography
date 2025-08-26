import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from PIL import Image
import os
from cryptography.fernet import Fernet
import base64

# Helper functions for encryption and decryption
def generate_key(password):
    # Generate a Fernet-compatible key from the provided password
    key = base64.urlsafe_b64encode(password.ljust(32)[:32].encode())
    return key

def encrypt_message(message, key):
    fernet = Fernet(key)
    return fernet.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message.encode()).decode()

# Steganography functions
def message_to_binary(message):
    return ''.join([format(ord(char), '08b') for char in message])

def binary_to_message(binary):
    message = []
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        message.append(chr(int(byte, 2)))
    return ''.join(message)

def hide_message(image_path, encrypted_message, output_path):
    image = Image.open(image_path)
    binary_message = message_to_binary(encrypted_message) + '1111111111111110'  # End of message delimiter
    pixels = image.load()

    binary_index = 0
    for i in range(image.size[0]):
        for j in range(image.size[1]):
            if binary_index < len(binary_message):
                pixel = list(pixels[i, j])
                for n in range(3):  # Loop over RGB
                    if binary_index < len(binary_message):
                        pixel[n] = pixel[n] & ~1 | int(binary_message[binary_index])
                        binary_index += 1
                pixels[i, j] = tuple(pixel)

    image.save(output_path)

def extract_message(image_path):
    image = Image.open(image_path)
    pixels = image.load()

    binary_message = ''
    for i in range(image.size[0]):
        for j in range(image.size[1]):
            pixel = pixels[i, j]
            for n in range(3):  # Loop over RGB
                binary_message += str(pixel[n] & 1)

    end_index = binary_message.find('1111111111111110')
    if end_index != -1:
        binary_message = binary_message[:end_index]

    return binary_to_message(binary_message)

# GUI functions
def select_image():
    file_path = filedialog.askopenfilename(filetypes=[('Image files', '*.png;*.bmp')])
    entry_image_path.delete(0, tk.END)
    entry_image_path.insert(0, file_path)

def save_image():
    file_path = filedialog.asksaveasfilename(defaultextension='.png', filetypes=[('Image files', '*.png;*.bmp')])
    entry_output_path.delete(0, tk.END)
    entry_output_path.insert(0, file_path)

def hide_message_gui():
    image_path = entry_image_path.get()
    message = entry_message.get('1.0', tk.END).strip()
    output_path = entry_output_path.get()

    if not os.path.exists(image_path):
        messagebox.showerror('Error', 'Image file does not exist.')
        return

    key = simpledialog.askstring('Key Creation', 'Enter a key to encrypt the message (max 32 chars):', show='*')
    if not key:
        messagebox.showerror('Error', 'No key provided.')
        return

    if len(key) > 32:
        messagebox.showerror('Error', 'Key must be at most 32 characters long.')
        return

    try:
        key = generate_key(key)
        encrypted_message = encrypt_message(message, key)
        hide_message(image_path, encrypted_message, output_path)
        messagebox.showinfo('Success', 'Message hidden successfully.')
    except Exception as e:
        messagebox.showerror('Error', str(e))

def extract_message_gui():
    image_path = entry_image_path.get()

    if not os.path.exists(image_path):
        messagebox.showerror('Error', 'Image file does not exist.')
        return

    key = simpledialog.askstring('Key Input', 'Enter the key to decrypt the message (max 32 chars):', show='*')
    if not key:
        messagebox.showerror('Error', 'No key provided.')
        return

    if len(key) > 32:
        messagebox.showerror('Error', 'Key must be at most 32 characters long.')
        return

    try:
        hidden_message = extract_message(image_path)
        key = generate_key(key)
        decrypted_message = decrypt_message(hidden_message, key)
        entry_message.delete('1.0', tk.END)
        entry_message.insert(tk.END, decrypted_message)
        messagebox.showinfo('Success', 'Message extracted successfully.')
    except Exception as e:
        messagebox.showerror('Error', 'Decryption failed. Check your key.')

# GUI setup
root = tk.Tk()
root.title('Steganography Tool')
root.geometry('600x400')  # Set fixed window size

# Image file path
tk.Label(root, text='Image File:', font=('Arial', 12)).grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
entry_image_path = tk.Entry(root, width=40, font=('Arial', 12))
entry_image_path.grid(row=0, column=1, padx=10, pady=10)
tk.Button(root, text='Browse', command=select_image, font=('Arial', 12)).grid(row=0, column=2, padx=10, pady=10)

# Message to hide or extracted message
tk.Label(root, text='Message:', font=('Arial', 12)).grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
entry_message = tk.Text(root, height=10, width=40, font=('Arial', 12))
entry_message.grid(row=1, column=1, padx=10, pady=10, columnspan=2)

# Output file path
tk.Label(root, text='Output File:', font=('Arial', 12)).grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)
entry_output_path = tk.Entry(root, width=40, font=('Arial', 12))
entry_output_path.grid(row=2, column=1, padx=10, pady=10)
tk.Button(root, text='Save As', command=save_image, font=('Arial', 12)).grid(row=2, column=2, padx=10, pady=10)

# Buttons for hiding and extracting messages
tk.Button(root, text='Hide Message', command=hide_message_gui, font=('Arial', 12), bg='#4CAF50', fg='white').grid(row=3, column=0, columnspan=3, padx=10, pady=10, sticky=tk.W+tk.E)
tk.Button(root, text='Extract Message', command=extract_message_gui, font=('Arial', 12), bg='#2196F3', fg='white').grid(row=4, column=0, columnspan=3, padx=10, pady=10, sticky=tk.W+tk.E)

root.mainloop()