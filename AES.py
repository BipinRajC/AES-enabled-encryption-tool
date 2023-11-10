from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import os
from PIL import Image, ImageDraw

class ImageEncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.wm_title("Image Encryption")

        self.setup_ui()

    def setup_ui(self):
        self.pass_label = Label(self.root, text="Enter Encrypt/Decrypt Password:")
        self.pass_label.pack()

        self.pass_entry = Entry(self.root, show="*", width=20)
        self.pass_entry.pack()

        self.encrypt_button = Button(self.root, text="Encrypt", fg="black", command=self.image_open, width=25, height=5)
        self.encrypt_button.pack(side=LEFT)

        self.decrypt_button = Button(self.root, text="Decrypt", fg="black", command=self.cipher_open, width=25, height=5)
        self.decrypt_button.pack(side=RIGHT)

    def image_open(self):
        password = self.pass_entry.get()
        if not password:
            self.pass_alert("Please enter a password.")
            return

        filename = filedialog.askopenfilename()
        if not filename:
            return

        try:
            # Load and encrypt the image
            encrypt_image(filename, password)
            self.enc_success("visual_encrypt.jpeg")
        except Exception as e:
            self.pass_alert(f"Encryption failed: {str(e)}")

    def cipher_open(self):
        password = self.pass_entry.get()
        if not password:
            self.pass_alert("Please enter a password.")
            return

        filename = filedialog.askopenfilename()
        if not filename:
            return

        try:
            # Decrypt and display the image
            decrypt_image(filename, password)
            self.enc_success("visual_decrypt.jpeg")
        except ValueError:
            self.pass_alert("Wrong password entered.")
        except FileNotFoundError:
            self.pass_alert("Error : Enter the encrypted image to decrypt")
        except Exception as e:
            self.pass_alert(f"Decryption failed: {str(e)}")

    def pass_alert(self, message):
        messagebox.showinfo("Alert", message)

    def enc_success(self, imagename):
        messagebox.showinfo("Success", "Encrypted/Decrypted Image: " + imagename)

# Function to encrypt the image using AES
def encrypt_image(imagename, password):
    # Load the image
    with open(imagename, "rb") as file:
        plaintext = file.read()

    # Generate a random IV
    iv = get_random_bytes(16)

    # Create AES cipher object with the provided password and IV
    cipher = AES.new(hashlib.sha256(password.encode()).digest(), AES.MODE_CBC, iv)

    # Pad the plaintext data to be a multiple of 16 bytes
    padding_length = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + bytes([padding_length] * padding_length)

    # Encrypt the padded plaintext
    ciphertext = cipher.encrypt(padded_plaintext)

    # Write the IV and ciphertext to a new file
    with open("visual_encrypt_temp.bin", "wb") as file:
        file.write(iv + ciphertext)

    fake_image = Image.new("RGB", (100, 100))
    draw = ImageDraw.Draw(fake_image)
    draw.text((10, 10), "Encrypted Image", fill="white")
    fake_image.save("visual_encrypt.jpeg", "JPEG")

# Function to decrypt the image using AES
def decrypt_image(imagename, password):
    # Check if the provided image is valid for decryption
    if not imagename.endswith("visual_encrypt.jpeg"):
        raise FileNotFoundError("Error : Enter the encrypted image to decrypt")

    # Load the encrypted data from the binary file
    with open("visual_encrypt_temp.bin", "rb") as file:
        data = file.read()

    # Extract the IV
    iv = data[:16]

    # Create AES cipher object with the provided password and IV
    cipher = AES.new(hashlib.sha256(password.encode()).digest(), AES.MODE_CBC, iv)

    # Decrypt the ciphertext
    plaintext = cipher.decrypt(data[16:])

    # Remove padding
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]

    # Write the decrypted data to a new file
    with open("visual_decrypt.jpeg", "wb") as file:
        file.write(plaintext)

def main():
    root = Tk()
    app = ImageEncryptionApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
