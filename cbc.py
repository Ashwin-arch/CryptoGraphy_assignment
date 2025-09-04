import streamlit as st
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64

# CBC Functions
def encrypt_cbc(plaintext, key, iv):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode()

def decrypt_cbc(ciphertext, key, iv):
    ciphertext_bytes = base64.b64decode(ciphertext)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext_bytes) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()

# Streamlit UI
st.title("🔐 AES CBC Mode Encryption & Decryption")

text = st.text_area("Enter Text to Encrypt", "Hello CBC Mode in Streamlit!")

if st.button("Encrypt"):
    key = os.urandom(16)  # 128-bit key
    iv = os.urandom(16)   # 128-bit IV
    encrypted = encrypt_cbc(text, key, iv)
    decrypted = decrypt_cbc(encrypted, key, iv)

    st.write("### Results:")
    st.write("**Original Text:**", text)
    st.write("**Encrypted (Base64):**", encrypted)
    st.write("**Decrypted:**", decrypted)
    st.write("**Key (hex):**", key.hex())
    st.write("**IV (hex):**", iv.hex())
