import streamlit as st
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes

# ---------------------------------------------------------------------
# AES FUNCTIONS
# ---------------------------------------------------------------------
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

# ---------------------------------------------------------------------
# RSA FUNCTIONS
# ---------------------------------------------------------------------
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key, public_key, priv_pem.decode(), pub_pem.decode()

def rsa_encrypt_key(aes_key, public_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_key).decode()

def rsa_decrypt_key(encrypted_aes_key_b64, private_key):
    encrypted_key_bytes = base64.b64decode(encrypted_aes_key_b64)
    decrypted_key = private_key.decrypt(
        encrypted_key_bytes,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key


# ---------------------------------------------------------------------
# UI NAVIGATION SETUP
# ---------------------------------------------------------------------
st.set_page_config(page_title="AES-CBC + RSA Simulator", layout="wide")

st.sidebar.title("🔐 CBC Encryption Project")
page = st.sidebar.radio("Navigate", ["Home", "Simulator", "Example Problem", "Conclusion"])

# ---------------------------------------------------------------------
# PAGE 1: HOME
# ---------------------------------------------------------------------
if page == "Home":
    st.title("AES CBC Mode Encryption with RSA Key Protection")
    st.markdown("""
    **Subject:** BCS703 – Cryptography and Network Security  
    **Student:** Ashwin Kumar G Rao  
    **College:** Shri Madhwa Vadiraja Institute of Technology and Management, Bantakal  

    ---
    ### 🔑 Overview
    This project demonstrates how **AES-CBC (Cipher Block Chaining)** mode encrypts 
    data block-by-block using chaining, combined with **RSA public/private key 
    encryption** to secure the AES key.

    ---
    """)


# ---------------------------------------------------------------------
# PAGE 2: MAIN SIMULATOR
# ---------------------------------------------------------------------
elif page == "Simulator":
    st.title("🔐 AES-CBC + RSA Encryption & Decryption Simulator")

    # --- KEY GENERATION ---
    st.subheader("🧩 Step 1: Generate Keys and IV")

    col1, col2 = st.columns(2)

    with col1:
        if st.button("Generate AES Key & IV"):
            st.session_state["aes_key"] = os.urandom(16)
            st.session_state["iv"] = os.urandom(16)
            st.success("AES Key & IV generated.")

    with col2:
        if st.button("Generate RSA Key Pair"):
            priv, pub, priv_pem, pub_pem = generate_rsa_keys()
            st.session_state["rsa_private_key"] = priv
            st.session_state["rsa_public_key"] = pub
            st.session_state["rsa_private_pem"] = priv_pem
            st.session_state["rsa_public_pem"] = pub_pem
            st.success("RSA Key Pair Generated.")

    if "aes_key" in st.session_state:
        st.code(f"AES Key (HEX): {st.session_state['aes_key'].hex()}")

    if "iv" in st.session_state:
        st.code(f"IV (HEX): {st.session_state['iv'].hex()}")

    if "rsa_public_pem" in st.session_state:
        st.text_area("Public Key", st.session_state["rsa_public_pem"], height=140)

    if "rsa_private_pem" in st.session_state:
        st.text_area("Private Key", st.session_state["rsa_private_pem"], height=140)

    st.divider()

    # --- ENCRYPTION ---
    st.subheader("🔒 Step 2: Encrypt Message")

    plaintext = st.text_area("Enter plain text:", "Hello CBC + RSA Security!")

    if st.button("Encrypt"):
        if "aes_key" not in st.session_state:
            st.error("Generate AES key first!")
        else:
            encrypted_text = encrypt_cbc(plaintext, st.session_state["aes_key"], st.session_state["iv"])
            st.session_state["encrypted_text"] = encrypted_text

            st.success("Encryption completed!")
            st.code(f"Ciphertext (Base64): {encrypted_text}")

            if "rsa_public_key" in st.session_state:
                rsa_key = rsa_encrypt_key(st.session_state["aes_key"], st.session_state["rsa_public_key"])
                st.session_state["rsa_encrypted_key"] = rsa_key
                st.code(f"RSA Encrypted AES Key (Base64): {rsa_key}")

    st.divider()

    # --- DECRYPTION ---
    st.subheader("🔓 Step 3: Decrypt Message")

    ciphertext_input = st.text_area("Ciphertext (Base64)", st.session_state.get("encrypted_text", ""))
    rsa_key_input = st.text_input("RSA Encrypted AES Key (optional)", st.session_state.get("rsa_encrypted_key", ""))
    iv_input = st.text_input("IV (Hex)", st.session_state.get("iv").hex() if "iv" in st.session_state else "")

    if st.button("🔓 Decrypt Now"):
        try:
            iv_bytes = bytes.fromhex(iv_input)

            if rsa_key_input.strip() and "rsa_private_key" in st.session_state:
                aes_key = rsa_decrypt_key(rsa_key_input, st.session_state["rsa_private_key"])
            else:
                aes_key = st.session_state["aes_key"]

            decrypted_text = decrypt_cbc(ciphertext_input, aes_key, iv_bytes)

            st.success("Decryption Successful!")
            st.code(decrypted_text)

        except Exception as e:
            st.error(f"❌ Decryption Failed: {e}")


# ---------------------------------------------------------------------
# PAGE 3: EXAMPLE PROBLEM
# ---------------------------------------------------------------------
elif page == "Example Problem":
    st.header("📘 Example Problem – CBC Encryption Logic")
    st.markdown("""
    **Given:**
    - Plaintext Blocks: P₁ = 1010, P₂ = 0110  
    - Key (K) = 1111  
    - Initialization Vector (IV) = 0001  
    - Encryption function: Eₖ(X) = X ⊕ K  

    ---
    **Solution:**
    - C₁ = Eₖ(P₁ ⊕ IV) = (1010 ⊕ 0001) ⊕ 1111 = 1011 ⊕ 1111 = **0100**  
    - C₂ = Eₖ(P₂ ⊕ C₁) = (0110 ⊕ 0100) ⊕ 1111 = 0010 ⊕ 1111 = **1101**

    ✅ **Final Ciphertext:** 0100 1101
    """)


# ---------------------------------------------------------------------
# PAGE 4: CONCLUSION
# ---------------------------------------------------------------------
elif page == "Conclusion":
    st.header("📜 Conclusion")

    st.markdown("""
AES-CBC (Cipher Block Chaining) mode strengthens encryption by ensuring that each ciphertext block is dependent on all previous blocks. 
This prevents predictable patterns from appearing in the encrypted data, making analysis or tampering significantly more difficult.

In this project, AES is used for data encryption (fast, symmetric) while RSA is used to securely exchange the AES key (asymmetric). 
This combination is known as a **hybrid cryptosystem**, a model widely adopted in secure communication protocols.

---

### 🔐 Why AES-CBC + RSA?

- 🔹 Prevents block repetition vulnerabilities  
- 🔹 Ensures confidentiality even if patterns exist in plaintext  
- 🔹 Allows secure AES key sharing via RSA  
- 🔹 Balances speed (AES) and security (RSA)

---

### 🌍 Real-World Applications

- TLS / HTTPS communication  
- SSL certificate key exchange  
- Secure email systems (PGP / GMail security layer)  
- VPNs, IPsec, Banking and authentication systems  

---

### ⭐ Key Takeaways

- AES handles **fast and secure encryption**  
- RSA handles **safe key delivery**  
- CBC mode ensures **non-repetitive ciphertext**  
- Together, they provide **strong, modern encryption workflow**  

---

### 📚 References

- https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation  
- https://cryptobook.nakov.com/  
- https://www.geeksforgeeks.org/block-cipher-modes-of-operation/  

---
""")


