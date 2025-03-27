import os
import base64
import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import json
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # ✅ FIXED: Added HKDF import
# Load passphrase
passphrase = b"mysecurepassphrase"

# Function to derive AES key from passphrase and salt
def derive_key(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(passphrase)

# Encrypt key using AES-GCM
def encrypt_key(key, passphrase):
    salt = os.urandom(16)
    aes_key = derive_key(passphrase, salt)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(key) + encryptor.finalize()
    return base64.b64encode(salt + iv + encryptor.tag + ciphertext).decode()

# Decrypt key using AES-GCM
def decrypt_key(encrypted_key, passphrase):
    encrypted_data = base64.b64decode(encrypted_key)
    salt, iv, tag, ciphertext = encrypted_data[:16], encrypted_data[16:28], encrypted_data[28:44], encrypted_data[44:]
    aes_key = derive_key(passphrase, salt)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Save key to file
def save_key_to_file(key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(key)

# Load key from file
def load_key_from_file(filename):
    with open(filename, "rb") as key_file:
        return key_file.read()

# Generate AES Key
def generate_aes_key():
    aes_key = os.urandom(32)  # Generate a 256-bit AES key
    save_key_to_file(aes_key, "aes_public_key.bin")
    print("[🔑] ✅ AES Key Generated & Saved!")


# Generate Diffie-Hellman Key Pair
def generate_dh_keys():
    dh_parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = dh_parameters.generate_private_key()
    public_key = private_key.public_key()

    # Save Private Key
    with open("dh_private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save Public Key
    with open("dh_public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("[🔑] ✅ Diffie-Hellman Key Pair Generated & Saved!")
    return private_key, public_key

# Load DH Keys
def load_dh_keys():
    try:
        with open("dh_private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        with open("dh_public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        print("[🔑] ✅ DH Keys Loaded Successfully!")
        return private_key, public_key

    except FileNotFoundError:
        print("[❌] DH Key files not found! Please generate them first.")
        return None, None

# Generate Shared Secret
def generate_shared_secret():
    private_key, public_key = load_dh_keys()
    if not private_key or not public_key:
        return None

    remote_public_key = public_key
    shared_secret = private_key.exchange(remote_public_key)

    # Derive a 32-byte AES key from the shared secret using HKDF
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'Diffie-Hellman AES Key'
    ).derive(shared_secret)

    # Save AES key to a file
    save_key_to_file(aes_key, "shared_secret.bin")
    print("[🔑] ✅ AES Key Derived from Shared Secret & Saved")
    return aes_key

# AES Encryption
def encrypt_message_aes(plaintext):
    aes_key = load_key_from_file("shared_secret.bin")
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = PKCS7(128).padder()
    padded_text = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_text) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

# AES Decryption
def decrypt_message_aes():
    aes_key = load_key_from_file("shared_secret.bin")
    encrypted_text = input("Enter encrypted AES message: ")
    encrypted_data = base64.b64decode(encrypted_text)
    iv, ciphertext = encrypted_data[:16], encrypted_data[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = PKCS7(128).unpadder()
    plaintext = unpadder.update(decryptor.update(ciphertext) + decryptor.finalize()) + unpadder.finalize()
    print(f"[🔓] Decrypted Message: {plaintext.decode()}")

# Generate RSA Key Pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Save private key
    with open("rsaprivate_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    public_key = private_key.public_key()
    with open("rsapublic_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("[🔑] ✅ RSA Key Pair Generated & Saved!")

def load_rsa_public_key(filename="rsapublic_key.pem"):
    try:
        with open(filename, "rb") as key_file:
            return serialization.load_pem_public_key(key_file.read())
    except FileNotFoundError:
        print(f"[❌] Error: Public key file '{filename}' not found!")
        return None

def load_rsa_private_key(filename="rsaprivate_key.pem"):
    try:
        with open(filename, "rb") as key_file:
            return serialization.load_pem_private_key(key_file.read(), password=None)
    except FileNotFoundError:
        print(f"[❌] Error: Private key file '{filename}' not found!")
        return None

def rsa_encrypt(message):
    public_key = load_rsa_public_key()
    if not public_key:
        return "[❌] Encryption failed: Public key not found"

    # Ensure message length is within the limit
    key_size_bytes = public_key.key_size // 8  # Convert bits to bytes
    max_message_length = key_size_bytes - 2 * hashes.SHA256().digest_size - 2

    if len(message.encode()) > max_message_length:
        return "[❌] Message is too long for RSA encryption! Reduce the size."

    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

def rsa_decrypt(encrypted_message):
    private_key = load_rsa_private_key()
    if not private_key:
        return "[❌] Decryption failed: Private key not found"

    try:
        ciphertext = base64.b64decode(encrypted_message)
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"[🔓] Decrypted Message: {plaintext.decode()}")
    except ValueError:
        print("[❌] Decryption failed: Incorrect key or corrupted ciphertext.")


# Generate Root CA
def generate_root_ca():
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "MyRootCA")
    ])
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(root_subject)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    with open("root_ca.pem", "wb") as f:
        f.write(root_cert.public_bytes(serialization.Encoding.PEM))
    with open("root_ca_key.pem", "wb") as f:
        f.write(root_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    print("[✅] Root CA Created!")

# Generate User CSR
def generate_user_csr():
    user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    user_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "User Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, "User")
    ])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(user_subject)
        .sign(user_key, hashes.SHA256())
    )

    with open("user_csr.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    with open("user_key.pem", "wb") as f:
        f.write(user_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

    print("[✅] User CSR Created!")

# Sign User CSR with Root CA
def sign_certificate():
    try:
        with open("user_csr.pem", "rb") as f:
            csr = x509.load_pem_x509_csr(f.read())
        with open("root_ca.pem", "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read())
        with open("root_ca_key.pem", "rb") as f:
            root_key = serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError:
        print("[❌] Error: Missing Root CA or CSR files.")
        return

    user_cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(root_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(root_key, hashes.SHA256())
    )

    with open("user_cert.pem", "wb") as f:
        f.write(user_cert.public_bytes(serialization.Encoding.PEM))

    print("[✅] User Certificate Signed & Saved!")
def verify_certificate():
    try:
        # Load the User Certificate
        with open("user_cert.pem", "rb") as f:
            user_cert = x509.load_pem_x509_certificate(f.read())

        # Load the Root CA Certificate
        with open("root_ca.pem", "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read())

        # Extract Root CA's Public Key
        root_public_key = root_cert.public_key()

        # Verify User Certificate's Digital Signature
        root_public_key.verify(
            user_cert.signature,                    # User cert's signature
            user_cert.tbs_certificate_bytes,        # Data that was signed
            padding.PKCS1v15(),
            user_cert.signature_hash_algorithm,     # Hash algorithm used for signing
        )

        print("[✅] Certificate Verification Successful!")
    
    except FileNotFoundError as e:
        print(f"[❌] Certificate Verification Failed! {e}")
    
    except Exception as e:
        print(f"[❌] Certificate Verification Error: {e}")
def revoke_certificate():
    try:
        with open("root_ca_key.pem", "rb") as f:
            root_key = serialization.load_pem_private_key(f.read(), password=None)
        with open("root_ca.pem", "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read())
        with open("user_cert.pem", "rb") as f:
            user_cert = x509.load_pem_x509_certificate(f.read())
    except FileNotFoundError:
        print("[❌] Error: Missing certificate or CA files.")
        return

    revoked_cert = x509.RevokedCertificateBuilder()
    revoked_cert = revoked_cert.serial_number(user_cert.serial_number)
    revoked_cert = revoked_cert.revocation_date(datetime.datetime.utcnow())
    revoked_cert = revoked_cert.build()

    try:
        with open("crl.pem", "rb") as f:
            existing_crl = x509.load_pem_x509_crl(f.read())
    except FileNotFoundError:
        existing_crl = x509.CertificateRevocationListBuilder()
    
    crl = (
        existing_crl
        .issuer_name(root_cert.subject)
        .last_update(datetime.datetime.utcnow())
        .next_update(datetime.datetime.utcnow() + datetime.timedelta(days=30))
        .add_revoked_certificate(revoked_cert)
        .sign(private_key=root_key, algorithm=hashes.SHA256())
    )

    with open("crl.pem", "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))
    print("[✅] Certificate Revoked and CRL Updated!")

# Function to check if a certificate is revoked
def is_certificate_revoked():
    try:
        with open("user_cert.pem", "rb") as f:
            user_cert = x509.load_pem_x509_certificate(f.read())
        with open("crl.pem", "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())
    except FileNotFoundError:
        print("[❌] CRL or certificate file missing!")
        return

    for revoked_cert in crl:
        if revoked_cert.serial_number == user_cert.serial_number:
            print("[❌] Certificate is revoked!")
            return True
    
    print("[✅] Certificate is valid and not revoked.")
    return False

# File to store revoked keys
REVOKED_KEYS_FILE = "revoked_keys.json"

# Initialize revoked keys file if not exists
def initialize_revoked_keys():
    if not os.path.exists(REVOKED_KEYS_FILE):
        with open(REVOKED_KEYS_FILE, "w") as f:
            json.dump([], f)

# Revoke a key
def revoke_key(filename):
    initialize_revoked_keys()
    if not os.path.exists(filename):
        print(f"[❌] Error: Key file '{filename}' not found!")
        return
    
    with open(REVOKED_KEYS_FILE, "r") as f:
        revoked_keys = json.load(f)
    
    if filename in revoked_keys:
        print(f"[⚠️] Key '{filename}' is already revoked!")
        return
    
    revoked_keys.append(filename)
    with open(REVOKED_KEYS_FILE, "w") as f:
        json.dump(revoked_keys, f)
    
    print(f"[✅] Key '{filename}' has been revoked successfully!")

# Check if a key is revoked
def is_key_revoked(filename):
    initialize_revoked_keys()
    with open(REVOKED_KEYS_FILE, "r") as f:
        revoked_keys = json.load(f)
    return filename in revoked_keys

# Attempt to use a key (Example: Loading a key)
def load_key(filename):
    if is_key_revoked(filename):
        print(f"[❌] Error: Key '{filename}' has been revoked and cannot be used!")
        return None
    
    try:
        with open(filename, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print(f"[❌] Error: Key file '{filename}' not found!")
        return None


import os
import base64
import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import json
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# [... All previous functions remain the same ...]

# Menu Loop
while True:
    print("\n=====================================")
    print("🔑  Secure Encryption & Decryption Menu  🔑")
    print("=====================================")
    print("1️⃣  Generate AES Key")
    print("2️⃣  Generate DH Key Pair")

    print("\n🔐  Symmetric Encryption & Decryption  🔐")
    print("------------------------------------------------")
    print("3️⃣  Generate Shared Secret ")
    print("4️⃣  Encrypt Message with AES")
    print("5️⃣  Decrypt Message with AES")

    print("\n🔏  Asymmetric Encryption & Decryption  🔏")
    print("------------------------------------------------")
    print("6️⃣  Generate RSA Key Pair")
    print("7️⃣  Encrypt Message with RSA")
    print("8️⃣  Decrypt Message with RSA")

    print("\n🔰  Certificate Management  🔰")
    print("------------------------------------------------")
    print("9️⃣  Generate Root CA")
    print("1️⃣0️⃣  Generate User CSR")
    print("1️⃣1️⃣  Sign User Certificate")
    print("1️⃣2️⃣  Verify Certificate")
    print("1️⃣3️⃣  Revoke Certificate")
    print("1️⃣4️⃣  Check Certificate Revocation Status")
    print("1️⃣5️⃣  Revoke a Key")
    print("1️⃣6️⃣  Check if a Key is Revoked")
    print("1️⃣7️⃣  Load a Key")
    print("1️⃣8️⃣  Exit")
    print("=====================================")

    choice = input("Enter your choice: ").strip()

    if choice == "1":
        generate_aes_key()
    elif choice == "2":
        generate_dh_keys()
    elif choice == "3":
        generate_shared_secret()
    elif choice == "4":
        print(f"🔒 Encrypted: {encrypt_message_aes(input('Enter message: '))}")
    elif choice == "5":
        decrypt_message_aes()
    elif choice == "6":
        generate_rsa_key_pair()
    elif choice == "7":
        print(f"🔒 Encrypted: {rsa_encrypt(input('Enter message: '))}")
    elif choice == "8":
        rsa_decrypt(input("Enter encrypted RSA message: "))
    elif choice == "9":
        generate_root_ca()
    elif choice == "10":
        generate_user_csr()
    elif choice == "11":
        sign_certificate()
    elif choice == "12":
        verify_certificate()
    elif choice == "13":
        revoke_certificate()
    elif choice == "14":
        is_certificate_revoked()
    elif choice == "15":
        filename = input("Enter key filename to revoke: ")
        revoke_key(filename)
    elif choice == "16":
        filename = input("Enter key filename to check: ")
        if is_key_revoked(filename):
            print(f"[⚠️] Key '{filename}' is revoked!")
        else:
            print(f"[✅] Key '{filename}' is NOT revoked!")
    elif choice == "17":
        filename = input("Enter key filename to load: ")
        key = load_key(filename)
        if key:
            print(f"[🔑] Key '{filename}' loaded successfully!")
    elif choice == "18":
        print("\n👋 Exiting... Stay Secure! 🔐")
        break
    else:
        print("❌ Invalid Choice! Please enter a valid option.")
