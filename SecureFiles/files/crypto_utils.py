import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from django.conf import settings

def generate_aes_key():
    """Generate a random AES-256 key"""
    return os.urandom(32)  # 256 bits

def generate_rsa_key_pair():
    """Generate RSA key pair and return as PEM strings"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    
    # Serialize keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem.decode('utf-8'), public_pem.decode('utf-8')

def load_rsa_key(key_pem, is_private=True):
    """Load RSA key from PEM string"""
    if is_private:
        return serialization.load_pem_private_key(
            key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
    else:
        return serialization.load_pem_public_key(
            key_pem.encode('utf-8'),
            backend=default_backend()
        )

def encrypt_file_aes(file_data, aes_key):
    """Encrypt file data using AES-256 in CBC mode"""
    iv = os.urandom(16)  # Initialization vector
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the data to be multiple of block size
    pad_length = 16 - (len(file_data) % 16)
    if pad_length == 16:
        pad_length = 0
    
    if pad_length > 0:
        padded_data = file_data + bytes([pad_length] * pad_length)
    else:
        padded_data = file_data
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data  # Prepend IV to encrypted data

def decrypt_file_aes(encrypted_data, aes_key):
    """Decrypt file data using AES-256"""
    iv = encrypted_data[:16]  # Extract IV
    actual_encrypted_data = encrypted_data[16:]
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_padded_data = decryptor.update(actual_encrypted_data) + decryptor.finalize()
    
    # Remove padding
    if len(decrypted_padded_data) > 0:
        pad_length = decrypted_padded_data[-1]
        if pad_length <= 16:  # Valid padding length
            decrypted_data = decrypted_padded_data[:-pad_length]
        else:
            decrypted_data = decrypted_padded_data
    else:
        decrypted_data = decrypted_padded_data
    
    return decrypted_data

def encrypt_rsa(data, public_key_pem):
    """Encrypt data using RSA public key"""
    try:
        public_key = load_rsa_key(public_key_pem, is_private=False)
        
        encrypted = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return encrypted
    except Exception as e:
        print(f"RSA Encryption Error: {e}")
        raise

def decrypt_rsa(encrypted_data, private_key_pem):
    """Decrypt data using RSA private key"""
    try:
        private_key = load_rsa_key(private_key_pem, is_private=True)
        
        decrypted = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return decrypted
    except Exception as e:
        print(f"RSA Decryption Error: {e}")
        raise

def compute_file_hash(file_data):
    """Compute SHA-256 hash of file data"""
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(file_data)
    return digest.finalize().hex()