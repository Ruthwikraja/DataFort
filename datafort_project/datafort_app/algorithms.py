# cryptography_app/crypto_utils.py
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.hazmat.primitives import serialization

from PIL import Image
import numpy as np
import cv2


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 requires a 256-bit key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_aes(data, password, salt):
    key = derive_key(password, salt)
    iv = os.urandom(16)  # Initialization Vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + ciphertext

def decrypt_aes(encrypted_data, password, salt):
    key = derive_key(password, salt)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# def generate_ecdh_keypair():
#     private_key = ec.generate_private_key(ec.SECP384R1(), backend=default_backend())
#     public_key = private_key.public_key()
#     return private_key, public_key

def generate_ecc_keypair():
    private_key = ec.generate_private_key(
        curve=ec.SECP256R1(),  # Choose the curve that suits your needs
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_ecc(data, public_key):
    ciphertext = public_key.encrypt(
        data.encode(),
        ec.ECIES(),
        hashes.SHA256()
    )
    return ciphertext

def decrypt_ecc(encrypted_data, private_key):
    decrypted_data = private_key.decrypt(
        encrypted_data,
        ec.ECIES(),
        hashes.SHA256()
    )
    return decrypted_data.decode()

def generate_dsa_keypair():
    private_key = dsa.generate_private_key(key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def hash_sha256(data):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()

def hash_sha3_256(data):
    digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()

def hash_whirlpool(data):
    digest = hashes.Hash(hashes.Whirlpool(), backend=default_backend())
    digest.update(data)
    return digest.finalize()

# cryptography_app/steganography_utils.py

def process_lsb_steganography(carrier_file):
    # Assuming the hidden message is stored as bytes
    hidden_message = b'This is a sample hidden message.'

    # Open the carrier image using PIL
    with Image.open(carrier_file) as img:
        img_data = bytearray(img.tobytes())

        # Embed the hidden message using LSB algorithm
        for i in range(len(hidden_message)):
            img_data[i] &= 0xFE  # Clear the least significant bit
            img_data[i] |= (hidden_message[i] >> 7) & 0x01  # Set the LSB with the message bit

        # Save the modified image
        stego_image = Image.frombytes(img.mode, img.size, bytes(img_data))
        stego_image.save('path/to/save/stego_image.png')

    return hidden_message

# cryptography_app/steganography_utils.py

def process_frequency_domain_steganography(carrier_file):
    # Assuming the hidden message is stored as bytes
    hidden_message = b'This is a sample hidden message.'

    # Open the carrier image using OpenCV
    carrier_image = cv2.imread(carrier_file.path, cv2.IMREAD_GRAYSCALE)

    # Apply Discrete Fourier Transform (DFT)
    f_transform = np.fft.fft2(carrier_image)
    f_shift = np.fft.fftshift(f_transform)

    # Embed the hidden message in the frequency domain
    for i in range(len(hidden_message)):
        row, col = divmod(i, carrier_image.shape[1])
        f_shift[row, col] = (f_shift[row, col] & ~1) | (hidden_message[i] & 1)

    # Apply Inverse Discrete Fourier Transform (IDFT)
    f_ishift = np.fft.ifftshift(f_shift)
    img_back = np.fft.ifft2(f_ishift)
    stego_image = np.abs(img_back).astype(np.uint8)

    # Save the modified image
    cv2.imwrite('path/to/save/stego_image.png', stego_image)

    return hidden_message
