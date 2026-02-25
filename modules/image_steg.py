"""
Image Steganography Module
- Uses Least Significant Bit (LSB) insertion
- Optionally encrypts message with AES-256 (CBC mode) before embedding
"""

import numpy as np
import cv2
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets

DELIMITER = '*^*^*'
SALT_SIZE = 16   # bytes prepended to cipher output
IV_SIZE = 16


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))


def aes_encrypt(plaintext: str, password: str) -> str:
    """Encrypt plaintext with AES-256-CBC; return base64-encoded blob."""
    salt = secrets.token_bytes(SALT_SIZE)
    iv = secrets.token_bytes(IV_SIZE)
    key = _derive_key(password, salt)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode('utf-8')) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()

    blob = salt + iv + ciphertext
    return base64.b64encode(blob).decode('utf-8')


def aes_decrypt(encoded: str, password: str) -> str:
    """Decrypt a base64 AES-256-CBC blob; return plaintext."""
    blob = base64.b64decode(encoded.encode('utf-8'))
    salt = blob[:SALT_SIZE]
    iv = blob[SALT_SIZE:SALT_SIZE + IV_SIZE]
    ciphertext = blob[SALT_SIZE + IV_SIZE:]
    key = _derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode('utf-8')


def _msgtobinary(msg):
    if isinstance(msg, str):
        return ''.join(format(ord(c), '08b') for c in msg)
    elif isinstance(msg, (bytes, np.ndarray)):
        return [format(b, '08b') for b in msg]
    elif isinstance(msg, (int, np.uint8)):
        return format(msg, '08b')
    raise TypeError("Unsupported type for binary conversion")


def max_capacity(image_path: str) -> int:
    """Return maximum bytes that can be hidden in the image."""
    img = cv2.imread(image_path)
    if img is None:
        raise FileNotFoundError(f"Cannot read image: {image_path}")
    h, w, _ = img.shape
    return (h * w * 3) // 8


def encode(image_path: str, output_path: str, message: str, password: str = '') -> None:
    """
    Encode a message into an image using LSB steganography.

    Args:
        image_path:  Path to the cover image (any OpenCV-readable format).
        output_path: Path to save the stego image (use .png for lossless).
        message:     Secret text to hide.
        password:    If non-empty, AES-256 encrypt the message first.
    """
    img = cv2.imread(image_path)
    if img is None:
        raise FileNotFoundError(f"Cannot read image: {image_path}")

    if password:
        message = aes_encrypt(message, password)

    no_of_bytes = (img.shape[0] * img.shape[1] * 3) // 8
    if len(message) + len(DELIMITER) > no_of_bytes:
        raise ValueError(f"Message too large. Max ~{no_of_bytes} bytes for this image.")

    data = message + DELIMITER
    binary_data = _msgtobinary(data)
    length_data = len(binary_data)
    index_data = 0

    for row in img:
        for pixel in row:
            r, g, b = _msgtobinary(pixel)
            if index_data < length_data:
                pixel[0] = int(r[:-1] + binary_data[index_data], 2)
                index_data += 1
            if index_data < length_data:
                pixel[1] = int(g[:-1] + binary_data[index_data], 2)
                index_data += 1
            if index_data < length_data:
                pixel[2] = int(b[:-1] + binary_data[index_data], 2)
                index_data += 1
            if index_data >= length_data:
                break

    cv2.imwrite(output_path, img)


def decode(image_path: str, password: str = '') -> str:
    """
    Decode a hidden message from a stego image.

    Args:
        image_path: Path to the stego image.
        password:   If non-empty, AES-256 decrypt after LSB extraction.

    Returns:
        The recovered secret message.
    """
    img = cv2.imread(image_path)
    if img is None:
        raise FileNotFoundError(f"Cannot read image: {image_path}")

    data_binary = ""
    for row in img:
        for pixel in row:
            r, g, b = _msgtobinary(pixel)
            data_binary += r[-1]
            data_binary += g[-1]
            data_binary += b[-1]
            total_bytes = [data_binary[i:i + 8] for i in range(0, len(data_binary), 8)]
            decoded_data = ""
            for byte in total_bytes:
                decoded_data += chr(int(byte, 2))
                if decoded_data[-5:] == DELIMITER:
                    result = decoded_data[:-5]
                    if password:
                        result = aes_decrypt(result, password)
                    return result
    raise ValueError("No hidden message found or delimiter missing.")
