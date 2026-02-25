"""
Video Steganography Module
- Combines RC4 stream cipher encryption with LSB image-frame steganography
- Message is encrypted with RC4 then embedded in the first designated frame
"""

import numpy as np
import cv2

DELIMITER = '*^*^*'


# ── RC4 helpers ──────────────────────────────────────────────────────────────

def _ksa(key: list) -> list:
    s = list(range(256))
    j = 0
    kl = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % kl]) % 256
        s[i], s[j] = s[j], s[i]
    return s


def _prga(s: list, n: int) -> list:
    i = j = 0
    ks = []
    while n > 0:
        n -= 1
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        ks.append(s[(s[i] + s[j]) % 256])
    return ks


def rc4_encrypt(plaintext: str, key: str) -> str:
    key_arr = [ord(c) for c in key]
    s = _ksa(key_arr)
    ks = np.array(_prga(s, len(plaintext)))
    pt = np.array([ord(c) for c in plaintext])
    cipher = ks ^ pt
    return ''.join(chr(c) for c in cipher)


def rc4_decrypt(ciphertext: str, key: str) -> str:
    # RC4 is symmetric
    return rc4_encrypt(ciphertext, key)


# ── LSB helpers ───────────────────────────────────────────────────────────────

def _msgtobinary(msg):
    if isinstance(msg, str):
        return ''.join(format(ord(c), '08b') for c in msg)
    elif isinstance(msg, (bytes, np.ndarray)):
        return [format(b, '08b') for b in msg]
    elif isinstance(msg, (int, np.uint8)):
        return format(msg, '08b')
    raise TypeError("Unsupported type")


def _embed_frame(frame: np.ndarray, data: str) -> np.ndarray:
    binary_data = _msgtobinary(data)
    length_data = len(binary_data)
    index_data = 0
    frame = frame.copy()
    for row in frame:
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
                return frame
    return frame


def _extract_frame(frame: np.ndarray) -> str:
    data_binary = ""
    for row in frame:
        for pixel in row:
            r, g, b = _msgtobinary(pixel)
            data_binary += r[-1]
            data_binary += g[-1]
            data_binary += b[-1]
            total_bytes = [data_binary[i:i + 8] for i in range(0, len(data_binary), 8)]
            decoded = ""
            for byte in total_bytes:
                decoded += chr(int(byte, 2))
                if decoded[-5:] == DELIMITER:
                    return decoded[:-5]
    raise ValueError("Delimiter not found in frame.")


# ── Public API ────────────────────────────────────────────────────────────────

def get_frame_count(video_path: str) -> int:
    cap = cv2.VideoCapture(video_path)
    count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    cap.release()
    return count


def encode(video_path: str, output_path: str, message: str,
           rc4_key: str, frame_number: int) -> None:
    """
    Encrypt message with RC4 and embed in a specific video frame using LSB.

    Args:
        video_path:   Path to the cover video.
        output_path:  Path to save the stego video.
        message:      Secret text to hide.
        rc4_key:      RC4 encryption key.
        frame_number: 1-indexed frame number to embed data into.
    """
    cap = cv2.VideoCapture(video_path)
    fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
    w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fourcc = cv2.VideoWriter_fourcc(*'XVID')
    out = cv2.VideoWriter(output_path, fourcc, fps, (w, h))

    ciphertext = rc4_encrypt(message, rc4_key)
    data = ciphertext + DELIMITER

    cur = 0
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break
        cur += 1
        if cur == frame_number:
            frame = _embed_frame(frame, data)
        out.write(frame)

    cap.release()
    out.release()


def decode(video_path: str, rc4_key: str, frame_number: int) -> str:
    """
    Extract and decrypt the hidden message from a stego video frame.

    Args:
        video_path:   Path to the stego video.
        rc4_key:      RC4 decryption key (same as encryption key).
        frame_number: 1-indexed frame number where data was embedded.

    Returns:
        The recovered plaintext message.
    """
    cap = cv2.VideoCapture(video_path)
    cur = 0
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break
        cur += 1
        if cur == frame_number:
            ciphertext = _extract_frame(frame)
            cap.release()
            return rc4_decrypt(ciphertext, rc4_key)
    cap.release()
    raise ValueError(f"Frame {frame_number} not found or message extraction failed.")
