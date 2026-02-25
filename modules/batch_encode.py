"""
Batch Image Encode Module
- Distributes a long message across multiple cover images (one chunk per image)
- Decodes by reading chunks from all stego images in order and reassembling
"""

import math
import os
from modules import image_steg


SEPARATOR = "||CHUNK||"   # written at start of each chunk so decoder knows index
END_MARKER = "||END||"


def encode_batch(image_paths: list, output_dir: str, message: str,
                 password: str = '') -> list:
    """
    Split a message across multiple images.

    Args:
        image_paths: List of cover image paths (one per chunk).
        output_dir:  Directory to save stego images.
        message:     Full secret message to distribute.
        password:    Optional AES password applied to each chunk.

    Returns:
        List of output stego image paths.
    """
    if not image_paths:
        raise ValueError("No images provided.")

    n = len(image_paths)
    chunk_size = math.ceil(len(message) / n)
    chunks = [message[i:i + chunk_size] for i in range(0, len(message), chunk_size)]

    # Pad to match image count
    while len(chunks) < n:
        chunks.append("")

    os.makedirs(output_dir, exist_ok=True)
    output_paths = []

    for idx, (img_path, chunk) in enumerate(zip(image_paths, chunks)):
        # Format: INDEX|TOTAL|payload
        payload = f"{idx}|{n}|{chunk}"
        ext = os.path.splitext(img_path)[1]
        # Always save as PNG for lossless quality
        out_name = f"batch_stego_{idx:03d}.png"
        out_path = os.path.join(output_dir, out_name)
        image_steg.encode(img_path, out_path, payload, password)
        output_paths.append(out_path)

    return output_paths


def decode_batch(stego_paths: list, password: str = '') -> str:
    """
    Reassemble a message from multiple stego images.

    Args:
        stego_paths: List of stego image paths (in any order; auto-sorted by index).
        password:    Optional AES password.

    Returns:
        The fully reconstructed secret message.
    """
    chunks = {}

    for path in stego_paths:
        raw = image_steg.decode(path, password)
        parts = raw.split("|", 2)
        if len(parts) < 3:
            raise ValueError(f"Invalid batch payload in {path}: '{raw}'")
        idx = int(parts[0])
        total = int(parts[1])
        chunk = parts[2]
        chunks[idx] = chunk

    if not chunks:
        raise ValueError("No valid batch chunks found.")

    total = max(chunks.keys()) + 1
    ordered = [chunks.get(i, "") for i in range(total)]
    return "".join(ordered)
