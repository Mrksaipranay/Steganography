"""
Text Steganography Module
- Hides text inside a cover text file using Zero-Width Characters (ZWC)
- Four ZWCs represent 2-bit pairs; each character encodes to 12 bits
"""

ZWC = {"00": u'\u200C', "01": u'\u202C', "11": u'\u202D', "10": u'\u200E'}
ZWC_REVERSE = {v: k for k, v in ZWC.items()}
DELIMITER_BITS = "111111111111"


def _txt_encode_bits(text: str) -> str:
    """Convert text to the 12-bit-per-char ZWC binary representation."""
    result = ""
    for ch in text:
        t = ord(ch)
        if 32 <= t <= 64:
            t1 = t + 48
            t2 = t1 ^ 170
            result += "0011" + bin(t2)[2:].zfill(8)
        else:
            t1 = t - 48
            t2 = t1 ^ 170
            result += "0110" + bin(t2)[2:].zfill(8)
    return result + DELIMITER_BITS


def _txt_decode_bits(bits: str) -> str:
    """Reverse the 12-bit-per-char encoding back to text."""
    message = ""
    i = 0
    while i < len(bits):
        tag = bits[i:i + 4]
        data = bits[i + 4:i + 12]
        if len(data) < 8:
            break
        val = int(data, 2)
        if tag == "0110":
            message += chr((val ^ 170) + 48)
        elif tag == "0011":
            message += chr((val ^ 170) - 48)
        i += 12
    return message


def max_capacity(cover_text_path: str) -> int:
    """Return maximum number of characters that can be hidden."""
    with open(cover_text_path, 'r', encoding='utf-8') as f:
        words = f.read().split()
    return len(words) // 6


def encode(cover_text_path: str, output_path: str, message: str) -> None:
    """
    Hide a message inside a cover text file using ZWC steganography.

    Args:
        cover_text_path: Path to the original cover .txt file.
        output_path:     Path to save the stego .txt file.
        message:         Secret text to hide.
    """
    with open(cover_text_path, 'r', encoding='utf-8') as f:
        words = f.read().split()

    bits = _txt_encode_bits(message)

    if len(bits) > len(words) * 12:
        raise ValueError(
            f"Message too large. Cover text supports ~{len(words) // 6} characters."
        )

    stego_words = []
    bit_idx = 0
    word_idx = 0

    while bit_idx < len(bits) and word_idx < len(words):
        chunk = bits[bit_idx:bit_idx + 12]
        hidden = ""
        for j in range(0, len(chunk), 2):
            pair = chunk[j:j + 2]
            hidden += ZWC.get(pair, "")
        stego_words.append(words[word_idx] + hidden)
        bit_idx += 12
        word_idx += 1

    # Append remaining uncovered words
    stego_words.extend(words[word_idx:])

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(" ".join(stego_words))


def decode(stego_path: str) -> str:
    """
    Extract the hidden message from a stego text file.

    Args:
        stego_path: Path to the stego .txt file.

    Returns:
        The recovered secret message.
    """
    with open(stego_path, 'r', encoding='utf-8') as f:
        content = f.read()

    bits = ""
    for word in content.split():
        word_bits = ""
        for ch in word:
            if ch in ZWC_REVERSE:
                word_bits += ZWC_REVERSE[ch]
        if word_bits == DELIMITER_BITS:
            break
        bits += word_bits

    if not bits:
        raise ValueError("No hidden message found in this file.")

    return _txt_decode_bits(bits)
