"""
Audio Steganography Module
- Modified LSB algorithm on WAV audio frames
- Hides message bits in the 2nd LSB / LSB of each frame byte
"""

import wave

DELIMITER = '*^*^*'


def max_capacity(audio_path: str) -> int:
    """Return maximum number of characters that can be hidden in a WAV file."""
    with wave.open(audio_path, mode='rb') as song:
        n = song.getnframes()
        frames = song.readframes(n)
    return (len(frames) // 8) - len(DELIMITER)


def encode(audio_path: str, output_path: str, message: str) -> None:
    """
    Hide a text message inside a WAV audio file.

    Args:
        audio_path:  Path to the cover WAV file.
        output_path: Path to save the stego WAV file.
        message:     Secret text to hide.
    """
    with wave.open(audio_path, mode='rb') as song:
        params = song.getparams()
        nframes = song.getnframes()
        frames = song.readframes(nframes)

    frame_bytes = bytearray(frames)

    data = message + DELIMITER
    bits = []
    for ch in data:
        b = bin(ord(ch))[2:].zfill(8)
        bits.extend(int(x) for x in b)

    if len(bits) > len(frame_bytes):
        raise ValueError(
            f"Message too large. Max ~{(len(frame_bytes) // 8) - len(DELIMITER)} characters."
        )

    for i, bit in enumerate(bits):
        res = bin(frame_bytes[i])[2:].zfill(8)
        if res[-4] == str(bit):
            frame_bytes[i] = (frame_bytes[i] & 253)       # clear 2nd LSB → 0
        else:
            frame_bytes[i] = (frame_bytes[i] & 253) | 2   # set 2nd LSB → 1
            frame_bytes[i] = (frame_bytes[i] & 254) | bit  # set LSB = message bit

    with wave.open(output_path, 'wb') as out:
        out.setparams(params)
        out.writeframes(bytes(frame_bytes))


def decode(audio_path: str) -> str:
    """
    Extract a hidden message from a stego WAV audio file.

    Args:
        audio_path: Path to the stego WAV file.

    Returns:
        The recovered secret message string.
    """
    with wave.open(audio_path, mode='rb') as song:
        nframes = song.getnframes()
        frames = song.readframes(nframes)

    frame_bytes = bytearray(frames)
    extracted = ""

    for i in range(len(frame_bytes)):
        res = bin(frame_bytes[i])[2:].zfill(8)
        if res[-2] == '0':
            extracted += res[-4]
        else:
            extracted += res[-1]

        if len(extracted) % 8 == 0 and len(extracted) >= 8:
            all_bytes = [extracted[j:j + 8] for j in range(0, len(extracted), 8)]
            decoded = ""
            for byte in all_bytes:
                decoded += chr(int(byte, 2))
            if decoded[-5:] == DELIMITER:
                return decoded[:-5]

    raise ValueError("No hidden message found or delimiter missing.")
