"""
Steganalysis Module — Chi-Square Attack
Estimates the probability that an image contains hidden LSB data by testing
whether the distribution of pixel LSBs deviates significantly from natural.

A clean image has correlated LSBs with neighboring values.
After LSB embedding, pairs of values (2k, 2k+1) should appear equally often.
Chi-square measures this deviation.
"""

import cv2
import numpy as np
from typing import Tuple


def chi_square_analysis(image_path: str) -> Tuple[float, float, str]:
    """
    Run chi-square steganalysis on an image's LSBs.

    Args:
        image_path: Path to the image to analyse.

    Returns:
        (chi_statistic, probability, verdict)
        - chi_statistic: raw chi-square value
        - probability:   0.0–1.0 estimate of steganographic content
        - verdict:       human-readable result string
    """
    img = cv2.imread(image_path)
    if img is None:
        raise FileNotFoundError(f"Cannot read image: {image_path}")

    # Flatten all channel bytes
    pixels = img.flatten().astype(np.int32)

    # For chi-square: compare observed pair frequencies
    # Pair (2k) and (2k+1) should be equal under LSB embedding
    chi_stat = 0.0
    total_pairs = 0

    for k in range(128):
        n1 = np.sum(pixels == 2 * k)       # even value count
        n2 = np.sum(pixels == 2 * k + 1)   # odd value count
        expected = (n1 + n2) / 2.0
        if expected > 0:
            chi_stat += ((n1 - expected) ** 2) / expected
            total_pairs += 1

    # Normalise chi-stat to a probability using simple sigmoid scaling
    # Higher chi_stat → lower steganographic probability (natural image)
    # Lower chi_stat → suspicious (uniform distribution = stego)
    if total_pairs == 0:
        return 0.0, 0.0, "Unable to analyse"

    # Normalised chi per pair
    normalised = chi_stat / total_pairs

    # Sigmoid mapping: large chi_stat means clean, small means stego
    # We map to "probability of steganographic content" (inverse relationship)
    import math
    exponent = max(-500, min(500, (normalised - 1.5) * 3))
    stego_prob = 1.0 / (1.0 + math.exp(exponent))

    if stego_prob > 0.75:
        verdict = "🔴 HIGH probability of hidden data detected"
    elif stego_prob > 0.45:
        verdict = "🟡 MODERATE probability of hidden data"
    else:
        verdict = "🟢 LOW probability of hidden data (likely clean)"

    return chi_stat, round(stego_prob, 4), verdict


def batch_analyse(image_paths: list) -> list:
    """
    Analyse multiple images and return a list of result dicts.

    Args:
        image_paths: List of image file paths.

    Returns:
        List of dicts with keys: path, chi_stat, probability, verdict.
    """
    results = []
    for path in image_paths:
        try:
            chi, prob, verdict = chi_square_analysis(path)
            results.append({
                "path": path,
                "chi_stat": round(chi, 2),
                "probability": prob,
                "verdict": verdict
            })
        except Exception as e:
            results.append({
                "path": path,
                "chi_stat": None,
                "probability": None,
                "verdict": f"Error: {e}"
            })
    return results
