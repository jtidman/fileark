#!/usr/bin/python3
'''
Created on Sep 27, 2020

@author: James Tidman
'''

import os
import sys
import subprocess
import time

import logging
logger = logging.getLogger(__name__)


#=========================================================
def add_image_hashes(files, methods=None):
    """
    Adds selected perceptual hashes to FileInfo objects.

    Parameters:
        files   : List of FileInfo objects
        methods : List of hash method names to compute.
                  Options: 'phash', 'dhash', 'ahash'
                  Default: all three

    add_image_hashes(files, methods=["phash", "dhash", "ahash"])
    """
    if methods is None:
        methods = ["phash", "dhash", "ahash"]

    hash_funcs = {
        "phash": imagehash.phash,
        "dhash": imagehash.dhash,
        "ahash": imagehash.average_hash,
    }

    for f in files:
        try:
            img = Image.open(f.full_path)
            hashes = {}
            for method in methods:
                func = hash_funcs.get(method)
                if func:
                    hashes[method] = str(func(img))
            f.addinfo(hashes)
        except Exception as e:
            logger.warning(f"Hashing failed: {f.full_path} -> {e}")

import zlib
import base64


#=========================================================
def decode_orb_features(b64_str, shape=(-1, 32), dtype=np.uint8):
    """
    Decodes a UTF-8 string back into a NumPy array of ORB descriptors.

    TODO add this to read csv
    """
    if not b64_str:
        return None
    try:
        compressed = base64.b64decode(b64_str)
        raw_bytes = zlib.decompress(compressed)
        return np.frombuffer(raw_bytes, dtype=dtype).reshape(shape)
    except Exception as e:
        logger.warning(f"Failed to decode ORB features: {e}")
        return None
    
#=========================================================
def encode_orb_features(des):
    """
    Compresses and encodes ORB feature descriptors (NumPy array) into a UTF-8 string.
    """
    if des is None:
        return None
    try:
        raw_bytes = des.tobytes()
        compressed = zlib.compress(raw_bytes)
        b64_encoded = base64.b64encode(compressed).decode('utf-8')
        return b64_encoded
    except Exception as e:
        logger.warning(f"Failed to encode ORB features: {e}")
        return None
    
#=========================================================
def add_orb_features(files):
    """
    Adds ORB feature descriptors to FileInfo objects.
    """
    orb = cv2.ORB_create()
    for f in files:
        try:
            img = cv2.imread(f.full_path, 0)
            if img is None:
                continue
            kp, des = orb.detectAndCompute(img, None)
            enc_des = encode_orb_features(des)
            #f.addinfo({"orb_features": des.tolist() if des is not None else None})
            f.addinfo({"orb_features": enc_des})
        except Exception as e:
            logger.warning(f"ORB feature extraction failed: {f.full_path} -> {e}")

#=========================================================
def compare_image_hashes(files, method='phash', threshold=5):
    """
    Compare images by perceptual hash. Adds find_reason on matches.
    Returns list of (FileInfo1, FileInfo2, distance).
    """
    result = []
    n = len(files)
    for i in range(n):
        h1 = getattr(files[i], method)
        if h1 is None:
            continue
        for j in range(i + 1, n):
            h2 = getattr(files[j], method)
            if h2 is None:
                continue
            try:
                dist = imagehash.hex_to_hash(h1) - imagehash.hex_to_hash(h2)
            except Exception:
                continue
            if dist <= threshold:
                reason = f"{method}<{threshold}"
                for f in (files[i], files[j]):
                    prev = getattr(f, "find_reason", None)
                    f.addinfo({"find_reason": f"{prev};{reason}" if prev else reason})
                result.append((files[i], files[j], dist))
    return result

#=========================================================
def compare_orb_features(files, match_thresh=30):
    """
    Compare images by ORB descriptors. Adds find_reason on matches.
    Returns list of (FileInfo1, FileInfo2, match_count).
    """
    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
    result = []
    n = len(files)
    for i in range(n):
        des1 = getattr(files[i], "orb_features", None)
        if des1 is None:
            continue
        for j in range(i + 1, n):
            des2 = getattr(files[j], "orb_features", None)
            if des2 is None:
                continue
            try:
                matches = bf.match(np.array(des1, dtype=np.uint8),
                                   np.array(des2, dtype=np.uint8))
            except Exception:
                continue
            if len(matches) >= match_thresh:
                reason = f"orbmatch>{match_thresh}"
                for f in (files[i], files[j]):
                    prev = getattr(f, "find_reason", None)
                    f.addinfo({"find_reason": f"{prev};{reason}" if prev else reason})
                result.append((files[i], files[j], len(matches)))
    return result

def find_similar_images(files, hash_threshold=5, orb_match_thresh=30):
    """
    Detects visually similar images by comparing available hashes and ORB features.
    Prints pairs of similar images with reasons.

    Parameters:
        files             : List of FileInfo objects
        hash_threshold    : Max Hamming distance for imagehash matches
        orb_match_thresh  : Min match count for ORB to count as similar
    """
    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
    seen_pairs = set()

    def print_match(f1, f2, reason, score):
        logger.info(f"[{reason}] {score} →")
        logger.info(f"  {f1.full_path}")
        logger.info(f"  {f2.full_path}")
        logger.info("  Run:")
        logger.info(f"  eog {shell_quote(f1.full_path)} & ; eog {shell_quote(f2.full_path)} &\n")
        
    def is_new_pair(f1, f2):
        return (id(f1), id(f2)) not in seen_pairs and (id(f2), id(f1)) not in seen_pairs

    #-------------------------------
    # Perceptual hash comparisons
    for method in ["phash", "dhash", "ahash"]:
        for i in range(len(files)):
            h1 = getattr(files[i], method, None)
            if not h1:
                continue
            for j in range(i + 1, len(files)):
                h2 = getattr(files[j], method, None)
                if not h2:
                    continue
                try:
                    d = hex_to_hash(h1) - hex_to_hash(h2)
                except Exception:
                    continue
                if d <= hash_threshold and is_new_pair(files[i], files[j]):
                    seen_pairs.add((id(files[i]), id(files[j])))
                    print_match(files[i], files[j], f"{method}<{hash_threshold}", d)

    #-------------------------------
    # ORB feature comparison (compressed form)
    for i in range(len(files)):
        orb1 = getattr(files[i], "orb_features", None)
        if not orb1:
            continue
        des1 = decode_orb_features(orb1)
        if des1 is None:
            continue
        for j in range(i + 1, len(files)):
            orb2 = getattr(files[j], "orb_features", None)
            if not orb2:
                continue
            des2 = decode_orb_features(orb2)
            if des2 is None:
                continue
            try:
                matches = bf.match(des1, des2)
            except Exception:
                continue
            if len(matches) >= orb_match_thresh and is_new_pair(files[i], files[j]):
                seen_pairs.add((id(files[i]), id(files[j])))
                print_match(files[i], files[j], f"orb>{orb_match_thresh}", len(matches))

