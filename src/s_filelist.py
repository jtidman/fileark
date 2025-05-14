#!/usr/bin/env python3
'''
Created on April 24, 2025

@author: James Tidman


# pip install NA
sudo apt install libheif-examples exiftool



'''

import os
import sys
import csv
import random
from datetime import datetime, timedelta
import hashlib
from collections import defaultdict
from itertools import product
import re
import string
import shutil
import multiprocessing
import subprocess
import json
import shlex

from PIL import Image
import imagehash
from imagehash import hex_to_hash

import cv2
import numpy as np

import time
from functools import wraps
import argparse

from s_filelist_db import *

from m_helper import *

#========================================
import logging
#logging.basicConfig(stream=sys.stdout, level=logging.DEBUG - 1) 
logging.basicConfig(stream=sys.stdout, level=logging.WARNING) 
logger = logging.getLogger(__name__)
logger.info("startup")
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^


read_all_exif = False



#======================================================================
#

# Define the prioritized list of EXIF datetime fields
EXIF_DATETIME_PRIORITY = [
    "TimeStamp",
    "SubSecCreateDate",
    "CreateDate",
    "DateCreated",
    "DateTimeOriginal",
    "DateTimeDigitized",
]

# Define the additional EXIF fields we want to pull
EXIF_ADDITIONAL_FIELDS = [
    "MIMEType",
    "ImageWidth",
    "ImageHeight",

    "Make",
    "Model",
    "Software",
]

# Master field list to request from exiftool
EXIF_FIELDS_TO_REQUEST = EXIF_DATETIME_PRIORITY + EXIF_ADDITIONAL_FIELDS

def parse_exif_datetime(dt_str):
    """
    Attempts to parse EXIF datetime strings in various formats.
    """
    if not dt_str or not isinstance(dt_str, str):
        return None

    dt_str = dt_str.strip()

    for fmt in [
        "%Y:%m:%d %H:%M:%S.%f%z",   # Subsecond + timezone
        "%Y:%m:%d %H:%M:%S%z",      # No subsecond, with timezone
        "%Y:%m:%d %H:%M:%S.%f",     # Subsecond, no timezone
        "%Y:%m:%d %H:%M:%S",        # No subsecond, no timezone

        "%Y:%m:%d %H:%M%z",         # Partial time with timezone
        "%Y:%m:%d %H:%M",           # Partial time
        "%Y:%m:%d",                 # Date only
        "%a %b %d %H:%M:%S %Y",     # Tue Mar 01 15:24:03 2011
        "%m/%d/%Y %I:%M:%S %p",     # 4/10/1912 12:00:00 AM
        "%Y/%m/%d %H:%M:%S",        # Non-standard slash-separated EXIF
        "%Y",                       # Year only
    ]:
        try:
            return datetime.strptime(dt_str, fmt)
        except ValueError:
            continue

    return None

def extract_exiftool_info(fqfn):
    """
    Extracts selected EXIF fields from a file using exiftool -j.
    Returns a dict of parsed fields.
    """
    try:
        cmd = ["exiftool", "-j"]
        if not read_all_exif:
            cmd += [f"-{field}" for field in EXIF_FIELDS_TO_REQUEST]
        cmd.append(fqfn)

        output = subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL,
            text=True
        )
        exif_list = json.loads(output)
        if not exif_list or not isinstance(exif_list, list):
            return {}

        exif_data = exif_list[0]
        return exif_data

    except (subprocess.CalledProcessError, json.JSONDecodeError, FileNotFoundError):
        return {}

def add_parsed_exif_create_time(files):
    """
    Parses 'exif_create_time_str' in each FileInfo object and assigns to 'exif_create_time'.
    Skips if string is missing or unparsable.
    """
    for f in files:
        dt_str = getattr(f, "exif_create_time_str", None)
        if dt_str:
            dt = parse_exif_datetime(dt_str)
            if dt:
                f.addinfo({"exif_create_time": dt})
            else:
                logger.warning(f"Unparsable datetime: '{dt_str}' in file {f.full_path}")
    return files

def extract_number_and_unit(value, known_units=("px", "pt", "in", "mm", "cm", "%")):
    """
    Extracts (float_value, unit_str) from a string like '160px', '32pt', or '12.5in'.

    - Returns (None, None) if no valid number was found.
    - Only returns a unit if a valid number exists.
    """
    if value is None:
        return None, None

    s = str(value).strip().lower()

    for unit in known_units:
        if s.endswith(unit):
            num_str = s[:-len(unit)].strip()
            try:
                return float(num_str), unit
            except ValueError:
                return None, None

    try:
        return float(s), "px"  # assume default unit if only number is present
    except ValueError:
        return None, None
    
def add_exif_info(files):
    """
    Adds exif_create_time, mimetype, exif_imagewidth, and exif_imageheight
    using exiftool if available.
    """
    for f in files:
        try:
            exif_info = extract_exiftool_info(f.full_path)

            if read_all_exif :
                f.addinfo({"exif_all": exif_info})

            #--------------------------------------------------
            # Try to parse datetime in priority order
            for field in EXIF_DATETIME_PRIORITY:
                dt_str = exif_info.get(field)
                if dt_str:
                    f.addinfo({
                        "exif_create_time_str": dt_str,
                        "exif_time_field": field
                    })
                    break
                
            #--------------------------------------------------
            # Save additional fields if found
            exif_mime = exif_info.get("MIMEType")
            if exif_mime:
                f.addinfo({"mimetype": exif_mime})

            exif_width_raw = exif_info.get("ImageWidth")
            exif_height_raw = exif_info.get("ImageHeight")

            width_val, width_unit = extract_number_and_unit(exif_width_raw)
            height_val, height_unit = extract_number_and_unit(exif_height_raw)

            if width_val is not None:
                f.addinfo({"exif_imagewidth": width_val})
            if height_val is not None:
                f.addinfo({"exif_imageheight": height_val})

            # Use matching unit or fallback
            unit = width_unit if width_unit == height_unit else (width_unit or height_unit or "px")
            f.addinfo({"exif_units": unit})
            
            #--------------------------------------------------
            # determine image source
            make = str(exif_info.get("Make", "")).strip()
            model = str(exif_info.get("Model", "")).strip()
            software = str(exif_info.get("Software", "")).strip()

            parts = [p for p in (make, model, software) if p]
            imagesource = "; ".join(parts) if parts else None

            f.addinfo({"exif_imagesource": imagesource})

        except Exception as e:
            logger.warning(f"EXIF processing failed for {f.full_path}: {e.__class__.__name__}: {e}")

    return files

#======================================================================
#
def sanitize_filename(name):
    """
    Makes a filename safe for Linux/macOS.
    Removes characters that are forbidden on Windows.
    """
    # Remove Windows-forbidden characters
    name = re.sub(r'[\\/*?:"<>|]', "_", name)
    # Remove trailing dots or spaces
    name = name.rstrip(". ")
    # Optionally, handle reserved names (CON, PRN, etc.)
    reserved = {'CON', 'PRN', 'AUX', 'NUL',
                'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
                'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'}
    if name.upper().split('.')[0] in reserved:
        name = "_" + name
    return name

def shell_quote(path):
    return "'" + path.replace("'", "'\"'\"'") + "'"

#======================================================================
#
def write_dup_mv_script(fqfn_mv_script, files, fqfn_destination, ask_user=True):
    """
    Creates a zsh script to move files, preserving rel_path.
    Quotes paths safely and avoids duplicate mkdir -p calls.
    Adds 'find_reason' as a comment for traceability.
    """
    fqfn_destination = os.path.abspath(fqfn_destination)
    dirs_to_create = set()
    mv_commands = []
    mv_cmd = "mv -i" if ask_user else "mv"

    for f in files:
        src = os.path.join(f.base_path, f.rel_path, f.filename + ('.' + f.ext if f.ext else ''))
        dst_dir = os.path.join(fqfn_destination, f.rel_path)
        dst = os.path.join(dst_dir, f.filename + ('.' + f.ext if f.ext else ''))

        dirs_to_create.add(dst_dir)

        # Quote paths
        src_quoted = shell_quote(src)
        dst_quoted = shell_quote(dst)

        # Optional: show what file this duplicates
        kept_path = shell_quote(f.md5sum_kept) if f.md5sum_kept else "" 

        # Reason for removal
        reason = getattr(f, "find_reason", "")
        comment_parts = []
        if kept_path:
            comment_parts.append(f"dup of {kept_path}")
        if reason:
            comment_parts.append(reason)

        comment = " # " + " | ".join(comment_parts) if comment_parts else ""
        mv_commands.append(f"{mv_cmd} {src_quoted} {dst_quoted}{comment}")

    with open(fqfn_mv_script, 'w', encoding='utf-8') as script:
        script.write("#!/bin/zsh\n\n")

        for d in sorted(dirs_to_create):
            script.write(f"mkdir -p {shell_quote(d)}\n")
        script.write("\n")

        for cmd in mv_commands:
            script.write(cmd + "\n")

    os.chmod(fqfn_mv_script, 0o755)

#======================================================================
#
date_dir_re = re.compile(r"^(\d{4})(\d{2}|mm)?(\d{2}|dd)?_.*$")

def dir_is_dated(f):
    """
    Returns True if f's relative path has a parent directory that matches
    YYYY_, YYYYMM_, or YYYYMMDD_ pattern.
    """
    parts = f.rel_path.split(os.sep)
    if parts:
        # Check the last or first component of rel_path (depending how you build paths)
        is_dated = bool(date_dir_re.match(parts[-1])) or bool(date_dir_re.match(parts[0]))
        #if is_dated :
        #    logger.info("dated: {}".format(parts))
        return is_dated
    return False

#======================================================================
#
def append_str(existing, new_value):
    """
    Appends new_value to existing string using semicolon delimiter.
    Returns new_value if existing is None.
    """
    if existing:
        return f"{existing};{new_value}"
    return new_value

#======================================================================
#
#======================================================================
#
def find_dups_by_md5sum_within_list(files):
    """
    Return a list of duplicates using the md5sum within a list.
    Adds 'md5sum_kept' as full_path.
    """
    md5_map = defaultdict(list)
    file_dups = []

    for f in files:
        md5 = getattr(f, "md5sum", None)
        if md5:
            md5_map[md5].append(f)

    for group in md5_map.values():
        if len(group) > 1:
            keeper = None
            for f in group:
                if keeper is None:
                    keeper = f
                elif dir_is_dated(f) and not dir_is_dated(keeper):
                    keeper.addinfo({"md5sum_kept": getattr(keeper, "full_path", None)})
                    file_dups.append(keeper)
                    keeper = f
                else:
                    f.addinfo({"md5sum_kept": getattr(keeper, "full_path", None)})
                    file_dups.append(f)

    return file_dups

#======================================================================
#
def find_dups_by_md5sum_between_lists(files_a, files_b):
    """
    Return a list of files in files_b that match files_a by md5sum.
    Mark files in files_b with 'md5sum_kept' by setting to files_a's full_path.
    """
    md5_map_a = defaultdict(list)
    file_dups = []
    seen = set()

    for f in files_a:
        md5 = getattr(f, "md5sum", None)
        if md5:
            md5_map_a[md5].append(f)

    for f in files_b:
        md5 = getattr(f, "md5sum", None)
        if md5 in md5_map_a and id(f) not in seen:
            keeper = md5_map_a[md5][0]
            f.addinfo({"md5sum_kept": getattr(keeper, "full_path", None)})
            file_dups.append(f)
            seen.add(id(f))

    return file_dups

#======================================================================
#
def find_dups_by_md5sum_v0(cur_files, unc_files=None):
    """
    Wrapper function to find duplicates within and between file lists.
    """
    dups = []

    if cur_files:
        dups += find_dups_by_md5sum_within_list(cur_files)

    if unc_files:
        dups += find_dups_by_md5sum_within_list(unc_files)
        dups += find_dups_by_md5sum_between_lists(cur_files, unc_files)

    return dups

#======================================================================
#
def add_md5sums(files, blocksize=65536):
    """
    Calculates MD5 checksums for each file and stores into .md5sum field.
    """
    for f in files:
        #full_path = os.path.join(f.base_path, f.rel_path, f.filename + ('.' + f.ext if f.ext else ''))
        #full_path = os.path.abspath(full_path)

        try:
            hash_md5 = hashlib.md5()
            with open(f.full_path, "rb") as file:
                for chunk in iter(lambda: file.read(blocksize), b""):
                    hash_md5.update(chunk)
            f.addinfo({"md5sum": hash_md5.hexdigest()})
        except FileNotFoundError:
            logger.warning(f"Warning: File not found {f.full_path}")
            continue
        except PermissionError:
            logger.warning(f"Warning: Permission denied {f.full_path}")
            continue

    return files

#======================================================================
#
def add_os_stats(files):
    for f in files:
        #full_path = os.path.join(f.base_path, f.rel_path, f.filename + ('.' + f.ext if f.ext else ''))
        #full_path = os.path.abspath(full_path)

        try:
            st = os.stat(f.full_path)

            results = {
                "st_mode": st.st_mode,
                "st_ino": st.st_ino,
                "st_dev": st.st_dev,
                "st_nlink": st.st_nlink,
                "st_uid": st.st_uid,
                "st_gid": st.st_gid,
                "filesize": st.st_size,  # Explicitly also save into 'filesize'
                "st_atime": datetime.fromtimestamp(st.st_atime),
                "st_mtime": datetime.fromtimestamp(st.st_mtime),
                "st_ctime": datetime.fromtimestamp(st.st_ctime),            
                }

            # You may want to set filesize explicitly from stat result
            results["filesize"] = st.st_size

            f.addinfo(results)

        except FileNotFoundError:
            logger.warning(f"Warning: File not found {f.full_path}")
            continue

    return files

#======================================================================
#
def add_file_info(files, mimeonly=True):
    for f in files:
        #full_path = os.path.join(f.base_path, f.rel_path, f.filename + ('.' + f.ext if f.ext else ''))
        #full_path = os.path.abspath(full_path)

        try:
            file_description = None
            if not mimeonly :
                # Get the human-readable description
                file_description = subprocess.check_output(
                    ['file', '--brief', f.full_path],
                    stderr=subprocess.DEVNULL,
                    text=True
                ).strip()

            # Get the MIME type + charset
            mime_output = subprocess.check_output(
                ['file', '--brief', '--mime', f.full_path],
                stderr=subprocess.DEVNULL,
                text=True
            ).strip()

            parts = mime_output.split(";")
            mimetype = parts[0].strip()
            file_charset = parts[1].strip() if len(parts) > 1 else None

            f.addinfo({
                "file_description": file_description,
                "mimetype": mimetype,
                "file_charset": file_charset
            })

        except subprocess.CalledProcessError:
            logger.warning(f"Warning: Unable to determine type for {f.full_path}")
            continue
        except FileNotFoundError:
            logger.warning(f"Warning: File not found {f.full_path}")
            continue

    return files






#======================================================================
#
def find_zerolen(filelist):
    """
    Returns a list of FileInfo objects that have zero file size.
    Appends 'zerolen' to the 'find_reason' field.
    """
    result = [f for f in filelist if not getattr(f, "filesize", None)]

    #for f in result:
    #    f.addinfo({"find_reason": append_str(getattr(f, "find_reason", None), "zerolen")})

    return result



#======================================================================
#
def find_files_in_base_dir(cur_files):
    """
    Returns only the FileInfo objects whose files are in the base_path root
    (i.e. rel_path is empty or ".").
    Appends 'base_dir' to the 'find_reason' field using semicolon delimiter.
    """
    result = [f for f in cur_files if f.rel_path in ("", ".", None)]

    #for f in result:
    #    f.addinfo({"find_reason": append_str(getattr(f, "find_reason", None), "base_dir")})
    return result

##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################


#======================================================================
# Global sets of known image and video file extensions (lowercase)
IMAGE_EXTENSIONS = {
    "bmp", "cal", "cgm", "clp", "cmx", "cr2", "crw", "cur", "cut", "dcr", "dcx", "dib", "drw",
    "emf", "eps", "fpx", "gem", "gif", "hdp", "hpgl", "iff", "img", "jp2", "jpg", "jpeg", "jps", "kdc",
    "lbm", "mac", "mpo", "mrw", "msp", "nef", "orf", "pbm", "pcd", "pct", "pict", "pcx", "pdf",
    "pef", "pgm", "pic", "png", "pns", "ppm", "psd", "pspimage", "psp", "raf", "ras", "raw",
    "riff", "rle", "sct", "srf", "svg", "tga", "tif", "tiff", "ufo", "webp", "wbmp", "wmf",
    "x3f", "wpg",
    "thm", "jpe", "heic", "bak", "dng", "htm", "xcf", "jpx"
}

VIDEO_EXTENSIONS = {
    "mp4", "mov", "avi", "mkv", "wmv", "flv", "webm", "m4v", "mpg",
    "vob" 
}

AUDIO_EXTENSIONS = {
    "mp3", "wav", "flac", "aac", "ogg", "m4a", "wma", "aiff", "alac", "opus"
}

image_exts = set()
video_exts = set()
audio_exts = set()

def find_media_files(files, find_images=True, find_videos=True, find_audio=True, invert=False,
                   use_ext=False, warn_on_conflict=False, media_options=None):
    """
    Filters FileInfo objects by media type using MIME or extension.
    Supports optional image resolution filters via media_options.

    Parameters:
        files              : List of FileInfo objects
        find_images        : Include images
        find_videos        : Include videos
        find_audio         : Include audio
        invert             : Return files NOT matching any media type
        use_ext            : Use file extension if EXIF MIME is missing
        warn_on_conflict   : Print mismatches between MIME and extension
        media_options      : Dict with optional keys:
            - image_exts   : set of str
            - video_exts   : set of str
            - audio_exts   : set of str
            - filter_out_widths_lte    : int
            - filter_out_heights_lte   : int
            - filter_out_areas_lte     : int

    Returns:
        Filtered list of FileInfo objects
    """
    opts = {
        "image_exts": IMAGE_EXTENSIONS,
        "video_exts": VIDEO_EXTENSIONS,
        "audio_exts": AUDIO_EXTENSIONS,
        "filter_out_widths_lte": None,
        "filter_out_heights_lte": None,
        "filter_out_areas_lte": None,
    }
    if media_options:
        opts.update(media_options)

    result = []

    for f in files:
        ext = (f.ext or "").lower()
        mime = (getattr(f, "mimetype", "") or "").lower()

        # MIME-based checks
        is_image_mime = mime.startswith("image/")
        is_video_mime = mime.startswith("video/")
        is_audio_mime = mime.startswith("audio/")

        # Extension-based checks
        is_image_ext = ext in opts["image_exts"]
        is_video_ext = ext in opts["video_exts"]
        is_audio_ext = ext in opts["audio_exts"]

        is_image = is_image_mime or (use_ext and is_image_ext)
        is_video = is_video_mime or (use_ext and is_video_ext)
        is_audio = is_audio_mime or (use_ext and is_audio_ext)

        match = (
            (find_images and is_image) or
            (find_videos and is_video) or
            (find_audio and is_audio)
        )

        if warn_on_conflict:
            if is_image_mime and not is_image_ext:
                logger.warning(f"WARNING: {f.full_path} has MIME '{mime}' but unknown extension '{ext}'")
            if is_image_ext and not is_image_mime:
                logger.warning(f"WARNING: {f.full_path} has extension '{ext}' but MIME '{mime}'")

        if match ^ invert:
            if invert:
                #f.addinfo({"find_reason": append_str(getattr(f, "find_reason", None), "not_media")})
                result.append(f)
            else:
                if is_image:
                    w = getattr(f, "exif_imagewidth", None)
                    h = getattr(f, "exif_imageheight", None)
                    if opts["filter_out_widths_lte"] is not None and (w is None or w > opts["filter_out_widths_lte"]):
                        continue
                    if opts["filter_out_heights_lte"] is not None and (h is None or h > opts["filter_out_heights_lte"]):
                        continue
                    if opts["filter_out_areas_lte"] is not None and (w is None or h is None or w * h > opts["filter_out_areas_lte"]):
                        continue
                result.append(f)

        if is_image and ext not in IMAGE_EXTENSIONS:
            image_exts.add(ext)
        if is_video and ext not in VIDEO_EXTENSIONS:
            video_exts.add(ext)
        if is_audio and ext not in AUDIO_EXTENSIONS:
            audio_exts.add(ext)

    return result

def find_image_files(files, invert=False, use_ext=False, warn_on_conflict=False, media_options=None):
    return find_media_files(files, find_images=True, find_videos=False, find_audio=False,
                          invert=invert, use_ext=use_ext, warn_on_conflict=warn_on_conflict,
                          media_options=media_options)

def find_videos(files, invert=False, use_ext=False, warn_on_conflict=False, media_options=None):
    return find_media_files(files, find_images=False, find_videos=True, find_audio=False,
                          invert=invert, use_ext=use_ext, warn_on_conflict=warn_on_conflict,
                          media_options=media_options)

def find_audio_files(files, invert=False, use_ext=False, warn_on_conflict=False, media_options=None):
    return find_media_files(files, find_images=False, find_videos=False, find_audio=True,
                          invert=invert, use_ext=use_ext, warn_on_conflict=warn_on_conflict,
                          media_options=media_options)

def update_attrib(files, attr, value, append=True):
    """
    Updates or appends a value to an attribute on a list of FileInfo objects.

    Parameters:
        files  : list of FileInfo
        attr   : attribute name to update
        value  : static value or callable(file) -> value
        append : if True, appends value using append_str(); else replaces
    """
    for f in files:
        current = getattr(f, attr, None)
        new_val = value(f) if callable(value) else value

        if append:
            setattr(f, attr, append_str(current, new_val))
        else:
            setattr(f, attr, new_val)

    return files

def clear_attrib(files, attrib):
    """
    Resets the specified attribute to its default value for all FileInfo objects in the list.

    Parameters:
        files  : list of FileInfo objects
        attrib : name of the attribute to reset

    Raises:
        KeyError if attrib is not defined in fileinfo_defaults.
    """
    if attrib not in fileinfo_defaults:
        raise KeyError(f"Attribute '{attrib}' not found in fileinfo_defaults.")

    default_val, _ = fileinfo_defaults[attrib]

    for f in files:
        setattr(f, attrib, default_val)

    return files

##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################






##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################

def add_renamed_fields(files):
    """
    Adds 'filename_new', 'ext_new', and 'ftime_mismatch' to FileInfo objects.

    - Formats filename from EXIF datetime: YYYYMMDD_HHMMSS_mmm
    - Skips rename if current filename matches the format or starts with 'NT_'
    - Flags mismatches between filename and EXIF timestamp
    """
    name_pattern = re.compile(r"^(\d{8}_\d{6}_\d{3})([a-z]{0,2})$", re.IGNORECASE)

    for f in files:
        ext = (f.ext or "").lower()
        exif_dt = getattr(f, "exif_create_time", None)

        # Skip renaming if filename starts with "NT_"
        if (f.filename or "").startswith("NT_"):
            f.addinfo({
                "filename_new": None,
                "ext_new": None,
                "ftime_mismatch": False,
            })
            continue

        if isinstance(exif_dt, datetime):
            millis = exif_dt.microsecond // 1000
            actual_base_name = f"{exif_dt.strftime('%Y%m%d_%H%M%S')}_{millis:03}"
        else:
            actual_base_name = "NT_" + (f.filename or "")

        # Check for conformance and mismatches
        match = name_pattern.fullmatch(f.filename or "")
        if match and ext == (f.ext or "").lower():
            existing_base = match.group(1)
            ftime_mismatch = (
                isinstance(exif_dt, datetime) and existing_base != actual_base_name
            )

            if ftime_mismatch:
                logger.warning(
                    f"⚠️  Timestamp mismatch for file '{f.filename}.{f.ext}':\n"
                    f"    ↳ From filename: {existing_base}\n"
                    f"    ↳ From EXIF    : {actual_base_name}"
                )

            f.addinfo({
                "filename_new": None,
                "ext_new": None,
                "ftime_mismatch": ftime_mismatch,
            })
            continue

        # Set base rename info
        f.addinfo({
            "filename_new": actual_base_name,
            "ext_new": ext,
            "ftime_mismatch": False
        })

    return files

def generate_suffixes(max_len=2):
    """
    Generates suffixes: '', 'a' to 'z', 'aa' to 'zz'.
    """
    yield ""  # first one gets no suffix
    alphabet = string.ascii_lowercase
    for length in range(1, max_len + 1):
        for combo in product(alphabet, repeat=length):
            yield ''.join(combo)

def write_newfn_rename_script(fqfn_rename_script, files, ask_user=True):
    """
    Writes a zsh script to rename files in-place using filename_new/ext_new fields.
    Auto-resolves duplicate destination names using suffixes ('a'..'zz').
    """
    path_map = {}  # (rel_path, ext) → {base_name → suffix count}
    used_paths = set()
    rename_cmds = []
    mv_cmd = "mv -i" if ask_user else "mv"

    for f in files:
        if not f.filename_new or not f.ext_new:
            continue  # skip unchanged

        rel_path = f.rel_path
        ext = f.ext_new
        base_name = f.filename_new
        old_path = os.path.abspath(os.path.join(f.base_path, rel_path, f.filename + ('.' + f.ext if f.ext else '')))

        key = (rel_path, ext, base_name)
        if key not in path_map:
            path_map[key] = generate_suffixes(max_len=2)

        while True:
            suffix = next(path_map[key])
            candidate_name = base_name + suffix
            new_name_full = candidate_name + ('.' + ext if ext else '')
            new_path = os.path.abspath(os.path.join(f.base_path, rel_path, new_name_full))

            if new_path not in used_paths:
                used_paths.add(new_path)
                break

        rename_cmds.append(f"{mv_cmd} {shell_quote(old_path)} {shell_quote(new_path)}")

    with open(fqfn_rename_script, 'w', encoding='utf-8') as script:
        script.write("#!/bin/zsh\n\n")
        script.write("\n".join(rename_cmds))
        script.write("\n")

    os.chmod(fqfn_rename_script, 0o755)

def write_exif_csv(csv_fqfn, files, no_overwrite=True):
    """
    Writes a CSV file with one row per file, and columns for each unique key found in exif_all.
    Assumes 'exif_all' is a JSON-formatted string in each FileInfo object.
    """

    # Backup existing file if needed
    if no_overwrite and os.path.exists(csv_fqfn):
        base, ext = os.path.splitext(csv_fqfn)
        backup_name = base + "-" + timestamp_suffix() + ext
        logger.info(f"Existing file {csv_fqfn} found. Moving to {backup_name}")
        shutil.move(csv_fqfn, backup_name)

    # First pass to collect all unique EXIF keys
    all_keys = set()
    exif_data_per_file = []

    for f in files:
        exif_dict = getattr(f, "exif_all", {})
        if not isinstance(exif_dict, dict):
            logger.info(f"⚠️ Invalid exif_all in {f}, expected dict")
            exif_data_per_file.append({})
            continue

        exif_data_per_file.append(exif_dict)
        all_keys.update(exif_dict.keys())

    all_keys = sorted(all_keys)

    # Write CSV
    with open(csv_fqfn, 'w', newline='', encoding='utf-8') as f_csv:
        writer = csv.DictWriter(f_csv, fieldnames=all_keys)
        writer.writeheader()

        for exif_dict in exif_data_per_file:
            row = {k: exif_dict.get(k, "") for k in all_keys}
            writer.writerow(row)

    return csv_fqfn



##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################

os_stats_pipeline = [
    (add_os_stats, 1),
]

media_pipeline = [
    (add_md5sums, 1), 
    (add_exif_info, 1), 
    (add_parsed_exif_create_time,  0),
    (add_renamed_fields, 0),
]

os_media_pipeline = os_stats_pipeline + media_pipeline

#======================================================================
#
process_defaults = {

    "fqdn": (None, str),
    "mvfilt_nfqdn": (None, str),
    "mvunc_nfqdn": (None, str),

    "read_db_fqfn": (None, str),

    "db_fqfn": (None, str),
    "regenerate_db": (False, bool),  # priority

    "dbgdb_fqfn": (None, str),
    "dbgexif_fqfn": (None, str),
#    "process_db": (None, int),

    "fqfn_mv_script": (None, str),
    "fqfn_rename_script": (None, str),
    "fqfn_mvunc_script": (None, str),

    "files": ([], list),    

    "basedir_files": ([], list),
    "zerolen_files": ([], list),
    "not_media_files": ([], list),
    "md5sum_dup_files": ([], list),

    # temporary use
    "db_files": ([], list),
    "files_not_in_dir": ([], list),
    "files_not_in_db": ([], list),
    "files_dont_match": ([], list),
    "small_image_files": ([], list),

}

class Process():

    def __init__(self, config={}) :

        # maybe add a dir_type flag, "media", "audio", "docs", etc.
        # use to configure fields in the db load/check
        # configure process steps
        # configure outputs

        # set up logging        
        #logger.debug("class init")

        # combine dictionaries and create object attributes from them
        init_object_attributes_enh(self, process_defaults, config)

#......................................................................
#
    def addinfo(self, info_dict):
        for k, v in info_dict.items():
            setattr(self, k, v)
            #setattr(self, k, coerce_value(v, fileinfo_defaults[k][1]))

#......................................................................
#
    def __setattr__(self, name, value):

#        if name == "ext" :
#            if value==None or len(value) ==0:
#                pass

        # Look up the expected type from fileinfo_defaults
        expected_info = process_defaults.get(name)
        if expected_info:
            _, expected_type = expected_info
            if expected_type:
                value = coerce_value(value, expected_type)

        # Finally set the attribute
        super().__setattr__(name, value)

#......................................................................
#
#    def __repr__(self) :
#        pass

#......................................................................
#
    def print_stats(self) :

        logger.info("----------")
        logger.info("Base dir files: {}".format(len(self.basedir_files)))
        logger.info("Zero len files: {}".format(len(self.zerolen_files)))
        logger.info("Not media files: {}".format(len(self.not_media_files)))
        logger.info("MD5SUM dup files: {}".format(len(self.md5sum_dup_files)))
        logger.info("----------")


#......................................................................
#
    def pre_process_dir(self):
        """
        """

        if self.fqdn == None :
            #stub out all attribs
            return

        # set the default input database

        # use provided db name, otherwise use default
        if self.read_db_fqfn == None:
            self.read_db_fqfn = os.path.join(self.fqdn, "curated_db.csv")
        else :
            self.read_db_fqfn = os.path.join(self.fqdn, self.read_db_fqfn)

        # set the default output databases
        self.db_fqfn = os.path.join(self.fqdn, "curated_db.csv")
        self.dbgdb_fqfn = os.path.join(self.fqdn,  "debug_db.csv")
        self.dbgexif_fqfn = os.path.join(self.fqdn,  "exif_db.csv")

        # set default script filename
        self.fqfn_mv_script = os.path.join(self.fqdn, "1_mvfiltered.sh")
        self.fqfn_rename_script = os.path.join(self.fqdn, "2_rename.sh")
        self.fqfn_mvunc_script = os.path.join(self.fqdn, "3_mvuncurated.sh")

        # set default duplicates directory
        if self.mvfilt_nfqdn == None :
            self.mvfilt_nfqdn = os.path.join(self.fqdn, "../duplicates")

        # set default duplicates directory
        # only do this if unc_mv_nqfdn is not absolute
        if self.mvunc_nfqdn is not None and not os.path.isabs(self.mvunc_nfqdn):
            self.mvunc_nfqdn = os.path.join(self.fqdn, self.mvunc_nfqdn)

        #----------------------------------------
        # build list of files
        # load os_stats for each file
        self.dbfs = FileDB()
        self.files = self.dbfs.create_from_dir(self.fqdn, os_stats_pipeline)
        

        #----------------------------------------
        # load db, skip if regenerate is requested
        if not self.regenerate_db :
            self.regenerate_db = False
            # load db
            self.db = FileDB()
            self.db_files = self.db.create_from_db(self.read_db_fqfn)

            if self.db_files == None :
                # TODO ask to continue and rebuild db, or exit
                while True:
                    resp = input(f"Required file {self.read_db_fqfn} is missing or empty. [n] stop, [r] regenerate from filesystem? ").strip().lower()
                    if resp == "r":
                        print("Reloading from filesystem...")
                        self.regenerate_db = True
                        break
                    elif resp == "n":
                        raise ValueError("User aborted due to database mismatch.")
                    else:
                        print("Invalid input. Please enter 'n' or 'r'.")
                #raise FileNotFoundError(f"Required file {self.read_db_fqfn} is missing or empty.")

            if not self.regenerate_db :
                #----------------------------------------
                # check for reasonable errors and fix, otherwise wait for confirmation from user

                # compare the just-read filelist to the saved one 
                # (only path/filename and os.stats are loaded at this point)

                # other things to check for and recover:
                #  - files have been renamed
                #  - files have been moved, but the filename and/or other stats are preserved

                self.files_not_in_dir, self.files_not_in_db, self.files_dont_match = compare_db(self.db_files, self.files)

                logger.info("----------")
                logger.info(f"Files in dir: {len(self.files)}")
                logger.info(f"Files in db:  {len(self.db_files)}")
                logger.info("----------")
                logger.info(f"Files missing in dir: {len(self.files_not_in_dir)}")
                logger.info(f"Files missing in db: {len(self.files_not_in_db)}")
                logger.info(f"Files that mismatch: {len(self.files_dont_match)}")
                logger.info("----------")

                len_files_not_in_dir = len(self.files_not_in_dir)
                len_files_not_in_db = len(self.files_not_in_db)
                len_files_dont_match = len(self.files_dont_match)

                total_issues = len_files_not_in_dir + len_files_not_in_db + len_files_dont_match

                # "y" correct errors and continue
                # "n" stop
                # "r" read new database from filesystem
                if total_issues > 300 :
                    while True:
                        resp = input(f"Database mismatch detected ({total_issues}). [y] fix and continue, [n] stop, [r] reload from filesystem? ").strip().lower()
                        if resp == "y":
                            if len_files_not_in_dir != 0 :
                                logger.debug(self.files_not_in_dir)
                                self.db_files = remove_extra_files_db(self.db_files, self.files_not_in_dir)

                            if len_files_not_in_db != 0 :
                                logger.debug(self.files_not_in_db)
                                self.db_files = add_missing_files_db(self.db_files, self.files_not_in_db, media_pipeline)

                            if len_files_dont_match != 0 :
                                logger.debug(self.files_dont_match)
                                self.db_files = update_files_db(self.db_files, self.files_dont_match, media_pipeline)

                            break
                        elif resp == "r":
                            print("Reloading from filesystem...")
                            self.regenerate_db = True
                            break
                        elif resp == "n":
                            raise ValueError("User aborted due to database mismatch.")
                        else:
                            print("Invalid input. Please enter 'y', 'n', or 'r'.")

        #----------------------------------------
        # If we use the db, do not call these time consuming functions
        if self.regenerate_db :
            print(f"Database not found, invalid, or rebuild requested - generating data from filesystem")
            self.files = mp_run_pipeline(self.files, media_pipeline) # os_stat already added
        else :
            self.files = self.db_files
            run_spot_check(self.files, percent=5, skip_recent=False, pipeline=os_media_pipeline) # check needs all fields added

        if not exif_data_in_db(self.files) :
            # should rebuild, but this is the most time consuming task
            # ask user what to do
            raise ValueError(f"File {self.read_db_fqfn} does not seem to contain exif data.")



#......................................................................
#
    def process_dir_as_media(self) :
        """
        """

        if self.fqdn == None :
            #stub out all attribs
            return

        #----------------------------------------

        # TODO (mostly implemented) add optional determine image source based on camera, make, model, scanner, cd processing house, etc
        # usefull to build database of test images 
        # current known /  suspected issues
        # - video time may need to be tweaked (see heic code)
        # - probably lots of unknowns
        # - may help identify who took the image/video

        #----------------------------------------

        # clear the reason attribute
        clear_attrib(self.files, "find_reason")

        # find files in the base directory (usually database files, etc.)
        self.basedir_files = find_files_in_base_dir(self.files)
        update_attrib(self.basedir_files, "find_reason", "base dir")

        # find zero length files
        self.zerolen_files = find_zerolen(self.files)
        update_attrib(self.zerolen_files, "find_reason", "zero len")

        # find all files that are likely thumbnails or junk images
        self.small_image_files = find_image_files(self.files, 
            media_options = {
            "filter_out_widths_lte": 160-1,
            "filter_out_heights_lte": 120-1,
            })
        update_attrib(self.small_image_files, "find_reason", "small image")

        # find all files not media files (exlude audio)
        self.not_media_files = find_media_files(self.files, find_audio=False, invert=True)
        update_attrib(self.not_media_files, "find_reason", "not media")

        self.print_stats()

#......................................................................
#
    def post_process_dir(self):

        if self.fqdn == None :
            #stub out all attribs
            pass
        else :
            #----------------------------------------

            # write all curated files with md5sums (and other time consuming data collected)
            # this is the existing state of the curated directory (before any modifications)
            write_csv(self.dbgdb_fqfn, self.files, fileinfo_defaults)

            if read_all_exif :
                write_exif_csv(self.dbgexif_fqfn, self.files)

            # write out move filtered files script
            # move (zerolen, not media, dups, small image) but not (basedir)
            move = self.zerolen_files+self.not_media_files+self.md5sum_dup_files+self.small_image_files
            no_move = self.basedir_files
            fl = remove_files_db(move, no_move)
            write_dup_mv_script(self.fqfn_mv_script, fl, self.mvfilt_nfqdn)

            if self.mvunc_nfqdn is not None :
                # write out move "media" files script if requested
                # move (zerolen, not media, dups, small image) but not (basedir)
                no_move = self.basedir_files+self.zerolen_files+self.not_media_files+self.md5sum_dup_files+self.small_image_files
                fl = remove_files_db(self.files, no_move)
                write_dup_mv_script(self.fqfn_mvunc_script, fl, self.mvunc_nfqdn)

            # write out rename files with date:time script
            # rename only the files that are not moved, and have vaild datetime info
            # TODO create a valid datetime function  find_valid_exif_datetime(files) update_datetime(files, )
            move = self.zerolen_files+self.not_media_files+self.md5sum_dup_files+self.small_image_files
            fl = remove_files_db(self.files, move)
            write_newfn_rename_script(self.fqfn_rename_script, fl)

            #----------------------------------------
            # save curated files after removing 0 len and md5sum duplicates
            # this is the state of the curated directory if all scripts generated are executed
            fl = remove_files_db(self.files, self.basedir_files+self.zerolen_files+self.not_media_files+self.md5sum_dup_files)
            write_csv(self.db_fqfn, fl, fileinfo_defaults)

#======================================================================
#
def hl_process_curated_dir(cur_fqdn,      cur_mvfilt_nfqdn=None, cur_read_db_fqfn=None, cur_regenerate_db=False, 
                           unc_fqdn=None, unc_mvfilt_nfqdn=None, unc_read_db_fqfn=None, unc_regenerate_db=False,
                           mvunc_nfqdn=None) :
    """
    High-level function to curate and clean up a media directory by:
    - Analyzing metadata,
    - Detecting invalid or duplicate files,
    - Generating shell scripts for safe removal and renaming,
    - Updating or generating a persistent file database.

    Parameters:
        cur_fqdn (str)             : Path to the curated media directory.
        cur_mvfilt_nfqdn (str)     : Directory where filtered files (e.g., zero-length, junk) are moved.
        cur_read_db_fqfn (str)     : Path to curated CSV database to read from (optional).
        cur_regenerate_db (bool)   : If True, regenerate curated DB from filesystem instead of reading it.

        unc_fqdn (str)             : Path to an uncurated directory for reference or deduplication.
        unc_mvfilt_nfqdn (str)     : Move destination for uncurated filtered files (currently unused).
        unc_read_db_fqfn (str)     : Path to uncurated CSV database (optional).
        unc_regenerate_db (bool)   : If True, regenerate uncurated DB from filesystem instead of reading it.
        mvunc_nfqdn (str)        : Optional path to store unique media from the uncurated set.

    Behavior:
        1. Loads file metadata from both curated and uncurated directories.
           - Uses multiprocessing for fast file stat/EXIF/hash extraction.
           - Loads from cached CSV if available, or regenerates if requested or missing.

        2. Validates file presence and consistency with the existing database.
           - Prompts user if discrepancies exceed threshold.
           - Applies updates by adding missing files or replacing stale ones.

        3. Filters files in both directories into categories:
           - Files in base directory
           - Zero-length files
           - Files too small to be useful (e.g., thumbnails)
           - Non-media files based on MIME type or extension

        4. Deduplicates curated files against uncurated using MD5 hashes.

        5. Generates the following artifacts in the curated directory:
           - `curated_db.csv`    : Final list of curated files (minus junk/dupes)
           - `debug_db.csv`      : All discovered files before filtering
           - `exif_db.csv`       : Optional CSV of full EXIF metadata
           - `1_mvfiltered.sh`   : Shell script to move junk/dupes to a subdir
           - `2_rename.sh`       : Shell script to rename remaining files by EXIF timestamp

    Notes:
        - All processing is driven by a central `Process` class and `FileInfo` metadata.
        - The user may be prompted to resolve inconsistencies if the DB is missing or outdated.
        - Designed to prepare a media library for archival or import into a media manager.

    Example:
        hl_process_curated_dir(
            cur_fqdn="/photos/curated",
            unc_fqdn="/photos/unsorted",
            cur_read_db_fqfn="curated_db.csv",
            unc_regenerate_db=True,
            mvunc_nfqdn="../mv_media"
        )
    """

    cur = Process({"fqdn": cur_fqdn, "mvfilt_nfqdn": cur_mvfilt_nfqdn, "read_db_fqfn": cur_read_db_fqfn, "regenerate_db": cur_regenerate_db})
    unc = Process({"fqdn": unc_fqdn, "mvfilt_nfqdn": unc_mvfilt_nfqdn, "read_db_fqfn": unc_read_db_fqfn, "regenerate_db": unc_regenerate_db, "mvunc_nfqdn": mvunc_nfqdn})

    #----------------------------------------
    # process unc first as it is most likely to have missing db or other errors
    unc.pre_process_dir()
    cur.pre_process_dir()

    #----------------------------------------
    # media (images, videos) specific processing

    unc.process_dir_as_media()
    cur.process_dir_as_media()

    # find duplicates using md5sum
    cur_fl = remove_files_db(cur.files, cur.basedir_files+cur.zerolen_files+cur.not_media_files)
    unc_fl = remove_files_db(unc.files, unc.basedir_files+unc.zerolen_files+unc.not_media_files)

    #----------
    cur.dups = find_dups_by_md5sum_within_list(cur_fl)
    update_attrib(cur.dups, "find_reason", "cur <-> cur")

    cur.uncdups = find_dups_by_md5sum_between_lists(cur_fl, unc_fl)
    update_attrib(cur.uncdups, "find_reason", "cur <-> unc")

    cur.md5sum_dup_files = cur.dups + cur.uncdups

    #----------
    unc.dups = find_dups_by_md5sum_within_list(unc_fl)
    update_attrib(unc.dups, "find_reason", "unc <-> unc")

    unc.uncdups = find_dups_by_md5sum_between_lists(cur_fl, unc_fl)
    update_attrib(unc.uncdups, "find_reason", "cur <-> unc")

    unc.md5sum_dup_files = unc.dups + unc.uncdups

    """
    cur.images = find_image_files(cur.files, use_ext=False, warn_on_conflict=False)
    #add_image_hashes(cur.images, methods=["phash", "dhash", "ahash"])
    add_image_hashes(cur.images, methods=["phash"])
    #add_orb_features(cur.images)

    find_similar_images(cur.images, hash_threshold=8)
    """

    #----------------------------------------
    cur.post_process_dir()
    unc.post_process_dir()

    #logger.info("\n".join(f"{k}: {v}" for k, v in self.__dict__.items()))
    logger.info("----------")
    logger.info("\n".join(f"\"{k}\" (None, str)," for k, v in cur.__dict__.items()))
    logger.info("----------")

#======================================================================
#
if __name__ == "__main__":

    logger.setLevel(logging.WARNING)

    #----------------------------------------
    # header stuff
    #
    start_time = time.time()

    # start logging
    #logging.basicConfig(stream=sys.stdout, level=logging.INFO) 
    #logger = logging.getLogger()
    logger.info("starting main......{}".format(start_time))
     
    # parse arguments
    parser = argparse.ArgumentParser(description='grab sequential images from scanner.')

    parser.add_argument("analysis_type", choices=["media", "audio", "mail"], 
                        help="Type of analysis to perform. Must be one of: media, audio, mail.")

    parser.add_argument("--debug", help="Prints lots of debug.", action="store_true")
    parser.add_argument("--info", help="Prints less debug.", action="store_true")

    parser.add_argument("--cur_dir", help="Curated directory.", default='.')
    parser.add_argument("--cur_regenerate_db", help="Re-read curated database file.", default=False)
    parser.add_argument("--cur_db", help="File to use as curated database.", default=None)

    parser.add_argument("--unc_dir", help="Uncurated directory.", default="")
    parser.add_argument("--unc_regenerate_db", help="Re-read uncurated database file.", default=False)
    parser.add_argument("--unc_db", help="File to use as uncurated database.", default=None)
    parser.add_argument("--mvunc_dir", help="Destination for unique media files fomr uncurated directory.", default=None)

    #--------------------
    # debug
    #if len(sys.argv) == 1 :

    if "JT_PYTHON_DEBUGGER_ACTIVE" in os.environ:
        username = os.environ["USER"]
                
        debug_cmdline = []

        debug_cmdline.append("media --debug "
                             f"--cur_dir '/home/{username}/Pictures/curated' "
                             "--cur_db 'debug_db.csv' "
                             f"--unc_dir '/home/{username}/test/Y2428Z1C' "
                             "--unc_db 'debug_db.csv' "
                             "--mvunc_dir '../mv_media' "
                             )
        
        debug_cmdline.append("media --debug "
                             f"--cur_dir '/home/{username}/Pictures/curated' "
                             "--cur_db 'debug_db.csv' "
                             f"--unc_dir '/home/{username}/.smbshare/dsk1_raid5_0/hdd_copies/Y2428Z1C' "
                             "--unc_db 'debug_db.csv' "
                             "--mvunc_dir '../mv_media' "
                            )

        # rerun on current database
        debug_cmdline.append("media --debug "
                             f"--cur_dir '/home/{username}/Pictures/curated' "
                             "--cur_db 'debug_db.csv' "
                             )
        
        # rerun on large test database (make copy before running)
        debug_cmdline.append("media --debug "
                             f"--cur_dir '/home/{username}/test/Y2428Z1C_baseline (Copy)' "
                             "--cur_db 'debug_db.csv' "
                             )

        debug_cmdline.append("media --debug "
                             f"--cur_dir '/home/{username}/Pictures/curated' "
                             "--cur_db 'debug_db.csv' "
                             f"--unc_dir '/home/{username}/test/Y2428Z1C_baseline (Copy)' "
                             "--unc_db 'debug_db.csv' "
                             "--mvunc_dir '../mv_media' "
                            )

        debug_cmdline.append("media --debug "
                             f"--cur_dir '/home/{username}/Pictures/curated' "
                             "--cur_db 'debug_db.csv' "
                             f"--unc_dir '/home/{username}/.smbshare/dsk1_raid5_0/hdd_copies/5VP6T7W5' "
                             "--unc_db 'debug_db.csv' "
                             "--mvunc_dir '../mv_media' "
                            )

        debug_cmdline.append("media "
                             f"--cur_dir '/home/{username}/Pictures/curated' "
                             "--cur_db 'debug_db.csv' "
                             f"--unc_dir '/home/{username}/Pictures/massive_gma_recovery' "
                             "--unc_db 'debug_db.csv' "
                             )

        debug_cmdline.append("media --debug "
                             f"--cur_dir '/home/{username}/test/001_2010_baseline (Copy)' "
                             "--cur_db 'debug_db.csv' "
                            )

        debug_cmdline.append("media --debug "
                             f"--cur_dir '/home/{username}/test/001_2010_baseline (Copy)' "
                             f"--unc_dir '/home/{username}/test/002_2012_baseline (Copy)' ")

        debug_cmdline.append("media "
                             f"--cur_dir '/home/{username}/Pictures/curated' "
                             f"--unc_dir '/home/{username}/Pictures/massive_gma_recovery' ")
                                    
    #hl_process_curated_dir("/home/{username}/test/find_similar", cur_use_db=False)
    #    
        args = parser.parse_args(shlex.split(debug_cmdline[2]))
    else :
        # get and validate command line arguments 
        args = parser.parse_args()

    #^^^^^^^^^^^^^^^^^^^^

    # configure logging
    if args.info :
        logger.setLevel(logging.INFO)
    if args.debug :
        logger.setLevel(logging.DEBUG)
        
    logger.debug(args)

    hl_process_curated_dir(cur_fqdn=args.cur_dir, cur_read_db_fqfn=args.cur_db, cur_regenerate_db=args.cur_regenerate_db,
                           unc_fqdn=args.unc_dir, unc_read_db_fqfn=args.unc_db, unc_regenerate_db=args.unc_regenerate_db,mvunc_nfqdn=args.mvunc_dir)

    logger.info("---------- image exts found, not in list ----------")
    logger.info(image_exts)

    logger.info("---------- video exts found ----------")
    logger.info(video_exts)

    #----------------------------------------

    """
    write_csv(sys.stdout, files, fileinfo_defaults)

    files2 = read_csv(csv_fqfn)

    write_csv(sys.stdout, files2, fileinfo_defaults)
    """
