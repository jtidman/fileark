#!/usr/bin/env python3
'''
Created on May 11, 2025

@author: James Tidman


# pip install NA
sudo apt install libheif-examples exiftool



'''

import os
import random
from datetime import datetime, timedelta
from collections import defaultdict
from itertools import product
from functools import wraps
from m_helper import *
import time
import csv

import sys
import hashlib
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
import argparse



####################################################################################
####################################################################################
##########                                                                ##########
##########                                                                ##########
##########   8888888888 d8b 888         8888888           .d888           ##########
##########   888        Y8P 888           888            d88P"            ##########
##########   888            888           888            888              ##########
##########   8888888    888 888  .d88b.   888   88888b.  888888 .d88b.    ##########
##########   888        888 888 d8P  Y8b  888   888 "88b 888   d88""88b   ##########
##########   888        888 888 88888888  888   888  888 888   888  888   ##########
##########   888        888 888 Y8b.      888   888  888 888   Y88..88P   ########## 
##########   888        888 888  "Y8888 8888888 888  888 888    "Y88P"    ##########
##########                                                                ##########
##########                                                                ##########
####################################################################################
####################################################################################


db_check = {
    "rel_path": None,
    "filename": None,
    "ext": None,

    #"st_mtime": None,

    "filesize": None,

    #"file_description": None,
    #"mimetype": None,
    #"file_charset": None,
}

#======================================================================
#
"""
The order of this dict is preserved.

Empty strings are represented as None for consistency.

"""
fileinfo_defaults = {
    "fileinfo_updated": (None, datetime),

    "full_path": (None, str),
    "base_path": (None, str),
    "rel_path": (None, str),
    "filename": (None, str),
    "ext": (None, str),

    "st_mode": (None, int),
    "st_ino": (None, int),
    "st_dev": (None, int),
    "st_nlink": (None, int),
    "st_uid": (None, int),
    "st_gid": (None, int),
    "st_atime": (None, datetime),
    "st_mtime": (None, datetime),
    "st_ctime": (None, datetime),

    "filesize": (None, int),

    "md5sum": (None, str),
#    "md5sum_kept": (None, globals().get("FileInfo")),
    "md5sum_kept": (None, str),

    "file_description": (None, str),
    "file_charset": (None, str),

    "exif_create_time": (None, datetime), 
    "exif_create_time_str": (None, str), 
    "exif_time_field": (None, str),
    "exif_imagewidth": (None, float),
    "exif_imageheight": (None, float),
    "exif_units": (None, str),
    "exif_imagesource": (None, str),

    "exif_all": (None, dict),

    "mimetype": (None, str),       # hold mimetype from exiftool or file

    "filename_new": (None, str),
    "ext_new": (None, str),
    "ftime_mismatch": (False, bool),

    "find_reason": (None, str),

    # image comparison
    "phash": (None, str),
    "dhash": (None, str),
    "ahash": (None, str),
    "orb_features": (None, str),

}

#======================================================================
#
class FileInfo():

    def __init__(self, config={}) :

        # set up logging        
        #logger.debug("class init")

        # combine dictionaries and create object attributes from them
        init_object_attributes_enh(self, fileinfo_defaults, config)

    def addinfo(self, info_dict):
        for k, v in info_dict.items():
            setattr(self, k, v)
            #setattr(self, k, coerce_value(v, fileinfo_defaults[k][1]))

    def __setattr__(self, name, value):

#        if name == "ext" :
#            if value==None or len(value) ==0:
#                pass

        # Look up the expected type from fileinfo_defaults
        expected_info = fileinfo_defaults.get(name)
        if expected_info:
            _, expected_type = expected_info
            if expected_type:
                value = coerce_value(value, expected_type)

        # Finally set the attribute
        super().__setattr__(name, value)

    def __repr__(self) :
        #full_path = os.path.join(self.base_path, self.rel_path, self.filename + ('.' + self.ext if self.ext else ''))
        #full_path = os.path.abspath(full_path)
        return "FileInfo: "+self.full_path

####################################################################################
####################################################################################
##########                                                                ##########
##########                                                                ##########
##########   8888888888 d8b 888         8888888           .d888           ##########
##########   888        Y8P 888           888            d88P"            ##########
##########   888            888           888            888              ##########
##########   8888888    888 888  .d88b.   888   88888b.  888888 .d88b.    ##########
##########   888        888 888 d8P  Y8b  888   888 "88b 888   d88""88b   ##########
##########   888        888 888 88888888  888   888  888 888   888  888   ##########
##########   888        888 888 Y8b.      888   888  888 888   Y88..88P   ########## 
##########   888        888 888  "Y8888 8888888 888  888 888    "Y88P"    ##########
##########                                                                ##########
##########                                                                ##########
####################################################################################
####################################################################################


#======================================================================
#
def get_file_list(base_path):
    """
    Fills out the basic file information, omitting files located in the base directory.
    """
    base_path = os.path.abspath(base_path)
    
    filelist = []

    for root, _, files in os.walk(base_path):
        rel_path = os.path.relpath(root, base_path)
        if rel_path in ("", ".", None):
            continue  # skip base directory files

        for name in files:
            file = {
                "fileinfo_updated": datetime.now(),
                "full_path": os.path.join(root, name),
                "base_path": base_path,
                "rel_path": rel_path,
                "filename": os.path.splitext(name)[0],
                "ext": os.path.splitext(name)[1].lstrip('.'),
            }
            filelist.append(FileInfo(file))

    return filelist

#======================================================================
#
def split_list(lst, num_sublists):
    """
    Splits a list into num_sublists approximately equal parts.
    """
    k, m = divmod(len(lst), num_sublists)
    return [lst[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(num_sublists)]

#======================================================================
#
def mp_exec(files, max_workers, func):
    """
    Splits files into max_workers chunks and processes them in parallel using func(chunk).
    """
    chunks = split_list(files, max_workers)

    with multiprocessing.Pool(processes=max_workers) as pool:
        results = pool.map(func, chunks)

    # Flatten results if each func(chunk) returns a list
    flattened = []
    for r in results:
        if r:
            flattened.extend(r)

    return flattened

#======================================================================
#
def mp_run_pipeline(files, pipeline):

    for pl, mp in pipeline :
        if mp:
            files = mp_exec(files, 10, pl)
        else:
            files = pl(files)

    return files


                                                  
####################################################################################
####################################################################################
##########                                                                ##########
##########                                                                ##########
##########   8888888888 d8b 888          8888888b.  888888b.              ##########
##########   888        Y8P 888          888  "Y88b 888  "88b             ##########
##########   888            888          888    888 888  .88P             ##########
##########   8888888    888 888  .d88b.  888    888 8888888K.             ##########
##########   888        888 888 d8P  Y8b 888    888 888  "Y88b            ##########
##########   888        888 888 88888888 888    888 888    888            ##########
##########   888        888 888 Y8b.     888  .d88P 888   d88P            ##########
##########   888        888 888  "Y8888  8888888P"  8888888P"             ##########
##########                                                                ##########
##########                                                                ##########
####################################################################################
####################################################################################
                                                  
                                                  
#======================================================================
#
class FileDB():

    def __init__(self, config={}) :

        # set up logging        
        #logger.debug("class init")

        # combine dictionaries and create object attributes from them
        #init_object_attributes_enh(self, fileinfo_defaults, config)

        self.files = []

    #------------------------------------------------------------
    #
    def addinfo(self, info_dict):
        for k, v in info_dict.items():
            setattr(self, k, v)
            #setattr(self, k, coerce_value(v, fileinfo_defaults[k][1]))

    #------------------------------------------------------------
    #
    def __setattr__(self, name, value):

#        if name == "ext" :
#            if value==None or len(value) ==0:
#                pass

        # Look up the expected type from fileinfo_defaults
        expected_info = fileinfo_defaults.get(name)
        if expected_info:
            _, expected_type = expected_info
            if expected_type:
                value = coerce_value(value, expected_type)

        # Finally set the attribute
        super().__setattr__(name, value)

    #------------------------------------------------------------
    #
    def __repr__(self) :
        #full_path = os.path.join(self.base_path, self.rel_path, self.filename + ('.' + self.ext if self.ext else ''))
        #full_path = os.path.abspath(full_path)
        return "FileInfo: "+self.full_path


    #------------------------------------------------------------
    #
    def create_from_dir(self, fqdn, pipeline):

        self.fqdn = fqdn

        if not os.path.exists(self.fqdn):
            raise FileNotFoundError(f"directory not found {self.fqdn}")

        self.files = get_file_list(self.fqdn)
        if len(self.files) == 0 :
            raise FileNotFoundError(f"no files found in {self.fqdn}")
                
        logger.info(f"Files found: {len(self.files)}")
        
        self.files = mp_run_pipeline(self.files, pipeline)

        return self.files

    #------------------------------------------------------------
    #
    def create_from_db(self, fqfn):

        if os.path.exists(fqfn):
            self.files = read_csv(fqfn)
            if self.files == [] :
                self.files = None
        else:
            self.files = None
            
        return self.files

#======================================================================
#
def cmpfiles(cur_files, dbg_files, fields_to_match):
    """
    Compare two lists of FileInfo objects based on specified fields.
    Returns:
      - files_not_in_cur: files in dbg_files not found in cur_files
      - files_not_in_dbg: files in cur_files not found in dbg_files
      - files_dont_match: files that exist in both but fields differ
    """
    fields = list(fields_to_match.keys())

    # Build index maps by a unique key: you can use filename+rel_path for now
    def build_key(f):
        #if f.ext==None or len(f.ext)==0:
        #    pass
        return (f.rel_path, f.filename, f.ext)

    # exclude files in basefiles
    #cur_map = {build_key(f): f for f in cur_files if f.rel_path not in (None, '', '.')}
    #dbg_map = {build_key(f): f for f in dbg_files if f.rel_path not in (None, '', '.')}
    cur_map = {build_key(f): f for f in cur_files}
    dbg_map = {build_key(f): f for f in dbg_files}

    files_not_in_cur = []
    files_not_in_dbg = []
    files_dont_match = []

    # Compare dbg_files to cur_files
    for key, dbg_f in dbg_map.items():
        cur_f = cur_map.get(key)
        if not cur_f:
            files_not_in_cur.append(dbg_f)
        else:
            mismatch = False
            for field in fields:
                val_cur = getattr(cur_f, field, None)
                val_dbg = getattr(dbg_f, field, None)
                if val_cur != val_dbg:
                    mismatch = True
                    break
            if mismatch:
                files_dont_match.append(dbg_f)

    # Compare cur_files to dbg_files
    for key, cur_f in cur_map.items():
        if key not in dbg_map:
            files_not_in_dbg.append(cur_f)

    return files_not_in_cur, files_not_in_dbg, files_dont_match

#======================================================================
#
def compare_db(db_files, files, attribs_to_check=db_check):

    # compare the real filelist to the saved one (only path/filename and os.stats are loaded at this point)
    files_not_in_dir, files_not_in_db, files_dont_match = cmpfiles(files, db_files, attribs_to_check)

    return files_not_in_dir, files_not_in_db, files_dont_match


#======================================================================
#
def run_spot_check(db_files, percent=10, skip_recent=True, recent_hours=24, select_by="oldest", pipeline=[], 
                   fields_to_check=["full_path", "md5sum", "filesize", "mimetype", "exif_create_time_str"]):
    """
    Runs a spot check on N% of database files, skipping recently updated ones.

    - Updates missing 'fileinfo_updated' fields with current timestamp (and skips them from checking)
    - Selects files either randomly or by walking down sorted oldest -> newest
    - Reprocesses selected files via pipeline
    - Compares values from `fields_to_check`
    - Updates `fileinfo_updated` on all selected files

    Parameters:
        db_files         : List of FileInfo objects
        percent          : Percentage of eligible files to test
        skip_recent      : If True, skip files updated in last `recent_hours`
        recent_hours     : Time window for "recent" updates
        select_by        : "random" or "oldest"
        pipeline         : List of functions for processing the files
        fields_to_check  : Dict[str, type] or List[str] of fields to compare

    Returns:
        {
            "selected": [FileInfo],
            "updated_timestamps": [FileInfo],
            "mismatches": [FileInfo],
        } or None
    """
    if fields_to_check is None:
        fields_to_check = db_check

    field_list = list(fields_to_check.keys()) if isinstance(fields_to_check, dict) else fields_to_check
    now = datetime.now()
    cutoff = now - timedelta(hours=recent_hours)

    eligible = []
    updated_timestamps = []

    for f in db_files:
        ts = getattr(f, "fileinfo_updated", None)
        if ts is None:
            f.addinfo({"fileinfo_updated": now})
            updated_timestamps.append(f)
            continue
        if skip_recent and ts >= cutoff:
            continue
        eligible.append(f)

    if not eligible:
        return None

    n_select = max(1, int(len(eligible) * percent / 100))  
    logging.info(f"Selected {n_select} files for spotcheck")

    if select_by == "oldest":
        eligible.sort(key=lambda f: getattr(f, "fileinfo_updated"))
        selected = []
        for f in eligible:
            if len(selected) >= n_select:
                break
            if random.random() < (n_select / len(eligible)):
                selected.append(f)
        while len(selected) < n_select:
            candidate = random.choice(eligible)
            if candidate not in selected:
                selected.append(candidate)
    else:
        selected = random.sample(eligible, n_select)

    # Update fileinfo_updated for all selected files
    for f in selected:
        f.addinfo({"fileinfo_updated": now})

    # Deepcopy before processing
    import copy
    copied_files = [copy.deepcopy(f) for f in selected]
    processed = mp_run_pipeline(copied_files, pipeline)

    mismatches = []
    selected_map = {(f.rel_path, f.filename, f.ext): f for f in selected}
    for f_new in processed:
        key = (f_new.rel_path, f_new.filename, f_new.ext)
        f_old = selected_map.get(key)
        if not f_old:
            continue
        for field in field_list:
            val_old = getattr(f_old, field, None)
            val_new = getattr(f_new, field, None)
            if val_old != val_new:
                mismatches.append(f_old)
                logger.info(f"Mismatch in {field}:")
                logger.info(f"  File: {f_old.full_path}")
                logger.info(f"  DB Value   : {val_old}")
                logger.info(f"  Recomputed: {val_new}")
                break

    # If no mismatches, overwrite matching entries in db_files
    if not mismatches:
        db_index = {(f.rel_path, f.filename, f.ext): i for i, f in enumerate(db_files)}
        for f in processed:
            key = (f.rel_path, f.filename, f.ext)
            idx = db_index.get(key)
            if idx is not None:
                db_files[idx] = f

    return {
        "selected": selected,
        "updated_timestamps": updated_timestamps,
        "mismatches": mismatches,
    }

#======================================================================
#

# tempting to use mimetype, but it can come from multiple sources
EXIF_CHECK_FIELDS = ["exif_create_time", "exif_imagewidth", "exif_imageheight", "exif_imagesource"]

def exif_data_in_db(db_files, exif_fields=EXIF_CHECK_FIELDS, threshold=0.1):
    """
    Checks if the specified EXIF-related fields appear to be populated for most files.

    Parameters:
        db_files      : list of FileInfo objects
        exif_fields   : list of attribute names to verify (default: common EXIF fields)
        threshold     : minimum fraction of files that must have most fields populated

    Returns:
        bool          : True if most files are EXIF-loaded, False otherwise
    """
    if not db_files:
        return False

    total = len(db_files)
    pass_count = 0

    for f in db_files:
        filled = 0
        for field in exif_fields:
            val = getattr(f, field, None)
            if val is not None and val != "":
                filled += 1
        #if filled >= len(exif_fields) * 0.6:  # e.g., at least 3 of 5 fields are present
        if filled >= 1 :  #at least 1 field is present
            pass_count += 1

    return (pass_count / total) >= threshold



#======================================================================
#
def remove_files_db(files_a, files_b):
    """
    Removes files_b from files_a using identity (object reference).
    Returns a new list with files_b removed.
    """
    if files_a == None or (isinstance(files_a, list) and len(files_a) == 0):
        return files_a
    
    if files_b == None or (isinstance(files_b, list) and len(files_b) == 0):
        return files_a

    b_ids = set(id(f) for f in files_b)
    return [f for f in files_a if id(f) not in b_ids]

#======================================================================
#
def add_missing_files_db(baseline_files, hasmissing_files, pipeline=[]):
    """
    Processes and adds missing files (present in the directory but not in the DB)
    into the baseline_files list.

    Calls media processing pipeline on the missing files before merging.
    """
    if not hasmissing_files:
        return baseline_files

    # Process the missing files using your full pipeline
    #missing = process_with_media_pipeline(hasmissing_files)
    missing = mp_run_pipeline(hasmissing_files, pipeline)

    #logger.debug(missing)

    return baseline_files + missing

#======================================================================
#
def remove_extra_files_db(baseline_files, hasextra_files, pipeline=[]):
    """
    Removes FileInfo objects from baseline_files that are not found in the current directory scan.
    """
    if not hasextra_files:
        return baseline_files
    
    extras = set(id(f) for f in hasextra_files)

    #logger.info(extras)

    return [f for f in baseline_files if id(f) not in extras]

#======================================================================
#
def update_files_db(baseline_files, hasnewer_files, pipeline=[]):
    """
    Processes and replaces outdated files in baseline_files with updated versions
    from hasnewer_files (i.e., same path/filename/ext but different metadata).

    Calls media processing pipeline on the newer files before merging.
    """
    if not hasnewer_files:
        return baseline_files

    # Process the modified files
    newer = mp_run_pipeline(hasnewer_files, pipeline)

    # Index baseline files by (rel_path, filename, ext)
    def key(f):
        return (f.rel_path, f.filename, f.ext)

    replace_keys = {key(f) for f in hasnewer_files}
    baseline_filtered = [f for f in baseline_files if key(f) not in replace_keys]

    #logger.debug(newer)

    return baseline_filtered + newer


####################################################################################
####################################################################################
####################################################################################
####################################################################################
####################################################################################
####################################################################################
####################################################################################
####################################################################################
####################################################################################
####################################################################################


#======================================================================
#
def timestamp_suffix():
    now = datetime.now()
    date_part = now.strftime("%Y%m%d-%I%M%S")
    millis = f"{now.microsecond // 1000:03}"
    am_pm = now.strftime("%p").lower()
    return f"{date_part}{millis}{am_pm}"

#======================================================================
#
def write_csv(csv_fqfn, files, csv_cols, no_overwrite=True):

    fileobj = None
    close_file = False

    if csv_fqfn == sys.stdout:
        fileobj = sys.stdout
    else:
        if no_overwrite and os.path.exists(csv_fqfn):
            # Move the existing file out of the way
            base, ext = os.path.splitext(csv_fqfn)
            backup_name = base + "-" + timestamp_suffix() + ext
            logger.info(f"Existing file {csv_fqfn} found. Moving to {backup_name}")
            shutil.move(csv_fqfn, backup_name)

        fileobj = open(csv_fqfn, 'w', newline='', encoding='utf-8')
        close_file = True

    headers = list(csv_cols.keys())
    writer = csv.DictWriter(fileobj, fieldnames=headers)
    writer.writeheader()

    for f in files:
        row = {}
        for key in headers:
            value = getattr(f, key, "")
            if value is None:
                value = ""
            row[key] = value
        writer.writerow(row)

    if close_file:
        fileobj.close()

    return csv_fqfn if close_file else None

#======================================================================
#
def read_csv(csv_path, field_defaults=fileinfo_defaults):
    """
    Loads a CSV, applying types from field_defaults.
    field_defaults must be a dict: field_name -> (default_value, expected_type)
    """
    files = []
    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        for row in reader:
            parsed_row = {}

            for field, (default_val, expected_type) in field_defaults.items():
                raw_value = row.get(field, None)

                if raw_value is None or raw_value == '':
                    parsed_row[field] = None
                else:
                    try :
                        parsed_row[field] = coerce_value(raw_value, expected_type)
                    except Exception as e:
                        logger.warning(f"coerce_value failed: {raw_value} {expected_type} -> {e}")
                        raise e

            files.append(FileInfo(parsed_row))

    return files

####################################################################################
####################################################################################
##########                                                                ##########
##########                                                                ##########
##########   8888888888 d8b 888          8888888b.  888888b.              ##########
##########   888        Y8P 888          888  "Y88b 888  "88b             ##########
##########   888            888          888    888 888  .88P             ##########
##########   8888888    888 888  .d88b.  888    888 8888888K.             ##########
##########   888        888 888 d8P  Y8b 888    888 888  "Y88b            ##########
##########   888        888 888 88888888 888    888 888    888            ##########
##########   888        888 888 Y8b.     888  .d88P 888   d88P            ##########
##########   888        888 888  "Y8888  8888888P"  8888888P"             ##########
##########                                                                ##########
##########                                                                ##########
####################################################################################
####################################################################################
                                                  
