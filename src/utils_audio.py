#!/usr/bin/python3
'''
Created on Sep 27, 2020

@author: James Tidman
'''

import os
import sys
import subprocess
import time

#from datetime import datetime

#import mariadb
#import json
#import urllib.request
#import shutil
#import argparse
#import fnmatch
#import csv

import hashlib

# https://pypi.org/project/Pillow/
import PIL.Image
import PIL.ExifTags

# https://pypi.org/project/exif/
from exif import Image

# https://pypi.org/project/ExifRead/
#import exifread


import logging
logger = logging.getLogger(__name__)

import utils_file

"""

########################################################################
#
#
#

file_categories = {
    "uncategorized": 0,
    "file": 1,
    "dir": 2,
    "link2file": 3,
    "link2dir": 4,
    "link2badfile": 5,
    "link2baddir": 6,
    "mountpt": 7,
}

class file_categorize() :

#......................................................................
    def __init__(self, fully_qualified_path_name, debug=False) :

        self.fqpn = fully_qualified_path_name
        self.category = "uncategorized"
        
        self.debug = debug
        
        self.reinit()

#......................................................................
    def process_file(self) :
        
        # get the extension
        self.root, self.ext = os.path.splitext(self.fqpn)
        
        # get the base filename
        self.root, self.basename = os.path.split(self.root)
        
        # get the filesize
        self.size = os.path.getsize(self.fqpn)

        self.category = "file"
        
        if self.debug :
            print("location, file, {}, {}, {}, {}".format(self.root, self.basename, self.ext, self.size))
            
#......................................................................
    def process_dir(self) :
        
        # get the extension
        self.root, self.ext = os.path.splitext(self.fqpn)
        
        # get the base filename
        self.root, self.basename = os.path.split(self.root)
        
        # get the filesize
        self.size = os.path.getsize(self.fqpn)

        self.category = "dir"
        
        if self.debug :
            print("location, dir, {}, {}, {}, {}".format(self.root, self.basename, self.ext, self.size))
            
#......................................................................
    def process_link2file(self) :
        
        self.category = "link2file"

        if self.debug :
            print("location, link2file, {}, , ,".format(fname))

#......................................................................
    def process_link2dir(self) :
        
        self.category = "link2dir"

        if self.debug :
            print("location, link2dir, {}, , ,".format(fname))

#......................................................................
    def process_link2badfile(self) :
        
        self.category = "link2badfile"

        if self.debug :
            print("location, link2badfile, {}, , ,".format(fname))

#......................................................................
    def process_link2baddir(self) :
        
        self.category = "link2baddir"

        if self.debug :
            print("location, link2baddir, {}, , ,".format(fname))

#......................................................................
    def process_mountpt(self) :
        
        self.category = "mountpt"

        if self.debug :
            print("location, mountpt, {}, , ".format(fname))
        
#......................................................................
    def process_uncategorized(self) :
        
        self.category = "uncategorized"

        if self.debug :
            print("location, uncategorized, {}, , ".format(fname))
        


#......................................................................
    def __eq__(self, other):
        result = False

        return result
            

#......................................................................
    def __getitem__(self, item) :
        pass

#......................................................................
    def __repr__(self) :
        
        return self.fqpn + "\n"
        
#......................................................................
    def reinit(self) :

        # check if its a moun point
        if os.path.ismount(self.fqpn) :
            #print("mount")
            self.process_mountpt(self)
        else :
            # check if it's a link
            if os.path.islink(self.fqpn) :
                #print("link")
                if os.path.exists(self.fqpn) :
                    #print("exists")
                    if os.path.isfile(self.fqpn) :
                        self.process_link2file()
                    elif os.path.isdir(self.fqpn) :
                        self.process_link2dir()
                else :
                    #print("not exists")
                    if os.path.isdir(self.fqpn) :
                        self.process_link2baddir()
                    else :
                        self.process_link2badfile()
            else :
                if os.path.isfile(self.fqpn) :
                    self.process_file()
                elif os.path.isdir(self.fqpn) :
                    self.process_dir()


    #=======================================================================
    #
    # Get the proper credentials into the execution environment
    #
def get_credentials() :    
    
    logger.info(os.getenv("USER", default=None))
    logger.info(os.getenv("HOME", default=None))
    logger.info(os.getenv("HOSTNAME", default=None))
    logger.info(os.getenv("HOST", default=None))
    
    user = os.getenv("USER", default=None)
    user_path = os.getenv("HOME", default=None)
    
    machine_name = os.getenv("HOST", default=None)
    if machine_name == None :
        machine_name = os.getenv("HOSTNAME", default=None)
    if machine_name == None :
        machine_name = open("/etc/hostname", "r").read().strip()
    
    logger.info("user = {}".format(user))
    logger.info("user_path = {}".format(user_path))
    logger.info("machine_name = {}".format(machine_name))
    
    # get credentials based on username
    try :
        fp = open(os.path.join(user_path, ".ssh/s3.json"), "r")
        creds = json.load(fp)
    except Exception as e :
        raise(e)
    
#=======================================================================
#
# Test the dB connection.
# Note for remote dB access, the local port must be forwarded through an active ssh tunnel.
#
def test_db_connection() :    
    #----------------------------------------
    # Connect to MariaDB Platform
    try:
        conn = mariadb.connect(
            user=creds["picturedbaccess"]["dbusername"],
            password=creds["picturedbaccess"]["dbpassword"],
            #host="tidmanfamily.com",
            host="127.0.0.1",
            port=3306,
            database=creds["picturedbaccess"]["dbname"]
        )
    except mariadb.Error as e:
        print(f"Error connecting to MariaDB Platform: {e}")
        sys.exit(1)
    
    # Get Cursor
    cur = conn.cursor()
    
    # Get all pictures stored in database
    cur.execute("SELECT * FROM extensions")
    
    dbext = []
    for (ext, category) in cur :
        print("{} {}".format(ext, category))
        dbext.append(ext)
        

#=======================================================================
def find_all_files(startdir) :
    pass

"""

#=======================================================================
#=======================================================================
#=======================================================================
#=======================================================================
#=======================================================================



#=======================================================================
def get_picture_exif_v1(filename) :

    picture_info = {}

    #----------------------------------------
    img = None
    
    # TODO: check for broken links


    try :
        img = PIL.Image.open(filename)
    except FileNotFoundError :
        logger.warn("Unable to open image file - file not found {}.".format(filename))
        
    except PIL.UnidentifiedImageError :
        logger.warn("Unable to open image file - unidentified image type {}.".format(filename))
        picture_info = {
            "Width" : 0,
            "Height" : 0
            }
    else :
    #if img != None :
        try :
            exif = {
                PIL.ExifTags.TAGS[k]: v
                for k, v in img._getexif().items()
                if k in PIL.ExifTags.TAGS
            }
        except AttributeError :
            # broken link
            logger.warn("Unable to read EXIF from {}.".format(filename))
        except OSError :
            logger.warning("Unexpected error {}, file {}.".format(sys.exc_info()[0], filename))
        else :
            try :
               
                # format is "YYYY:MM:DD HH:MM:SS", assume UTC?
                # time.strptime(exif["DateTimeOriginal"], "%Y:%m:%d %H:%M:%S")
                picture_info["CreatedDate"] = exif["DateTimeOriginal"]
                picture_info["Width"] =  exif["ExifImageWidth"]
                picture_info["Height"] = exif["ExifImageHeight"]
        
            except KeyError :
                pass
            except :
                logger.warn("Unexpected error {}.".format(sys.exc_info()[0]))

        #----------------------------------------
        if "Width" not in picture_info :
            picture_info["Width"] =  img.width
        else :
            if picture_info["Width"] != img.width :
                logger.info("exif and image width not consistent {} exif {} img {}".format(filename, picture_info["Width"], img.width))
                picture_info["Width"] =  img.width
    
        #----------------------------------------
        if "Height" not in picture_info :
            picture_info["Height"] = img.height
        else :
            if picture_info["Height"] != img.height :
                logger.info("exif and image height not consistent {} exif {} img {}".format(filename, picture_info["Height"], img.height))
                picture_info["Height"] = img.height
    

    #----------------------------------------
    if "CreatedDate" not in picture_info :

        try :
            stat = os.stat(filename)
            try:
                picture_info["CreatedDate"] = time.strftime("%Y:%m:%d %H:%M:%S", time.gmtime(stat.st_birthtime))
            except AttributeError:
                picture_info["CreatedDate"] = time.strftime("%Y:%m:%d %H:%M:%S", time.gmtime(stat.st_mtime))
        except FileNotFoundError :
            # broken link
            logger.warn("Unable to open image file - file not found {}.".format(filename))
            picture_info["CreatedDate"] = "0000:00:00 00:00:00"
            

    #----------------------------------------

    return picture_info


#=======================================================================
def get_picture_exif_v3(filename) :

    return "date"

#=======================================================================
def get_picture_exif_v4(filename) :

    return "date"

#=======================================================================
def get_picture_info(filename):
    
    return get_picture_exif_v1(filename)
    

#=======================================================================
def get_file_md5sum_v1(filename) :
    
    try :
        md5_hash = hashlib.md5()
        with open(filename,"rb") as f:
            # Read and update hash in chunks of 4K
            for byte_block in iter(lambda: f.read(4096),b""):
                md5_hash.update(byte_block)
        
        md5sum = md5_hash.hexdigest()
        
    except :
        logger.warn("Unexpected error {}.".format(sys.exc_info()[0]))
        md5sum = "00000000000000000000000000000000"

    return md5sum
    

#=======================================================================
def get_file_md5sum(filename) :
    
    return get_file_md5sum_v1(filename)


#=======================================================================
picture_exts = [
    "jpg",
    "jpeg",
    "png"
    ]




#=======================================================================
#=======================================================================
#=======================================================================
#=======================================================================
#=======================================================================


# remove tags from MP3
#https://code.activestate.com/recipes/577139-remove-id3-tags-from-mp3-files/

# https://stackoverflow.com/questions/17388213/find-the-similarity-metric-between-two-strings

########################################################################
#
#
#
def md5_os(fname):

    cp = subprocess.run(["md5sum", fname], capture_output=True)
    
    return cp.stdout[:32].decode('utf-8')

########################################################################
#
#
#
def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

########################################################################
#
#
#
def calc_md5sum(file_list, md5_method=md5) :
    
    md5sum_list = []
    
    for path, file in file_list :
        try :
            fname = os.path.join(path, file)
            md5sum_list.append(md5_method(fname))
        except KeyboardInterrupt :
            raise KeyboardInterrupt
        except :
            md5sum_list.append("error---------------------------")
            logger.warn("Unexpected error {}.".format(sys.exc_info()[0]))
    
    return md5sum_list

########################################################################
#
#
#
def calc_md5sum_os(file_list):
    '''
    Using the OS call is much slower, obviously :-)
    '''

    return calc_md5sum(file_list, md5_method=md5_os)

########################################################################
#
#
#
def list_to_delimited_str(input_list, delimiter=",") :
    
    string = ""
    
    for s in input_list[:-1] :
        string += s + delimiter
    
    string += input_list[-1:][0]
    
    return string     


########################################################################
#
#
#
def properly_escape_filename(input_str) :
    
    if "'" in input_str :
        output_str = "\"" + input_str + "\""
    else :
        output_str = "'" + input_str + "'" 
        
    return output_str 



########################################################################
#
#
#
class ufile(utils_file.ufile) :

    utils_file.ufile.attr_names += ["isaudiofile", "audioencoding"]

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        
        self.isaudiofile = True
        self.audioencoding = 'MP3'

########################################################################
#
#
#
class udir(utils_file.udir) :
    pass


