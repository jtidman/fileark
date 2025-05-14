#!/usr/bin/python3
'''

@author: James Tidman

Copyright 2021 James Tidman
'''

import os
import sys
import subprocess
import time

import concurrent.futures
import contextlib

from datetime import datetime, timezone

#from pip._internal import self_outdated_check

#from datetime import datetime

#import mariadb
#import json
#import urllib.request
#import shutil
#import argparse
#import fnmatch
#import magic

import csv

import hashlib

# https://pypi.org/project/ExifRead/
#import exifread

# remove tags from MP3
#https://code.activestate.com/recipes/577139-remove-id3-tags-from-mp3-files/

# https://stackoverflow.com/questions/17388213/find-the-similarity-metric-between-two-strings

# before local module imports?
import logging
logger = logging.getLogger(__name__)

sequence_number = 100


########################################################################
#
#
#
@contextlib.contextmanager
def smart_open(filename: str, mode: str = 'r', *args, **kwargs):
    '''Open files and i/o streams transparently.'''
    if filename == '-':
        if 'r' in mode:
            stream = sys.stdin
        else:
            stream = sys.stdout
        if 'b' in mode:
            fh = stream.buffer  # type: IO
        else:
            fh = stream
        close = False
    else:
        fh = open(filename, mode, *args, **kwargs)
        close = True

    try:
        yield fh
    finally:
        if close:
            try:
                fh.close()
            except AttributeError:
                pass

            
########################################################################
#
#
#
def file_obj_calc_md5sum(file_obj) :
    
    try :
        hash_md5 = hashlib.md5()
        with open(file_obj.fqfname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return int(hash_md5.hexdigest(), 16)

    except FileNotFoundError :
        return None

########################################################################
#
#
#
def file_obj_calc_md5sum_os(file_obj) :
   
    try : 
        cp = subprocess.run(["md5sum", file_obj.fqfname], capture_output=True)
        return int(cp.stdout[:32].decode('utf-8'), 16)

    except FileNotFoundError :
        return None

########################################################################
#
#
#
def file_calc_md5sum(fname) :

    file_obj = ufile(fname)
    return file_obj_calc_md5sum(file_obj)

########################################################################
#
#
#
def file_calc_md5sum_os(fname) :

    file_obj = ufile(fname)
    return file_obj_calc_md5sum_os(file_obj)

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


    output_str = output_str.replace("$", "\\$")
        
    return output_str 


########################################################################
#
#
#
def build_list_of_all_extensions(src_path, exclude_ext_list=None, process_match=None) :

    ext_list = []

    for root, dirs, files in os.walk(src_path):

        if files != [] :
            for f in files :
                basename, ext = os.path.splitext(f)
                ext = ext.lower()
                if ext not in exclude_ext_list and ext not in ext_list :
                    ext_list.append(ext) 
            
    return ext_list

########################################################################
#
#
#
def find_all_extensions(startdir, knownext) :

    allfiles = {}
    allext = knownext

    if not os.path.isdir(startdir) :
        print("ERROR: startdir is not a directory >{}<".format(startdir))
        exit(-1)
    """    
    with os.scandir(startdir) as it:
        for entry in it:
            if not entry.name.startswith('.') and entry.is_file():
                print(entry.name)
    """
    
    for root, dirs, files in os.walk(startdir):
        #print(root, dirs, files)
        for d in dirs :
            if os.path.ismount(d) :
                print("removed dir {}".format(d))
                dirs.remove(d)
                
        #print(root, "consumes", end=" ")
        #file.append()
        #print(sum(os.path.getsize(os.path.join(root, name)) for name in files), end=" ")
        #print("bytes in", len(files), "non-directory files")
        #print("{} {} {}".format(root, dirs, files))
        if files != [] :
            #print("{} {}".format(root, files))
            allfiles[root] = files
            for f in files :
                basename, ext = os.path.splitext(f)
                ext = ext.lower()
                if ext not in allext :
                    print("{} {}".format(root, f))
                    allext.append(ext) 
            
    return allext

    
#=======================================================================
#
#
#
class udir() :
    
    def __init__(self, dir_path, ndirs, nfiles) :
        
        self.dir_path = dir_path
        self.nfiles = nfiles 
        self.ndirs = ndirs 
        
#=======================================================================
#
#
#
#class udir_list() :
#    
#    def __init__(self) :
#        
#        self.dir_path = dir_path
#        self.dirs = []
#        
#    def add(self, udir_obj):
#        self.dirs.append(udir_obj)
        
#=======================================================================
#
#
#
class ufile() :
    
    attr_names = ["file_path", "file_name", "size", "created", "modified", "md5sum", "filetype", "mimetype"] # + picture_utils.image_attr_names

    #-------------------------------------------------------------------
    def __init__(self, *args, **kwargs) :

        # TODO
        # hack to add image attributes to all ufile objects
        #if picture_utils.image_attr_names[0] not in ufile.attr_names :
        #    ufile.attr_names += picture_utils.image_attr_names

        if len(args) == 1 :
            self.set_vars_from_dict(*args)
        else :
            self.set_vars_from_params(*args, **kwargs)

        self.fqfname = os.path.join(self.file_path, self.file_name)

    #-------------------------------------------------------------------
    def set_vars_from_dict(self, attr_list) :

        for attr_name in attr_list :
            if attr_name not in self.attr_names :
                logger.warn("attr name not found")
            self.__dict__[attr_name] = attr_list[attr_name]
            
        if "md5sum" in attr_list :
            try :
                if type(self.md5sum) == str :
                    self.md5sum = int(self.md5sum, 16)
                else :
                    self.md5sum = self.md5sum
            except :
                self.md5sum = None
            
                 

    #-------------------------------------------------------------------
    def set_vars_from_params(self, file_path, file_name, size=None, created=None, modified=None, md5sum=None, filetype=None, mimetype=None) :

        self.file_path = file_path
        self.file_name = file_name
        
        self.size = size
        self.created = created
        self.modified = modified
       
        self.filetype = filetype
        self.mimetype = mimetype

        if type(md5sum) == str :
            self.md5sum = int(self.md5sum, 16)
        else :
            self.md5sum = md5sum
        
    #-------------------------------------------------------------------
    def __repr__id(self) :
        
        return str(id(self))

    #-------------------------------------------------------------------
    def __repr__(self) :
        
        #string = "{} -> {} : {} {} {} {} {} {:032x}\n".format(self.file_path, self.file_name, self.size, self.created, self.modified, self.filetype, self.mimetype, self.md5sum)
        #l = self.get_attrs()
        #s = ""
        #for i in l :
        #    s = s + str(l)
        return self.file_path + self.file_name

    #-------------------------------------------------------------------
    def __lt__(self, other) :

        return (self.fqfname < other.fqfname)
    
    #-------------------------------------------------------------------
    def get_attrs(self) :

        #if self.file_name == "P5070029.JPG" :
        #    print("!!!")

        l = []
        for attr_name in self.attr_names :
            
            #----------------------------------------
            # get value from self object
            if not hasattr(self, attr_name) :
                v = "None"
            else :
                v = self.__dict__[attr_name]
            
            #----------------------------------------
            # convert value to printable wstring
            if attr_name == "md5sum" :
                if type(self.md5sum) != int :
                    fv = "None"
                else :
                    fv = "{:032x}".format(self.md5sum)
            #elif attr_name == "ExifMake" :
            #    fv = "{}".format(v) 
            #    #if self.file_name == "P5070029.JPG" :
            #    #    l.append("ExifMake")
            #    #else :
            #    #    l.append("{}".format(v))   
            else :
                fv = "{}".format(v)
            
            #----------------------------------------
            # remove non-printable charatcters from the string
            # TODO a codec should be able to do this?
            if not fv.isprintable() :
                # common in exif to get 0x00 bytes in strings
                fv = v.strip('\x00')
                
                # check if more unprintable chars are in the string that we don't anticipate
                if not fv.isprintable() :
                    raise Exception("Bad string: {}".format(bytes(fv,"utf-8")))
                
            l.append(fv)

        return l

    #-------------------------------------------------------------------
    def is_equal_pf(self, other) :
        
        if self.file_path == None :
            raise Exception('None in compare()')
        if self.file_name == None :
            raise Exception('None in compare()')
        
        if other.file_path == None :
            raise Exception('None in compare()')
        if other.file_name == None :
            raise Exception('None in compare()')
        
        result = self.file_path == other.file_path
        result = result and self.file_name == other.file_name
        
        return result 
    
    #-------------------------------------------------------------------
    def is_equal_pfm(self, other) :

        if self.file_path == None :
            raise Exception('None in compare()')
        if self.file_name == None :
            raise Exception('None in compare()')
        if self.md5sum == None :
            raise Exception('None in compare()')
        
        if other.file_path == None :
            raise Exception('None in compare()')
        if other.file_name == None :
            raise Exception('None in compare()')
        if other.md5sum == None :
            raise Exception('None in compare()')
        
        result = self.file_path == other.file_path
        result = result and self.file_name == other.file_name
        result = result and self.md5sum == other.md5sum
        
        return result 
    
    #-------------------------------------------------------------------
    def is_equal_m(self, other) :

        if self.md5sum == None :
            raise Exception('None in compare()')
        
        if other.md5sum == None :
            raise Exception('None in compare()')
        
        result = self.md5sum == other.md5sum
        
        return result 
    

########################################################################
#
#
#
def chunk_fileobj_calc_md5sum(chunk) :

    start, stop, files = chunk
    
    md5sums = []

    for e in range(start, stop) :
        md5sums.append(file_obj_calc_md5sum(files[e]))
        
    return md5sums


########################################################################
#
#
#
def chunk_compare_md5sums(chunk) :

    start, stop, existing_files, new_files = chunk

    # keep list of file objects that have already been "removed" from this object (self). 
    #removed_files = []
    dups = []

    # remove duplicates from .self that are not in other.        
    for e in range(start, stop) :
        existing_file = existing_files[e]

        for new_file in new_files :

#            if same :
#                # skip files we have already found
#                if new_file.fqfname in removed_files :
#                    continue#
#
            if new_file.is_equal_pf(existing_file) :
                continue

            if new_file.is_equal_m(existing_file) :
                #if same :
                #    removed_files.append(existing_file.fqfname)
                dups.append((existing_file, new_file))

                
    return dups

########################################################################
#
#
#
def make_chunk_list(num, num_chunks=16, min_chunksize=50) :

    # create a list with the first and last index of each chunk
    # note they should overlap:  [(0,12), (12, 24)  etc. ]

    if (num / num_chunks) < min_chunksize :
        chunks = [(0, num)]
    else :
        chunksize = int(num / num_chunks)
        num_remainder = num % chunksize

        chunks = []

        c = 0
        for i in range(0, num_chunks - 1) :
            chunks.append((c, c+chunksize))
            c = c + chunksize

        #if num_remainder != 0 :
        chunks.append((c, num))

    if logger.getEffectiveLevel() >= logging.DEBUG :
        for i in range(0, len(chunks)) :
            logger.debug("chunk {} {}".format(i, chunks[i]))
        
    return chunks


########################################################################
#
#
#

#=======================================================================
#
#
#
class ufile_list() :
    
    #-------------------------------------------------------------------
    def __init__(self, base_path, cwd_path=None, load_from="file_system", fobject=ufile, dobject=udir, maxthreads=10) :

        # validate directory path
        if cwd_path == None :
            cwd_path = os.getcwd()
        else :        
            self.cwd_path = os.path.realpath(os.path.expanduser(cwd_path)) #, strict=True)
            
        self.base_path = os.path.realpath(os.path.expanduser(base_path)) #, strict=True)

        self.ufile = fobject
        self.files = []
        self.num_files = len(self.files)
        
        self.udir = dobject
        self.dirs = []
        self.num_dirs = len(self.dirs)

        # ensure the path is absolute
        if not os.path.isabs(self.base_path) :
            self.base_path = os.path.join(self.cwd_path, self.base_path)
    
        # validate we have an actual directory
        if not os.path.isdir(self.base_path) :
            logger.error("Directory does not exist: {}".format(self.base_path))
            raise 

        logger.debug("CWD: {}".format(cwd_path))
        logger.debug("src directory: {}".format(self.base_path))
        
        # 
        if load_from == "file_system" :
            
            # load files
            #self.build_list_of_all_files(self.base_path)
            self.build_list_of_all_files(self.base_path)
        
            # get created and modified times, file size
        elif load_from == "database" :
            # load files
            self.read_database()
        
    #-------------------------------------------------------------------
    def __repr__(self) :
        
        #string = "{} -> {} : {} {} {} {} {} {:032x}\n".format(self.file_path, self.file_name, self.size, self.created, self.modified, self.filetype, self.mimetype, self.md5sum)
        s = ""
        for f in self.files :
            s = s + f.__repr__() + "\n"
            
        return s
         
    
    #-------------------------------------------------------------------
    def add_file(self, ufile_obj):
        self.files.append(ufile_obj)
        
    #-------------------------------------------------------------------
    def add_dir(self, udir_obj):
        self.dirs.append(udir_obj)
        
    #-------------------------------------------------------------------
    def is_equal(self, other):

        # is this the same instance?
        if self is other :
            return True

        # are the number fo files the same?
        ls = len(self.files)
        lo = len(other.files)
        if ls != lo :
            return False
        
        # is the base path the same?
        if self.base_path != other.base_path :
            return False

        # are all of the fqfnames the same?
        # TODO optimize, worst case this is O(n^2)!
        count = 0
        for sfile_obj in self.files :
            found = False
            for ofile_obj in other.files :
                if sfile_obj.fqfname == ofile_obj.fqfname :
                    count = count + 1
                    found = True
                    break
            if found :
                continue
            else :
                return False
        
        if count == ls :
            return True
        
        return False 

    #-------------------------------------------------------------------
    def is_equal_p(self, other):

        result = self.base_path == other.base_path
        
        return result 
    #-------------------------------------------------------------------
    def is_equal_pl(self, other):

        result = self.base_path == other.base_path
        result = result and len(self.files) == len(other.files)
        
        return result 
        
    #-------------------------------------------------------------------
    def build_list_of_all_files(self, src_path, include_list=[], exclude_list=[], get_filetype=True) :

        logger.debug("--------------------")
        logger.debug("building file list with stats: {}".format(src_path))

    
        #file_list = []
        #dir_list = []
        
        for root, dirs, files in os.walk(src_path):
            #logger.debug("{} {} {}".format(root, dirs, files))
    
            dir_info = udir(root, len(dirs), len(files))
            self.add_dir(dir_info)
            #logger.debug("dir_info {}".format(dir_info))

            
            for entry in os.scandir(root):
                #logger.debug("{} {} {}".format(root, dirs, files))
        
                if entry.is_dir(follow_symlinks=False) :
                    continue
                else :
                    #size = entry.stat(follow_symlinks=False).st_size
                    #created = entry.stat(follow_symlinks=False).st_ctime
                    #modified = entry.stat(follow_symlinks=False).st_mtime
                    
                    #created = datetime.fromtimestamp(created, tz=timezone.utc).strftime("%Y:%m:%d %H:%M:%S")
                    #modified = datetime.fromtimestamp(modified, tz=timezone.utc).strftime("%Y:%m:%d %H:%M:%S")
                    
                    #file_info = ufile(root, entry.name, size, created, modified)
                    file_info = self.ufile(root, entry.name)
                    self.add_file(file_info)
                    #logger.debug("file_info {}".format(file_info))
    
        logger.debug("dirs found {}".format(len(self.dirs) - self.num_dirs))
        logger.debug("files found {}".format(len(self.files) - self.num_files))
        
        prev_num_items = (self.num_dirs) + (self.num_files)
        num_items = (len(self.dirs) - self.num_dirs) + (len(self.files) - self.num_files)
        
        logger.debug("total items found {}".format(num_items))
        logger.debug("total items added {}".format(num_items - prev_num_items))
        
    #-------------------------------------------------------------------
    def calc_all_md5sums_one_by_one(self, md5_method=file_obj_calc_md5sum) :
        
        with concurrent.futures.ProcessPoolExecutor(max_workers=48) as executor:
            for file_obj, md5sum in zip(self.files, executor.map(md5_method, self.files)) :
                file_obj.md5sum = md5sum

    #-------------------------------------------------------------------
    def print_md5sum_format_as_check_file(self, fname_write=None, base_path=None, absolute=True) :
        
        abs_str = ["relative", "absolute"]
        
        logger.debug("--------------------")
        logger.debug("writing md5sum file in {} mode: {}".format(abs_str[int(absolute)], fname_write))

        if base_path == None :
            base_path = self.base_path

        base_path = os.path.realpath(os.path.expanduser(base_path))            

        if fname_write != None :
            # validate
            pass
            
        # print output in md5sum file check format
        with smart_open(fname_write) as fh:
            for file_obj in self.files :
                if not absolute :
                    file_path = os.path.relpath(file_obj.fqfname, start=base_path)
                else :
                    file_path = file_obj.fqfname
    
                print("{:032x}  {}".format(file_obj.md5sum, file_path), file=fh)
            

    #-------------------------------------------------------------------
    #def find_duplicates_by_md5sum(self, other) :
    #    
    #    for this_obj in self.files :
    #        if this_obj.md5sum == None :
    #            print("no md5sum {}".format(this_obj.fqfname))
    #            continue
    #        for other_obj in other.files :
    #            if other_obj.md5sum == None :
    #                continue
    #            else :
    #                if this_obj.md5sum == other_obj.md5sum :
    #                    print("duplicate {}".format(this_obj.fqfname))

    #-------------------------------------------------------------------
    def compare_by_md5sum(self, other) :
        
        
        tc = 0
        oc = 0
        
        for this_obj in self.files :
            print("tc " + str(tc))
            tc += 1
            if this_obj.md5sum == None :
                print("no md5sum {}".format(this_obj.fqfname))
                continue
            for other_obj in other.files :
                print("oc"+str(oc))
                oc += 1
                if other_obj.md5sum == None :
                    continue
                else :
                    if this_obj.md5sum == other_obj.md5sum :
                        print("rm {}".format(properly_escape_filename(this_obj.fqfname)))
            print("next")
            oc = 0



    #-------------------------------------------------------------------
    def find_added(self, new_files) :
        """
        self (or the calling instance) is the existing list, or in other words the collection of music, or pictures, etc.
        
        copy new_files that do not match existing_files
       
        """

        existing_files = self

        logger.debug("--------------------")
        logger.debug("find files in new_files that are not in existing_files based on md5sum values")

        # remove duplicates from .self that are not in other.        
        for new_file in new_files.files :
            found = False
            for existing_file in existing_files.files :

                if new_file.is_equal_m(existing_file) :
                    found = True
                    break
                
            if not found :
                print("cp {} #".format(properly_escape_filename(new_file.fqfname)))


    '''
    #-------------------------------------------------------------------
    def find_removed(self, new_files) :
        existing_files = self

    #-------------------------------------------------------------------
    def find_renamed(self, new_files) :
        existing_files = self

    #-------------------------------------------------------------------
    def find_changed(self, new_files) :
        existing_files = self
    '''

    #-------------------------------------------------------------------
    def write_database(self, fname="jt_database.csv", maxcols=25, wrap=True) :
        """
        
           
        """
        
        if fname and fname != '-' :
            fname_write = os.path.join(self.base_path, fname)
        else :
            fname_write = "-"
        
        logger.debug("--------------------")
        logger.debug("writing database file: {}".format(fname_write))
    
        with smart_open(fname_write, mode='w', newline='', encoding = "UTF-8") as f:
            writer = csv.writer(f, delimiter = '\t', dialect='excel-tab', quoting=csv.QUOTE_MINIMAL)

            # write header row
            writer.writerows([ufile.attr_names])

            for file_obj in self.files :
                row = file_obj.get_attrs()
                writer.writerows([row])

        return
        
    #-------------------------------------------------------------------
    def read_database(self, fname="jt_database.csv"):
        """
        
           
        """

        fname_read = os.path.join(self.base_path, fname)

        logger.debug("--------------------")
        logger.debug("reading database file: {}".format(fname_read))
    
        # read in all rows from the file, splitting them into property_rows and net_rows
        with open(os.path.join(self.base_path, fname), newline='', encoding = "UTF-8") as csvfile:
            data = csv.reader(csvfile, delimiter = '\t', dialect='excel-tab')
            
            num_cols = 0
            num_rows = 0
            
            for row in data:
                if (num_rows == 0) :
                    # read headers
                    header_row = row
                    num_cols = len(row)
                    num_rows += 1
                    
                    continue
                    
                else :
                    
                    if len(row) != num_cols :
                        logger.error("column mismatch on read")
                    attrs = dict(zip(header_row, row))
                    self.files.append(ufile(attrs)) 
                    num_rows += 1
                
            

        return

    #-------------------------------------------------------------------
    def sort_by_file_path(self):
        """
        
           
        """
        self.files = sorted(self.files, key=lambda ufile_obj: ufile_obj.file_path)

    #-------------------------------------------------------------------
    def sort_by_fqfname(self):
        """
        
           
        """
        self.files = sorted(self.files, key=lambda ufile_obj: ufile_obj.fqfname)
        
    #-------------------------------------------------------------------
    def find_dups_v0(self, new_files) :
        """
        self (or the calling instance) is the existing list, or in other words the collection of music, or pictures, etc.
        
        remove new_files that match existing_files
       
        """
        
        existing_files = self
        
        logger.debug("--------------------")
        logger.debug("find duplicates based on md5sum values")

        # see if the current and previous lists are the same
        # can speed up the search, and also helps prevent removing a file twice if the lists are the same        
        same = False
        if self.is_equal_p(new_files) :
            if self.is_equal(new_files) :
                logger.debug("comparing same list")
                same = True
        
        # keep list of file objects that have already been "removed" from this object (self). 
        removed_files = []

        # remove duplicates from .self that are not in other.        
        for existing_file in existing_files.files :

            for new_file in new_files.files :

                if same :
                    # skip files we have already found (probably only happen if the file lists are identical)
                    if new_file.fqfname in removed_files :
                        continue
    
                    if new_file.is_equal_pf(existing_file) :
                        # probably only happen if file lists are identical)
                        continue

                if new_file.is_equal_m(existing_file) :
                    if same :
                        removed_files.append(existing_file.fqfname)
                    print("rm {} # \t {}".format(properly_escape_filename(new_file.fqfname), properly_escape_filename(existing_file.fqfname)))

           
    #-------------------------------------------------------------------
    def find_dups_v1(self, new_files) :
        """
        self (or the calling instance) is the existing list, or in other words the collection of music, or pictures, etc.
        
        remove new_files that match existing_files
       
        """
        
        existing_files = self
        
        logger.debug("--------------------")
        logger.debug("find duplicates based on md5sum values")

        # see if the current and previous lists are the same
        # can speed up the search, and also helps prevent removing a file twice if the lists are the same        
        same = False
        if self.is_equal_p(new_files) :
            if self.is_equal(new_files) :
                logger.debug("comparing same list")
                same = True
        
        # keep list of file objects that have already been "removed" from this object (self). 
        removed_files = []

        existing_md5sums = []
        existing_fobjs = []
        new_md5sums = []
        new_fobjs = []
        new_files_to_remove = []

        for file_obj in self.files :
            existing_md5sums.append(int(file_obj.md5sum, 16))
            existing_fobjs.append(file_obj)

        for file_obj in new_files.files :
            new_md5sums.append(int(file_obj.md5sum, 16))
            new_fobjs.append(file_obj)

        ts = time.perf_counter()

        for e in range(0, len(existing_md5sums)) :
            for n in range(0, len(new_md5sums)) :
                if existing_md5sums[e] == new_md5sums[n] :
                    if same and (e == n) :
                        continue
                    new_files_to_remove.append(n)
                    
                    
        logger.info("elapsed time {}".format(time.perf_counter() - ts))

    #-------------------------------------------------------------------
    def print_dups(self, dup_files, target_dir="/stuff/BigVM/pictures_remove_buffer/.") :
        """
       
        """
        dup_files.sort()
        #target_dir = ""
        
        for n, e in dup_files :
            print("mv {} {} #\tmv {} {}".format(properly_escape_filename(n.fqfname), target_dir, properly_escape_filename(e.fqfname), target_dir))

    #-------------------------------------------------------------------
    def find_dups(self, new_files) :
        """
        self (or the calling instance) is the existing list, or in other words the collection of music, or pictures, etc.
        
        remove new_files that match existing_files
       
        """
        
        existing_files = self
        
        logger.debug("--------------------")
        logger.debug("find duplicates based on md5sum values")

        # see if the current and previous lists are the same
        # can speed up the search, and also helps prevent removing a file twice if the lists are the same        
        #same = False
        #if self.is_equal_p(new_files) :
        #    if self.is_equal(new_files) :
        #        logger.debug("comparing same list")
        #        same = True
                
        
        # this in not-optimal if new >> existing
        # divide the list into chunks, calculate the chunksize and remainder
        num_e_files = len(existing_files.files)
        num_n_files = len(new_files.files)
        
        # corner case
        #if (num_n_files > num_e_files) :
        #    num_e_files, num_n_files = num_n_files, num_e_files
        #    swapped = True
            
        chunks = make_chunk_list(num_e_files, num_chunks=32)
        num_chunks = len(chunks)

        # add extra data for processing    
        for i in range(0, num_chunks) :
            chunks[i] = chunks[i] + (existing_files.files, new_files.files)

        ts = time.perf_counter()
            
        results = []
        with concurrent.futures.ProcessPoolExecutor(max_workers=num_chunks) as executor:
            for r in executor.map(chunk_compare_md5sums, chunks):
                results += r
            
        logger.info("elapsed time {}".format(time.perf_counter() - ts))

        # make sure we don't remove the same file from both directories
        # use the fqfname for the comparison
        # sort e by fqfname to get sane results in the dups list
        results = sorted(results, key=lambda fobjs: fobjs[0].fqfname)
        
        
        dup_fqfnames = []
        dup_file_objs = []
        
        for e, n in results :
            if (e.fqfname in dup_fqfnames) :
                continue
            dup_fqfnames.append(n.fqfname)
            dup_file_objs.append((n, e))

        #print(dups[0])

        return dup_file_objs


    #-------------------------------------------------------------------
    def calc_md5sums(self) :
        """
        self (or the calling instance) is the existing list, or in other words the collection of music, or pictures, etc.
        
        """
        
        logger.debug("--------------------")
        logger.debug("calculate md5sum values")

        num_files = len(self.files)
        
        # corner case
        #if (num_n_files > num_e_files) :
        #    num_e_files, num_n_files = num_n_files, num_e_files
        #    swapped = True
            
        chunks = make_chunk_list(num_files, num_chunks=32)
        num_chunks = len(chunks)

        # add extra data for processing    
        for i in range(0, num_chunks) :
            chunks[i] = chunks[i] + (self.files, )

        ts = time.perf_counter()
            
        results = []
        with concurrent.futures.ProcessPoolExecutor(max_workers=num_chunks) as executor:
            for r in executor.map(chunk_fileobj_calc_md5sum, chunks):
                results += r
            
        logger.info("elapsed time {}".format(time.perf_counter() - ts))

        delete_bad_md5 = []
        for i in range(0, num_files) :
            if results[i] == None :
                delete_bad_md5.append(self.files[i])
            else :
                self.files[i].md5sum = results[i]
                
        for f in delete_bad_md5 :
            self.files.remove(f)

        return

    #-------------------------------------------------------------------
    def read_filetypes(self) :
        """
        
        
        """
        
        logger.debug("--------------------")
        logger.debug("calculate md5sum values")

        num_files = len(self.files)
    
        #try :
        #    with open(entry.path, mode='rb') as mf:
        #        magic_buffer = mf.read(min(size, 2048))
        #        mimetype = magic.from_buffer(magic_buffer, mime=True) 
        #        filetype = magic.from_buffer(magic_buffer) 
        #except FileNotFoundError :
        #    # normally a broken link
        #    continue
        #except IsADirectoryError :
        #    # a link to a directory
        #    continue


