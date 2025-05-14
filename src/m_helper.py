#!/usr/bin/python3

import logging
logger = logging.getLogger(__name__)

import sys
import os
from multiprocessing import Process, Queue, Event
import queue
#import time
#import math
from datetime import datetime
import socket
import struct
import fcntl
import ipaddress
#import serial
from serial.tools.list_ports import comports

#=======================================================================

class instrumentException(Exception):
    pass


class FeatureNotAvailable(Exception):
    """Exception raised when a feature is not available

    Attributes:
        feature -- string describing the missing feature
    """

    def __init__(self, feature=""):
        self.feature = feature
        super().__init__(self.message)
        


#=======================================================================

ignore_serial_ports_by_desc = [
    "ttyS0",
    "JTAG+Serial",
    "Intel(R) Active Management Technology",
    ]

ignore_serial_ports_by_port = [
    "ttyS",
    ]

#-----------------------------------------------------------------------
def get_optimized_visa_list(resources_found) :

    #--------------------
    # build list of serial devices that are to be ignored 
    # if some devices report a desc string that allows us to rule them out
    # the discovery process can be made a lot faster
    # the actual resources are trimmed later in the code
    
    # this changed in ubuntu 24.04 LTS and Python 3.12 - description field in linux is no longer
    # populated except if the serial port is a USB device
    # to compensate, added a section to exclude by port 
    good_serial_ports = []
    for port, desc, device_info in sorted(comports()) :
        ignore = False
        if desc in ignore_serial_ports_by_desc :
            ignore = True
        elif any(s in port for s in ignore_serial_ports_by_port): 
            ignore = True            

        if not ignore :
            good_serial_ports.append("ASRL"+port)
            logger.info("potentially good serial port; info = {0}, {1}, {2}".format(port, desc, device_info))
        else :
            logger.info("rejected serial port; info = {0}, {1}, {2}".format(port, desc, device_info))

    logger.info("good serial ports")
    logger.info("-----------------")
    logger.info(good_serial_ports)
    
    #--------------------
    #rm = pyvisa.ResourceManager()
    #resources_found = rm.list_resources()
    num_devices = len(resources_found)

    logger.info("{} visa devices found.".format(num_devices))
        
    if logger.getEffectiveLevel() == logging.INFO :
        logger.info("\nresources found list:")
        for i in resources_found :
            logger.info(i)
    
    #--------------------
    # put USB resources first in the list
    resources = []
    for i in resources_found :
        if i[:3] == "USB" :
            resources.append(i)
    for i in resources_found :
        if i[:3] != "USB" :
            resources.append(i)
    
    # remove known bad serial ports
    b = resources[:]
    for i in b :
        if (i[:4] == "ASRL") :
            for gsp in good_serial_ports :
                if gsp in i :
                    #print("gsp")
                    break
            else :
                #print("skip")
                resources.remove(i)
                continue
    
    #--------------------
    if logger.getEffectiveLevel() == logging.INFO :
        logger.info("\nfiltered, ordered list:")
        for i in resources :
            logger.info(i)

    return resources

#=======================================================================
def config_2_attrib(self, defaults, configs):
    """
    Create/update default object attributes from a dictionary.  If a key from the
    default dict is in the updated dict, then use the value from the updated
    dict to create the attribute.

    """
    
    for key, value in {**defaults, **configs}.items() :
        self.__setattr__(key, value)

#=======================================================================
def init_object_attributes(self, default_attribs, updated_attribs):
    """
    Create/update default object attributes from a dictionary.  If a key from the
    default dict is in the updated dict, then use the value from the updated
    dict to create the attribute.

    """
    
    for key in default_attribs :
        if key not in updated_attribs :
            self.__setattr__(key, default_attribs[key])
            continue
         
        self.__setattr__(key, updated_attribs[key])
        continue

#=======================================================================
def coerce_value(value, expected_type):
    """
    Attempts to convert value to expected_type.
    Returns the converted value if possible, otherwise the original value.
    """
    if value is None:
        return None

    # Normalize to list
    #if not isinstance(expected_type, list) and len(expected_type) != 0:
    if not isinstance(expected_type, list):
        expected_type = [expected_type]
    else :
        pass

    #----------------------------------------
    # check if the type of value matches expected_type
    if type(value) in expected_type:

        # empty strings should be None
        #if isinstance(value, str) and len(value) == 0:
        if isinstance(value, str) and value.strip() == "":
            return None
        
        return value

    #----------------------------------------
    # Try to coerce
    """
    try:
        if expected_type == int:
            return int(value)
        if expected_type == float:
            return float(value)
        if expected_type == str:
            
            return str(value)
        if expected_type == datetime:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f")

    except (ValueError, TypeError) as e:
        raise ValueError(f"Failed to convert value '{value}' to {expected_type.__name__}: {e}")
    raise ValueError(f"Conversion to {expected_type.__name__} is not implemented")
    """
    for t in expected_type:
        try:
            if t is bool:
                return bool(value)
            elif t is int:
                return int(value)
            elif t is float:
                return float(value)
            elif t is str:
                return str(value)
            elif t is datetime:
                if isinstance(value, (int, float)):
                    return datetime.fromtimestamp(value)
                elif isinstance(value, str):
                    try:
                        return datetime.fromisoformat(value)
                    except ValueError:
                        pass
                    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y:%m:%d %H:%M:%S%z", "%Y-%m-%d %H:%M:%S%z"):
                        try:
                            return datetime.strptime(value, fmt)
                        except ValueError:
                            continue
        except (ValueError, TypeError):
            continue
    
    raise ValueError(f"Failed to convert value '{value}' to any of {[t.__name__ for t in expected_type]}")


#=======================================================================
#
def init_object_attributes_enh(self, default_attribs, updated_attribs):
    """
    Create/update default object attributes from a dictionary.  If a key from the
    default dict is in the updated dict, then use the value from the updated
    dict to create the attribute.

    Converts values based on the tuple in default_attribs

    """
    for key in default_attribs :
        if key not in updated_attribs :
            self.__setattr__(key, default_attribs[key][0])
            continue
         
        self.__setattr__(key, updated_attribs[key])
        continue

"""    
    for key in default_attribs :
        if key not in updated_attribs :
            self.__setattr__(key, coerce_value(default_attribs[key][0], default_attribs[key][1]))
            continue
        # 
        self.__setattr__(key, coerce_value(updated_attribs[key], default_attribs[key][1]))
        continue
"""

#=======================================================================
def cmd_change(cmd_list, name, new_value) :
    """
    """
    
    for l in cmd_list :
        if l[0] == name :
            cmd_list[cmd_list.index((l))] = (name, new_value)
            break

#=======================================================================
#=======================================================================
#
#                  8888888 888b    888 8888888888 88888888888 
#                    888   8888b   888 888            888     
#                    888   88888b  888 888            888     
#                    888   888Y88b 888 8888888        888     
#                    888   888 Y88b888 888            888     
#                    888   888  Y88888 888            888     
#                    888   888   Y8888 888            888     
#                  8888888 888    Y888 8888888888     888     
#
#=======================================================================
#=======================================================================



#=======================================================================
def get_local_interfaces(skip_ifaces=[], skip_ips=[]) :

    ip_dict = {}

    if sys.platform == 'win32' :
        pass
    else :        
        SIOCGIFADDR = 0x8915
        
        ifnames = socket.if_nameindex()
        logger.debug("ifnames={}".format(ifnames))
        
        for ix in ifnames :
            name = ix[1]
            logger.debug("ix names={}".format(name))
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            ips = struct.pack('256s', name[:15].encode("UTF-8"))
            try :
                ipa = fcntl.ioctl(s.fileno(), SIOCGIFADDR, ips)
            except Exception as ex :
                logger.debug(ex)
                continue
                
            #ip = socket.inet_ntoa(ipa[20:24])
            #logger.debug("ip={}".format(ip))
    
            ip = ipaddress.ip_address(ipa[20:24])
            logger.debug("ip={}".format(ip))
    
            if (ip.is_loopback) or (name in skip_ifaces) or (str(ip) in skip_ips) :
                continue
    
            logger.debug("ifname={} ip={}".format(name, ip))
            ip_dict[name] = ip
        
        '''
            print(ipa.is_private)
            print(ipa.is_multicast)
            print(ipa.is_private)
            print(ipa.is_unspecified)
            print(ipa.is_reserved)
            print(ipa.is_loopback)
            print(ipa.is_link_local)
        '''
        
    return ip_dict

#=======================================================================
def get_ip_address(ifname):
    
    ret = None

    if sys.platform == 'win32' :
        pass
    else :      
        ifname = bytes(ifname, 'ascii')
        
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # SIOCGIFADDR = 0x8915
        f = fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))
        
        ret = socket.inet_ntoa(f[20:24])
        
    return ret

#=======================================================================
#=======================================================================
#
#        888      .d88888b.   .d8888b.   .d8888b.  8888888b.  
#        888     d88P" "Y88b d88P  Y88b d88P  Y88b 888   Y88b 
#        888     888     888 888    888 888    888 888    888 
#        888     888     888 888        888        888   d88P 
#        888     888     888 888  88888 888  88888 8888888P"  
#        888     888     888 888    888 888    888 888 T88b   
#        888     Y88b. .d88P Y88b  d88P Y88b  d88P 888  T88b  
#        88888888 "Y88888P"   "Y8888P88  "Y8888P88 888   T88b 
# 
#=======================================================================
#=======================================================================


class create_bg_logger():
    
    def __init__(self, fname_prefix) :

        self.now = datetime.now()
        
        # set up output log file
        self.fname_log = "{}_{}_{}.csv".format(fname_prefix, self.now.strftime("%Y-%m-%d"), self.now.strftime("%H-%M-%S"))
    
        if os.path.isfile(self.fname_log) :
            raise "Invalid name or file already exists. Try again."
        self.log_stream = open(self.fname_log,"w")

        #ctx = get_context('forkserver')
        #q = ctx.Queue()
        #p = ctx.Process(target=foo, args=(q,))

        self.stop_event = Event()
        self.pause_event = Event()
        
        self.q = Queue()
        self.q_command_control = Queue()
        self.q_command_response = Queue()    

        self.p = Process(target=bg_logger_process, args=(self.log_stream, self.stop_event, self.q))
        self.p.start()

        pass
        
    def get_queue(self) :
        return self.q

    def close(self) :
        self.stop_event.set()
        self.p.join(2)
        self.p.close()

#=======================================================================
def bg_logger_process(log_stream, stop_event, q):

    logcnt = 0
    #start_time = time.time()
    try:
        while not stop_event.is_set():

            try :
                data = q.get_nowait()
            except queue.Empty :
                pass
            else :
                log_stream.writelines(data)
                log_stream.flush()
                logcnt=logcnt+1
                
        log_stream.close()
        
    except KeyboardInterrupt:
        pass


