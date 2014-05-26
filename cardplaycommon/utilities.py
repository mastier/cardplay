#!/usr/bin/env python

import re

# utils
def exceptioncatch(e):
    import traceback, os.path
    top = traceback.extract_stack()[-1]
    print ", ".join([type(e).__name__, os.path.basename(top[0]), str(top[1])])

def response_print(responsedata,sw1,sw2):
    response = ' '.join( map(lambda x: '%02X' % x  , responsedata) )+("| (0:02X} {1:02X}".format(sw1, sw2))
    print response

def hex2bin(data):
    """ hex2bin converion, takes either string or list as argument
        return list of 4 bits
    """
    data = re.findall(r'[0-9a-fA-F]',''.join(data))
    return map(lambda x: '{0:04b}'.format(int(x,16))  , data )

def bytes2bin(data):
    """ hex2bin converion, takes bytes list as argument
        return list of 4 bits
    """
    return map(lambda x: '{0:04b}'.format(x)  , data )
    
def bin2hex(data):
    """ bin2hex converion, takes either string or list as argument
        return list of upper case hex characters
    """
    data = re.findall(r'[0-1]{4}',''.join(data))
    return map(lambda x: '{0:X}'.format(int(x,2))  , data )


def hex2bytes(data):
    data      = ''.join(data) 
    data      = re.findall(r'[0-9a-fA-F]{2}|[0-9a-fA-F]{1}',data)
    databytes = map(lambda x: int(x,16)  , data )
    return databytes

def asciidata_tobytes(data):
    data      = re.findall(r'.',data)
    databytes = map(lambda x: ord(x) & 0xFF  , data )
    return databytes

def bytes2ascii(inbytes):
    asciidata = map(lambda x: chr(x)  , inbytes )
    asciidata = ''.join(asciidata)
    return asciidata

def bytes2hex(inbytes, space=None):
    hexdata = map(lambda x: '{0:02X}'.format(x) , inbytes )
    if space:
        hexdata = ' '.join(hexdata)
    else:
        hexdata = ''.join(hexdata)
    return hexdata

def sfill(s, width):
    """ fill string with spaces to width """
    for c in range(width-len(s)):
        s = s + ' '
    return s

