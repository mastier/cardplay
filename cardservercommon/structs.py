#!/usr/bin/env python

import yaml

from constants import *
from madcrc import *
import sys

### ValueError - wlasny

class MifareClassicSector(object):
    """ Mifare Classic card sector represantion object class 
        this is a storage object with data validation and configuration methods
    """ 
    def __init__(self,blocksize=0x10,blocks=0x04,data=None):
        # values here can be defined by constructor later
        self.__dict__['blocksize'] = blocksize
        self.__dict__['blocks']    = blocks
        if not data:
            self.__dict__['data']  = [ 0 for x in range(self.blocksize*(self.blocks-1)) ]
        else:
            self.__dict__['data']  = data + [ 0 for x in range(self.blocksize*self.blocks-len(data)) ]
        self.initsectorlayout()
    
#   def __getattr__(self, name, value):
#       """ Override __getattr__ to handle getting """

    def __setattr__(self, name, value):
        """ Override __setattr__ for mutual changes in keys,acbytes and data, trailer """
        #super().__setattr__(self, name, value)
        if name == 'data':
            pass
        if name == 'trailer':
            if len(value) == self.blocksize and self.issametype(name):
                if self.acbytes_validate(value[6:9]):
                    self.__dict__[name] = value
                    self.__dict__['keya']   = self.trailer[:6]
                    self.__dict__['acbytes']     = self.trailer[6:9]
                    self.__dict__['gpb']    = self.trailer[9:10]
                    self.__dict__['keyb']   = self.trailer[10:]
                else:
                    raise AttributeError('Incorrect AC bytes, wrong bits inversion.')
            else:
                raise AttributeError('Block length is 16, int list must be provided.')

        elif name == 'keya':
            print >>sys.stderr,"KEYA:", len(value), name
            if len(value) == 6 and self.issametype(name):
                self.__dict__['keya']   = value 
                self.trailer = self.keya+self.trailer[6:]
            else:
                raise AttributeError('Key length is 6, int list must be provided.')

        elif name == 'keyb':
            if len(value) == 6 and self.issametype(name):
                self.__dict__['keyb']   = value 
                self.__dict__['trailer'] = self.trailer[:10]+self.keyb
            else:
                raise AttributeError('Key length is 6, int list must be provided.')
        
        elif name == 'acbytes':
            if len(value) == 3 and self.issametype(name):
                if self.acbytes_validate(value):
                    self.__dict__['acbytes'] = value
                    self.__dict__['trailer'] = self.trailer[:6]+self.acbytes+self.trailer[9:]
                else:
                    raise AttributeError('Incorrect AC bytes, wrong bits inversion.')
            else:
                raise AttributeError('AC length is 3, int list must be provided.')

        elif name == 'gpb' :
            if len(value) == 1 and self.issametype(name):
                self.__dict__['gpb'] = value
                self.__dict__['trailer'] = self.trailer[:9]+self.gpb+self.trailer[10:]
            else:
                raise AttributeError('GPB length is 1, int list must be provided.')
        else:
            print >>sys.stderr,'setattr:',name, value
            object.__setattr__(self, name, value)
#        elif name == 'block0' or name == 'block1' or name == 'block2':
#            if len(value) == 16 and self.issametype(name):
#                self.__dict__[name] = value
#            else:
#                raise AttributeError('Block length is 16, int list must be provided.')

    def initsectorlayout(self):
        
        self.trailer= [ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,              # key A
                        0xFF,0x07,0x80,                             # AC
                        0x69,                                       # GPB
                        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF ]             # key B
        self.keya   = [ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF ]             # default key A
        self.keyb   = [ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF ]             # default key B
        self.acbytes= [ 0xFF,0x07,0x80 ]                            # AC in transport(default) configuration
        self.gpb    = [ 0x69 ]                                      # GPB - General Purpose Byte


    def acbytes_validate(self,acbytes):
        """ Access conditions bytes validation
            bytes are splitted by right and left shift
            then the proper bits are cheched whether they are inverted
            with XOR operation
        """

        if  acbytes[0] >> 4 == (acbytes[2] & 0b00001111) ^ 0b1111 and \
            acbytes[1] >> 4 == (acbytes[0] & 0b00001111) ^ 0b1111 and \
            acbytes[2] >> 4 == (acbytes[1] & 0b00001111) ^ 0b1111:
            return True
        else:
            return False
    def acbytes_get(self,block):
        
        if block not in range(self.blocks):
            raise ValueError('Allowed block number is 0,1,2,3.')

        c1=((self.acbytes[1] >> 4         ) & (0b1 << block)) >> block
        c2=((self.acbytes[2] & 0b00001111 ) & (0b1 << block)) >> block
        c3=((self.acbytes[2] >> 4         ) & (0b1 << block)) >> block
        return c1+c2*2+c3*4

    def acbytes_set(self,actuple,block):
        
        if actuple not in range(8):
            raise ValueError('AC tuple is binary tuple, an integer in range <0,7>')
        if block not in range(4):
            raise ValueError('Allowed block number is 0,1,2,3.')
       
        C1=(actuple & 0b100) >> 2 
        C2=(actuple & 0b010) >> 1 
        C3=(actuple & 0b001)      
        
        # now set the proper bits value and make inversion of each byte parts, first reset, then set bit
        self.acbytes[0] = (self.acbytes[0] & ((1<<4+block)^0xff)) | ((C2^1) << 4+block)
        self.acbytes[0] = (self.acbytes[0] & ((1<<block)^0xff)  ) | ((C1^1) <<   block)
        
        self.acbytes[1] = (self.acbytes[1] & ((1<<4+block)^0xff) ) | ( C1    << 4+block)
        self.acbytes[1] = (self.acbytes[1] & ((1<<block)^0xff)   ) | ((C3^1) <<   block)

        self.acbytes[2] = (self.acbytes[2] & ((1<<4+block)^0xff) ) | ( C3    << 4+block)
        self.acbytes[2] = (self.acbytes[2] & ((1<<block)^0xff)   ) | ( C2    <<   block)
        
        self.acbytes = [ self.acbytes[0], self.acbytes[1],  self.acbytes[2] ]

    def get_perms(self):
        """ Provides list of dictionaries of each data block """
        block = []
        # data blocks
        for i in range(self.blocks-1):
            perms=MIFARE_ACB[self.acbytes_get(i)]
            block.append({})
            for key, perm in ACB.iteritems():
                block[-1][key]=[]
                for name, value in perm.iteritems():
                    if perms | value == perms: block[-1][key].append(name)
        # trailer block
        perms=MIFARE_ACT[self.acbytes_get(self.blocks-1)]
        block.append({})
        for key, perm in ACT.iteritems():
            block[-1][key]=[]
            for name, value in perm.iteritems():
                if perms | value == perms: block[-1][key].append(name)

        return block

    def issametype(self, thislist):
        if len(set([ type(item) for item in thislist])) == 1:
            return True
        else:
            return False
        
class ICCard(object):
    """ Universal card represantion object class
        this is a storage object with data validation and configuration methods
    """
    CARDTYPE_CHOICES = (
        (0, 'Mifare Classic Card'),
        (1, 'Mifare Ultralight C Card')
        )
   
    SECTORS_MAX=16

    
    def __init__(self, typeid=0):
        # values here can be defined by constructor later
        self.sectors  = self.SECTORS_MAX
        self.typeid = typeid
        # sector is an ordered list
        self.sector = []
        self.initcardlayout()

    def importyaml(self,filename):
        try:
            # TODO: przy importowaniu sprawdzac jakie atrybuty dostaje klasa obiektu
            self = yaml.load( open(filename) ) 
        except IOError as (errno, strerror):
            print "I/O error({0}): {1}".format(errno, strerror)

    def importcsv(self, filename,sep=','):
        lineformat  = [ 'block' , 'data' ]
        try:
            with open(filename) as f:
                for line in f:
                    linedict = dict(zip(lineformat,line.strip().split(sep)))
                    if len(lineformat) == len(linedict):
                        try:

                            block = int(linedict['block'],16)
                            data = [int(linedict['data'][x:x+2],16) for x in range(0, len(linedict['data']), 2)]
                            print '\n\ndata:', data

                            # auth data block ?
                            sector_nr = block / self.sector[0].blocks
                            block_nr  = block % self.sector[0].blocks
                            print 'sector_nr', sector_nr
                            print 'block_nr' , block_nr
                            if block_nr == self.sector[0].blocks - 1:
                                if self.typeid == 0:
                                    self.sector[sector_nr].keya    =  data[0:6]
                                    self.sector[sector_nr].acbytes =  data[6:9]
                                    self.sector[sector_nr].gpb     = [data[9]]
                                    self.sector[sector_nr].keyb    =  data[10:16]
                                else: 
                                    print 'Unsupported card type!'
                                    return False
                            else:
                                if block < self.sectors*self.sector[0].blocks:
                                    data_start = block_nr*self.sector[0].blocksize
                                    print 'data_start', data_start
                                    print 'data_end', data_start+self.sector[0].blocksize
                                    self.sector[sector_nr].data[data_start:data_start+self.sector[0].blocksize] = data[0:self.sector[0].blocksize] 
                                else:
                                    print 'Bad file format!'
                                    return False
                            print 'sector data   :',self.sector[sector_nr].data
                            print 'sector trailer:',self.sector[sector_nr].trailer

                        except ValueError as strerror:
                            print 'Bad file format: {0}!'.format(strerror)
                            return False
                    else: 
                        print 'Bad file format!'
                        return False

                        
                        
        except IOError as (errno, strerror):
            print "I/O error({0}): {1}".format(errno, strerror)
            return False
        except KeyError as (exc_value):
            print "KeyError: no {0} field".format(exc_value)
            return False
    
    def importbin(self, filename):
        try:
            binary = []
            with open(filename,'rb') as f:
                while True:
                    byte = f.read(1)
                    if byte == "":
                        break
                    byte = ord(byte)
                    binary.append(byte)
                    
            """ cut the list to the size of card """
            binary = binary[0:self.sectors*self.sector[0].blocks*self.sector[0].blocksize]
            print binary
            print len(binary)

            for b in range( self.sectors*self.sector[0].blocks - 1 ):
                try:
                    data = binary[b*self.sector[0].blocksize:(b+1)*self.sector[0].blocksize]

                    sector_nr = b / self.sector[0].blocks
                    block_nr  = b % self.sector[0].blocks

                    if block_nr == self.sector[0].blocks - 1:
                        if self.typeid == 0:
                            self.sector[sector_nr].keya    =  data[0:6]
                            self.sector[sector_nr].acbytes =  data[6:9]
                            self.sector[sector_nr].gpb     = [data[9]]
                            self.sector[sector_nr].keyb    =  data[10:16]
                        else: 
                            print 'Unsupported card type!'
                            return False
                    else:
                        if b < self.sectors*self.sector[0].blocks: # not needed
                            data_start = block_nr*self.sector[0].blocksize
                            print 'data_start', data_start
                            print 'data_end', data_start+self.sector[0].blocksize
                            self.sector[sector_nr].data[data_start:data_start+self.sector[0].blocksize] = data[0:self.sector[0].blocksize] 

                        else:
                            print 'Bad file format!'
                            return False
                    print 'sector data   :',self.sector[sector_nr].data
                    print 'sector trailer:',self.sector[sector_nr].trailer

                except ValueError as strerror:
                    print 'Bad file format: {0}!'.format(strerror)
                    return False
                        
        except IOError as (errno, strerror):
            print "I/O error({0}): {1}".format(errno, strerror)
            return False
    
    def exportyaml(self, filename=None):
        if filename:
            try:
                open(filename,'w').write(yaml.dump(self))
            except IOError as (errno, strerror):
                print "I/O error({0}): {1}".format(errno, strerror)
        else:
            return yaml.dump(self)
    
    def exportcsv(self, filename=None):
        csv = ''
        it = iter([x for x in range(self.sectors*self.sector[0].blocksize)])
        for s in self.sector:
            for b in range(self.sector[0].blocks):

                block = it.next()
                data_start = b*self.sector[0].blocksize

                if b != self.sector[0].blocks - 1:
                    csv += ''.join( 
                                      ['{0:02X}'.format(block)] 
                                    + [' ']
                                    + map(lambda x: '{0:02X}'.format(x), 
                                      s.data[data_start:data_start+self.sector[0].blocksize] ) 
                                    + ['\n'] 
                                  )
                else:
                    csv += ''.join( 
                                      ['{0:02X}'.format(block)] 
                                    + [' ']
                                    + map(lambda x: '{0:02X}'.format(x), s.trailer ) 
                                    + ['\n'] 
                                  )
                

        if filename:
            try:
                open(filename,'w').write(csv)
            except IOError as (errno, strerror):
                print "I/O error({0}): {1}".format(errno, strerror)
        else:
            return csv
    def hasMAD(self):
        self.mad_crc  = self.sector[0].data[16]
        self.mad_info = self.sector[0].data[17]
        aid           = self.sector[0].data[18:]
        return (sector_0x00_crc8(self.sector[0].data[17:]) == self.mad_crc)

    def getMAD(self):
        """ Only MAD1 i supported """
        self.aid_explained = []
        if self.hasMAD():
            self.aid      = [ ( aid[x+1],aid[x] ) for x in range(0, len(aid), 2) ]
            print self.aid
            for a in self.aid:
                j = FCC.get(a[0],a[0])
                k = ACC.get(a[1],a[1])
                self.aid_explained.append( ( j, k ) )
        return self.aid_explained

    def initcardlayout(self):
        """ Initializes card, checks the type to add sectors of corresponding type.
            Clears the sector list.
        """
        
        self.sector = []
        if self.typeid == 0:
            
            for i in range(self.sectors):
                self.sector.append( MifareClassicSector() )

        if self.typeid == 1:
            pass           
