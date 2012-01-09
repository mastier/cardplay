#!/usr/bin/env python

import yaml

class MifareSector(object):
    """ Mifare Classic card sector represantion object class 
        this is a storage object with data validation and configuration methods
    """ 
    def __init__(self):
        # values here can be defined by constructor later
        self.blocksize = 0x10
        self.blocks    = 0x03

        self.initsectorlayout()

    def __setattr__(self, name, value):
        """ Override __setattr__ for mutual changes in keys,acbytes and blocks """
        #super().__setattr__(self, name, value)
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

        elif name == 'acbytes'  :
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
            object.__setattr__(self, name, value)
#        elif name == 'block0' or name == 'block1' or name == 'block2':
#            if len(value) == 16 and self.issametype(name):
#                self.__dict__[name] = value
#            else:
#                raise AttributeError('Block length is 16, int list must be provided.')

    def initsectorlayout(self):
        

        self.block     = []
        self.nr    = -1
        for i in range(self.blocks):
            self.block.append( [ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ] )
        self.trailer= [ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,              # key A
                        0xFF,0x07,0x80,                             # AC
                        0x69,                                       # GPB
                        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF ]             # key B
        self.keya   = [ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF ]             # default key A
        self.keyb   = [ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF ]             # default key B
        self.acbytes= [ 0xFF,0x07,0x80 ]                            # AC in transport(default) configuration
        self.gpb    = [ 0x69 ]                                      # GPB - General Purpose Byte


    def acbytes_validate(self,acbytes):
        """ Access condition bytes validation
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
    def actuple_get(self,block):

        if block not in range(3):
            raise ValueError('Allowed block number is 0,1,2.')

        c1=((self.acbytes[1] >> 4         ) & (0b1 << block)) >> block
        c2=((self.acbytes[2] & 0b00001111 ) & (0b1 << block)) >> block
        c3=((self.acbytes[2] >> 4         ) & (0b1 << block)) >> block
        return c1*4+c2*2+c3

    def acbytes_set(self,actuple,block):
        
        if actuple >=0 and actuple <8:
            raise ValueError('AC tuple is binary tuple, an integer in range <0,7>')
        if block not in range(3):
            raise ValueError('Allowed block number is 0,1,2,3.')
        
        c1=((actuple & 0b100) << block)
        c2=((actuple & 0b010) << block)
        c3=((actuple & 0b001) << block)
        # zero the bits to change
        C1=(self.acbytes[1] >> 4         ) & ~(0b1 << block)
        C2=(self.acbytes[2] & 0b00001111 ) & ~(0b1 << block)
        C3=(self.acbytes[2] >> 4         ) & ~(0b1 << block)
        # now set the proper bits value and make inversion of each byte parts 
        self.acbytes[0] = (~(C2+c2) << 4) | ~(C1+c1)
        self.acbytes[1] = ( (C1+c1) << 4) | ~(C3+c3)
        self.acbytes[2] = ( (C3+c3) << 4) |  (C2+c2)

    def issametype(self, thislist):
        if len(set([ type(item) for item in thislist])) == 1:
            return True
        else:
            return False
        
class ICCard(object):
    """ Mifare Classic card represantion object class
        this is a storage object with data validation and configuration methods
    """

    def __init__(self):
        # values here can be defined by constructor later
        self.sectors  = 0x10
        self.typeid = 'mfclassic'
        self.initcardlayout()
        self.sector = []

    
    def initcardlayout(self):

        for i in range(self.sectors):
            self.sector.append( MifareSector() )
