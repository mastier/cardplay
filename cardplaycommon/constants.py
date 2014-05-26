#!/usr/bin/env python

__module__='constants'


READER_PCSC = 0x00
READER_ACS  = 0x10
READER_OMNIKEY  = 0x11

"""

                           [ Key A ]         [ Key B ]
                               |                |
                  ,----------- r(ead)           |
                  |,---------- w(rite)          |
                  ||,--------- d(ecrement)      |
                  |||,-------- i(ncrement)      |
                  ||||                          |
                  ||||,------------------------ r
  ,----- C3       |||||,----------------------- w
  |,---- C2       ||||||,---------------------- d
  ||,--- C1       |||||||,--------------------- i
  |||             ||||||||"""
MIFARE_ACB = {
0b000:          0b11111111, # Default (blank card) 
0b001:          0b10001100, # allow WRITE keyB 
0b010:          0b10001000, # only read both keys,
0b011:          0b10101111, # allow WRITE keyB, inc,dec keyB
0b100:          0b10101010, # only read,dec both keys
0b101:          0b00001000, # only read keyB
0b110:          0b00001100, # allow WRITE
0b111:          0b00000000  # DATA BLOCK NOT AVAILABLE
}
ACB = {
'keya': { 
          'read' : 0b10000000, 
          'write': 0b01000000,
          'dec'  : 0b00100000,
          'inc'  : 0b00010000
        },
'keyb': { 
          'read' : 0b00001000, 
          'write': 0b00000100,
          'dec'  : 0b00000010,
          'inc'  : 0b00000001
        }
}

"""
                              [ Key A ]     [ Access bits ]    [ Key B ]
                                 |              |                |
                  ,----------- read A           |                |
                  |,---------- read B           |                |
                  ||,--------- write A          |                |
                  |||,-------- write B          |                |
                  ||||                          |                |
                  ||||,----------------------- read A            |
                  |||||,---------------------- read B            |
                  ||||||,--------------------- write A           |
                  |||||||,-------------------- write B           |
                  ||||||||                                       |
                  ||||||||,----------------------------------- read A
  ,----- C3       |||||||||,---------------------------------- read B
  |,---- C2       ||||||||||,--------------------------------- write A
  ||,--- C1       |||||||||||,-------------------------------- write B
  |||             ||||||||||||   """
MIFARE_ACT = {
0b000:          0b001010001010,
0b001:          0b000111000001,
0b010:          0b000010001000, 
0b011:          0b000011000000, # only read AC
0b100:          0b001010101010, # Default (blank card), change AC with KeyA 
0b101:          0b000011010000, # change AC with KeyB
0b110:          0b000111010001, # change AC with KeyB
0b111:          0b000011000000  # only read AC
}
ACT = {
'keya': { 
          'reada' : 0b100000000000, 
          'readb' : 0b010000000000, 
          'writea': 0b001000000000,
          'writeb': 0b000100000000,
        },
'ac':   { 
          'reada' : 0b000010000000, 
          'readb' : 0b000001000000, 
          'writea': 0b000000100000,
          'writeb': 0b000000010000,
        },
'keyb': { 
          'reada' : 0b000000001000, 
          'readb' : 0b000000000100, 
          'writea': 0b000000000010,
          'writeb': 0b000000000001,
        }
}

# Mifare transort keys
MIFARE_TK= { 'AA' : 'A0A1A2A3A4A5',\
         'BB' : 'B0B1B2B3B4B5',\
         'FF' : 'FFFFFFFFFFFF'}
MIFARE_KEYTYPE= { 'A': '60',
                  'B': '61'
                }

MIFARE_DEFAULT_KEYS=[
                      'ffffffffffff',
                      #'a0a1a2a3a4a5',
                      #'000000000000',
                      #'d3f7d3f7d3f7',
                      #'b0b1b2b3b4b5','4d3a99c351dd',
                      #'1a982c7e459a','aabbccddeeff','714c5c886e97',
                      #'587ee5f9350f','a0478cc39091','533cb6c723f6','8fd0a4f256e9'
                     ]


# PCSC Errors
PCSC_NO_CARD= 'PC00'
PCSC_COMMS_ERROR= 'PC01'
PCSC_VOLATILE= '00'
PCSC_NON_VOLATILE= '20'
# PCSC Contactless Storage Cards
PCSC_CSC= '804F'
# PCSC Workgroup RID
PCSC_RID= 'A000000306'
# PCSC Storage Standard Byte
PCSC_SS= { '00':'No information given',\
       '01':'ISO 14443 A, part 1',\
       '02':'ISO 14443 A, part 2',\
       '03':'ISO 14443 A, part 3',\
       '04':'RFU',\
       '05':'ISO 14443 B, part 1',\
       '06':'ISO 14443 B, part 2',\
       '07':'ISO 14443 B, part 3',\
       '08':'RFU',\
       '09':'ISO 15693, part 1',\
               '0A':'ISO 15693, part 2',\
               '0B':'ISO 15693, part 3',\
               '0C':'ISO 15693, part 4',\
       '0D':'Contact (7816-10) I2 C',\
       '0E':'Contact (7816-10) Extended I2 C',\
       '0F':'Contact (7816-10) 2WBP',\
       '10':'Contact (7816-10) 3WBP',\
       'FF':'RFU'}
# PCSC card names
PCSC_NAME= { '0000':'No name given',\
         '0001':'Mifare Standard 1K',\
         '0002':'Mifare Standard 4K',\
         '0003':'Mifare Ultra light',\
         '0004':'SLE55R_XXXX',\
         '0006':'SR176',\
         '0007':'SRI X4K',\
         '0008':'AT88RF020',\
         '0009':'AT88SC0204CRF',\
         '000A':'AT88SC0808CRF',\
         '000B':'AT88SC1616CRF',\
         '000C':'AT88SC3216CRF',\
         '000D':'AT88SC6416CRF',\
         '000E':'SRF55V10P',\
         '000F':'SRF55V02P',\
         '0010':'SRF55V10S',\
         '0011':'SRF55V02S',\
         '0012':'TAG_IT',\
         '0013':'LRI512',\
         '0014':'ICODESLI',\
         '0015':'TEMPSENS',\
         '0016':'I.CODE1',\
         '0017':'PicoPass 2K',\
         '0018':'PicoPass 2KS',\
         '0019':'PicoPass 16K',\
         '001A':'PicoPass 16Ks',\
         '001B':'PicoPass 16K(8x2)',\
         '001C':'PicoPass 16KS(8x2)',\
         '001D':'PicoPass 32KS(16+16)',\
         '001E':'PicoPass 32KS(16+8x2)',\
         '001F':'PicoPass 32KS(8x2+16)',\
         '0020':'PicoPass 32KS(8x2+8x2)',\
         '0021':'LRI64',\
         '0022':'I.CODE UID',\
         '0023':'I.CODE EPC',\
         '0024':'LRI12',\
         '0025':'LRI128',\
         '0026':'Mifare Mini'}
# ACS Constants
ACS_TAG_FOUND= 'D54B'
ACS_DATA_OK= 'D541'
ACS_NO_SAM= '3B00'
ACS_TAG_MIFARE_ULTRA= 'MIFARE Ultralight'
ACS_TAG_MIFARE_1K= 'MIFARE 1K'
ACS_TAG_MIFARE_MINI= 'MIFARE MINI'
ACS_TAG_MIFARE_4K= 'MIFARE 4K'
ACS_TAG_MIFARE_DESFIRE= 'MIFARE DESFIRE'
ACS_TAG_JCOP30= 'JCOP30'
ACS_TAG_JCOP40= 'JCOP40'
ACS_TAG_MIFARE_OYSTER= 'London Transport Oyster'
ACS_TAG_GEMPLUS_MPCOS= 'Gemplus MPCOS'

ACS_TAG_TYPES=	{
        '00':ACS_TAG_MIFARE_ULTRA,
        '08':ACS_TAG_MIFARE_1K,
        '09':ACS_TAG_MIFARE_MINI,
        '18':ACS_TAG_MIFARE_4K,
        '20':ACS_TAG_MIFARE_DESFIRE,
        '28':ACS_TAG_JCOP30,
        '38':ACS_TAG_JCOP40,
        '88':ACS_TAG_MIFARE_OYSTER,
        '98':ACS_TAG_GEMPLUS_MPCOS,
        }

ISOAPDU=  {
       'VERIFY':'20',
       'EXTERNAL_AUTHENTICATE':'82',
       'INTERNAL_AUTHENTICATE':'86',
       'INTERNAL_AUTHENTICATE_OBS':'88',
       'READ_BINARY':'B0',
       'GET_DATA':'CA',
       'UPDATE_BINARY':'D6',
       }

PCSC_APDU= {
    'ACS_14443_A' : ['d4','40','01'],
    'ACS_14443_B' : ['d4','42','02'],
    'ACS_14443_0' : ['d5','86','80', '05'],
    'ACS_DISABLE_AUTO_POLL' : ['ff','00','51','3f','00'],
    'ACS_DIRECT_TRANSMIT' : ['ff','00','00','00'],
    'ACS_GET_SAM_SERIAL' : ['80','14','00','00','08'],
    'ACS_GET_SAM_ID' : ['80','14','04','00','06'],
    'ACS_GET_READER_FIRMWARE' : ['ff','00','48','00','00'],
    'ACS_GET_RESPONSE' : ['ff','c0','00','00'],
    'ACS_GET_STATUS' : ['d4','04'],
    'ACS_GET_TAGTYPE': ['ff','c0','00','00','05'],
    'ACS_IN_LIST_PASSIVE_TARGET' : ['d4','4a'],
    'ACS_LED_GREEN' : ['ff','00','40','0e','04','00','00','00','00'],
    'ACS_LED_ORANGE' : ['ff','00','40','0f','04','00','00','00','00'],
    'ACS_LED_RED' : ['ff','00','40','0d','04','00','00','00','00'],
    'ACS_MIFARE_LOGIN' : ['d4','40','01'],
    'ACS_READ_MIFARE' : ['d4','40','01','30'],
    'ACS_WRITE_MIFARE' : ['d4','40','01','A0'],
    'ACS_POLL_MIFARE' : ['d4','4a','01','00'],
    'ACS_POWER_OFF' : ['d4','32','01','00'],
    'ACS_POWER_ON' : ['d4','32','01','01'],
    'ACS_RATS_14443_4_OFF' : ['d4','12','24'],
    'ACS_RATS_14443_4_ON' : ['d4','12','34'],
    'ACS_SET_PARAMETERS' : ['d4','12'],
    'ACS_SET_RETRY' : ['d4','32','05','00','00','00'],
    'AUTHENTICATE' : ['ff', ISOAPDU['INTERNAL_AUTHENTICATE']],
    'AUTHENTICATE_OBS' : ['ff', ISOAPDU['INTERNAL_AUTHENTICATE_OBS']],
    'GUID' : ['ff', ISOAPDU['GET_DATA'], '00', '00', '00'],
    'ACS_GET_ATS' : ['ff', ISOAPDU['GET_DATA'], '01', '00', '00'],
    'LOAD_KEY' : ['ff',  ISOAPDU['EXTERNAL_AUTHENTICATE']],
    'READ_BLOCK' : ['ff', ISOAPDU['READ_BINARY']],
    'UPDATE_BLOCK' : ['ff', ISOAPDU['UPDATE_BINARY']],
    'VERIFY' : ['ff', ISOAPDU['VERIFY']],
    }


""" 
    #########################################################################################
    Responses and errors constants 
    #########################################################################################
"""

ISO_OK= '9000'
ISO_SECURE= '6982'
ISO_NOINFO= '6200'

ISO_SPEED= {'00':'106kBaud',\
        '02':'212kBaud',\
        '04':'424kBaud',\
        '08':'848kBaud'}
ISO_FRAMESIZE= { '00':'16',\
         '01':'24',\
         '02':'32',\
         '03':'40',\
         '04':'48',\
         '05':'64',\
         '06':'96',\
         '07':'128',\
         '08':'256'}
ISO7816ErrorCodes=  {
            '61':'SW2 indicates the number of response bytes still available',
            '6200':'No information given',
            '6281':'Part of returned data may be corrupted',
            '6282':'End of file/record reached before reading Le bytes',
            '6283':'Selected file invalidated',
            '6284':'FCI not formatted according to ISO7816-4 section 5.1.5',
            '6300':'Failed. No information given',
            '6301':'ACR: PN532 does not respond',
            '6327':'ACR: Contacless Response invalid checksum',
            '637F':'ACR: PN532 invalid Contactless Command',
            '6381':'File filled up by the last write',
            '6382':'Card Key not supported',
            '6383':'Reader Key not supported',
            '6384':'Plain transmission not supported',
            '6385':'Secured Transmission not supported',
            '6386':'Volatile memory not available',
            '6387':'Non Volatile memory not available',
            '6388':'Key number not valid',
            '6389':'Key length is not correct',
            '63C':'Counter provided by X (valued from 0 to 15) (exact meaning depending on the command)',
            '64':'State of non-volatile memory unchanged (SW2=00, other values are RFU)',
            '6400':'Card Execution error',
            '6500':'No information given',
            '6581':'Memory failure',
            '66':'Reserved for security-related issues (not defined in this part of ISO/IEC 7816)',
            '6700':'Wrong length',
            '6800':'No information given',
            '6881':'Logical channel not supported',
            '6882':'Secure messaging not supported',
            '6900':'No information given',
            '6981':'Command incompatible with file structure',
            '6982':'Security status not satisfied',
            '6983':'Authentication method blocked',
            '6984':'Referenced data invalidated',
            '6985':'Conditions of use not satisfied',
            '6986':'Command not allowed (no current EF)',
            '6987':'Expected SM data objects missing',
            '6988':'SM data objects incorrect',
            '6A00':'No information given',
            '6A80':'Incorrect parameters in the data field',
            '6A81':'Function not supported',
            '6A82':'File not found',
            '6A83':'Record not found',
            '6A84':'Not enough memory space in the file',
            '6A85':'Lc inconsistent with TLV structure',
            '6A86':'Incorrect parameters P1-P2',
            '6A87':'Lc inconsistent with P1-P2',
            '6A88':'Referenced data not found',
            '6B00':'Wrong parameter(s) P1-P2',
            '6C':'Wrong length Le: SW2 indicates the exact length',
            '6D00':'Instruction code not supported or invalid',
            '6E00':'Class not supported',
            '6F00':'No precise diagnosis',
            '9000':'Success or No further qualification',
            'ABCD':'RFIDIOt: Reader does not support this command',
            'F':'Read error or Security status not satisfied',
            'FFFB':'Mifare (JCOP) Block Out Of Range',
            'FFFF':'Unspecified Mifare (JCOP) Error',
            'N':'No precise diagnosis',
            'PC00':'No TAG present!',
            'PC01':'PCSC Communications Error',
            'PN00': 'PN531 Communications Error',
            'R':'Block out of range',
            'X':'Authentication failed',
            }


"""
MAD structure information about AIDs - AN10787.pdf
"""

#function cluster code (hex) function
FCC={
0x00:'card administration',
0x01:'miscellaneous applications',
0x02:'miscellaneous applications',
0x03:'miscellaneous applications',
0x04:'miscellaneous applications',
0x05:'miscellaneous applications',
0x06:'miscellaneous applications',
0x07:'miscellaneous applications',
0x08:'airlines',
0x09:'ferry trafic',
0x10:'railway services',
0x12:'transport',
0x18:'city traffic',
0x19:'Czech Railways',
0x20:'bus services',
0x21:'multi modal transit',
0x28:'taxi',
0x30:'road toll',
0x38:'company services',
0x40:'city card services',
0x47:'access control & security',
0x48:'access control & security',
0x49:'VIGIK',
0x4A:'Ministry of Defence, Netherlands',
0x4B:'Bosch Telecom, Germany',
0x4A:'Ministry of Defence, Netherlands',
0x4C:'European Union Institutions',
0x50:'ski ticketing',
0x51:'access control & security',
0x52:'access control & security',
0x53:'access control & security',
0x54:'access control & security',
0x58:'academic services',
0x60:'food',
0x68:'non food trade',
0x70:'hotel',
0x75:'airport services',
0x78:'car rental',
0x79:'Dutch government',
0x80:'administration services',
0x88:'electronic purse',
0x90:'television',
0x91:'cruise ship',
0x95:'IOPTA',
0x97:'Metering',
0x98:'telephone',
0xA8:'warehouse',
0xB0:'electronic trade',
0xB8:'banking',
0xC0:'entertainment & sports',
0xC8:'car parking',
0xC9:'Fleet Management',
0xD0:'fuel, gasoline',
0xD8:'info services',
0xE0:'press',
0xE1:'NFC Forum',
0xE8:'computer',
0xF0:'mail',
0xF8:'miscellaneous applications',
0xF9:'miscellaneous applications',
0xFA:'miscellaneous applications',
0xFB:'miscellaneous applications',
0xFC:'miscellaneous applications',
0xFD:'miscellaneous applications',
0xFE:'miscellaneous applications',
0xFF:'miscellaneous applications'
}
ACC={
0x00:'Free',
0x01:'Defect',
0x02:'Reserved',
0x03:'Additional info (for future cards)',
0x04:'Cardholder information',
0x05:'Not applicable (above memory)'
}







"""
                 cmd = raw_input('<< ')
            cmd = 'FF 00 00 00 0F D4 40 01 60 0E FF FF FF FF FF FF 5E B4 15 60'
            #cmd = 'FF 82 00 00 06 FF FF FF FF FF FF'
            cmd = self.cmdprepare(cmd)
            if cmd:
                data, sw1, sw2 = cardconnection.transmit(cmd)
                response=' '.join( map(lambda x: '%02X' % x  , data) )
                print '>>',response, "| %02X %02X" % (sw1, sw2)
            cmd = 'FF 00 00 00 15 D4 40 01 A0 0E 54 EF B5 F5 9B CF 32 03 96 18 48 81 55 77 31 59'
            #cmd = 'FF 86 00 00 05 01 00 0C 60 00'
            cmd = self.cmdprepare(cmd)
            if cmd:
                data, sw1, sw2 = cardconnection.transmit(cmd)
                response=' '.join( map(lambda x: '%02X' % x  , data) )
                print '>>',response, "| %02X %02X" % (sw1, sw2)
            #cmd = 'FF D6 00 0C 06 0C 10 54 EF B5 F5 9B CF 32 03 96 18 48 81 55 77 31 59'
            cmd = self.cmdprepare(cmd)
            if cmd:
                data, sw1, sw2 = cardconnection.transmit(cmd)
                response=' '.join( map(lambda x: '%02X' % x  , data) )
                print '>>',response, "| %02X %02X" % (sw1, sw2)
"""

