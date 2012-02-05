#! /usr/bin/env python

import sys,os,argparse

from smartcard.System import readers

#card monitoring
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.CardConnectionObserver import CardConnectionObserver

#from smartcard.CardType import AnyCardType
#from smartcard.CardRequest import CardRequest
# hexToString util
from smartcard.util import *
#In Exception we trust
from smartcard.Exceptions import *

# threading support
import threading

import re
from time import *


# additional content
from cardservercommon.constants import *
from cardservercommon.utilities import *
from cardservercommon.structs   import *



class CustomCardConnectionObserver(CardConnectionObserver): 
    def __init__(self, trace=False):
        self.trace = trace

    def update(self, cardconnection, ccevent): 
 
        if 'connect' == ccevent.type: 
            print '== connecting to ' + cardconnection.getReader() 
 
        elif 'disconnect' == ccevent.type: 
            print '== disconnecting from ' + cardconnection.getReader() 
 
        elif 'command' == ccevent.type and self.trace:
            print '<< ', toHexString(ccevent.args[0]) 
 
        elif 'response' == ccevent.type: 
            if [] == ccevent.args[0]:
                if bytes2hex(ccevent.args[-2:]) in ISO7816ErrorCodes.keys():
                    print '>>  [] ', "{0:02X} {1:02X}".format(ccevent.args[-2],ccevent.args[-1]),ISO7816ErrorCodes[bytes2hex(ccevent.args[-2:])]
                else:
                    print '>>  [] ', "{0:02X} {1:02X}".format(ccevent.args[-2],ccevent.args[-1]),'??UNKNOWN??'
            else: 
                print '>> ', bytes2hex(ccevent.args[0]),'"'+bytes2ascii(ccevent.args[0])+'"', "{0:02X} {1:02X}".format(ccevent.args[-2],ccevent.args[-1])

#class CLCard(object):
    




class CardServer(threading.Thread):
    """ CardServer main class controls the readers connections, sends APDU commands,
        inherits from threading.Thread
    """
    def __init__(self, args):
        self.args = args
        threading.Thread.__init__(self)    
        self.cardblocksize = 0x10 # works on both omnikey and acs
            
    def run(self):
        self.determine_reader()
#       self.determine_tagtype()

        if self.args['interactive']:
            self.spawnshell()
        elif self.args['action']:

            if 'infile' in self.args.keys():        
                """ File is taken as a input of keytype, key, block (and data to be written) """
                self.batchexec(self.getsource(self.args['infile']), self.args['action'], self.args['output'])



            if 'line'   in self.args.keys():        
                """ Line is taken as a input of keytype, key, block """
                if self.args['action'] == 'read':
                    self.readblock(      hex2bytes(self.args['block']),\
                                         MIFARE_KEYTYPE[self.args['keytype']],\
                                         hex2bytes(self.args['key']) 
                                  )
                if self.args['action'] == 'write':
                    """ Check whether input is hex or ascii """
                    if len(re.findall(r'[a-fA-F0-9]', self.args['data'])) == len( self.args['data'] ):
                        data = hex2bytes  ( sfill(self.args['data'], self.cardblocksize) ) 
                    else:
                        data = asciidata_tobytes( sfill(self.args['data'], self.cardblocksize) )

                    self.writeblock(      hex2bytes(self.args['block']),\
                                          MIFARE_KEYTYPE[self.args['keytype']],\
                                          hex2bytes(self.args['key']),\
                                          data
                                  )
                if self.args['action'] == 'ac':
                    distance = hex2bytes(self.args['block'])[0] % 4
                    sectortrailer = hex2bytes(self.args['block'])[0]+(3-distance)

                    sectorbytes= self.readblock([sectortrailer],\
                                         MIFARE_KEYTYPE[self.args['keytype']],\
                                         hex2bytes(self.args['key']) 
                                  )
                    if sectorbytes:
                        for i in range(0,3):
                            ac = self.accesscond_interpret(sectorbytes[6:9].i)
                            print bytes2hex([sectortrailer-3]), MIFAREACDB[ac]
                        ac = self.accesscond_interpret(sectorbytes[6:9],3)
                        print bytes2hex([sectortrailer]), MIFAREACKB[ac]
                    else:
                        print 'Cannot read access conditions!'

            if 'stupid'   in self.args.keys():
                """ STUPID MODE tries get access to each sector by trying default keys both A/B """
                carddata = []
                for b in range(4*self.cardblocksize):
                    for kt in ['A','B']:
                        for k in MIFARE_DEFAULT_KEYS:
                            carddata.append({'block':'{0:02X}'.format(b), 'keytype':MIFARE_KEYTYPE[kt], 'key':k})
                            #print >>sys.stderr, repr(carddata.pop())
                    
                self.batchexec(carddata, self.args['action'], self.args['stupid'])
   
    def getsource(self, infile):
        carddata = []
        lineformat = [ 'block' , 'keytype' , 'key', 'data' ]
        try:
            with open(infile) as f:
                for line in f:
                    carddata.append( dict(zip(lineformat,line.split()))  )
            return carddata
        except OSError:
            return None

    def batchexec(self, carddata, action ,outfile=None):
        data = {}
        if not outfile:
            outfile = open('/dev/stdout','w')
        else:
            outfile = open(outfile,'w')
#        success =      qed { 'A': False, 'B': False}
        for d in carddata:
            """ Read or write specified blocks of data """
            if action == 'read':
                import sys
                print >>sys.stderr, 'd:',d
                print >>sys.stderr, 'carddata:',carddata
                print >>sys.stderr, "d['keytype']:",d['keytype']
                data = self.readblock( hex2bytes(d['block']),\
                                           hex2bytes(d['keytype']),\
                                           hex2bytes(d['key'])
                                         )
            elif action == 'write':
                if int(d['block'],16) % 4 == 3:
                    print hex2bytes(d['data'])[6:9]
                    if self.accesscond_validate( hex2bytes(d['data'])[6:9] ):
                        print 'AC OK!'
                    else:
                        print 'AC schlecht!'
#                data = ([0x00,0x00,0x00],0x63,0x00)
                data = self.writeblock( hex2bytes(d['block']),\
                                           hex2bytes(d['keytype']),\
                                           hex2bytes(d['key']),\
                                           hex2bytes(d['data'])
                                         )

            """ Verify the result """
            if self.args['native'] and data[0][:3] == [0xD5, 0x41,0x00] and len(data[0]) > 3:
                outfile.write(  d['block']+' '+d['keytype']+' '+d['key']+' '+\
#                                            self.accesscond_interpret(  data[0][3:][6:9],int(d['block'],16) % 4)+' '+\
                                            bytes2hex  (data[0][3:])+' '+\
                                            bytes2ascii(data[0][3:])+'\n'
                                     )

            elif not self.args['native'] and data[0]:
                outfile.write(  d['block']+' '+d['keytype']+' '+d['key']+' '+\
#                                            self.accesscond_interpret(  data[0][6:9],int(d['block'],16) % 4)+' '+\
                                            bytes2hex  (data[0])+' '+\
                                            bytes2ascii(data[0])+'\n'
                                         )

            else:
                if not data[0]:
                    # PC/SC errors
                    outfile.write(  d['block']+' '+d['keytype']+' '+d['key']+' '+\
                                                bytes2hex  (data[-2:])+' '+\
                                                ISO7816ErrorCodes[bytes2hex(data[-2:])]+'\n'
                                             )
                else: 
                    # native chip errors
                    outfile.write(  d['block']+' '+d['keytype']+' '+d['key']+' '+\
                                                bytes2hex  (data[-2:])+' '+\
                                                bytes2hex(data[0])+'\n'
                                             )
    def iserror(response):
        pass

    def reconnect_loop(self):
        retry=True
        while retry: 
            try:
                self.connection.connect()
                #self.determine_tagtype()
                retry=False
            except CardConnectionException:
                print "error connecting, retrying in 2 sec.."
                sleep(2)
        
        
    def determine_reader(self):
        """ Check what readers are available, determine their type and pick one to use, save in self.readertype and self.readersubtype """
        rlist = readers()
        rlistnames = []
        map(lambda x: rlistnames.append(x.name), rlist)
        print "Found readers:",rlistnames
        if rlist:
            for r in rlist: 
                if   'ACS ACR122U' in r.name:
                    self.readertype    = READER_PCSC
                    self.readersubtype = READER_ACS
                    self.reader = r
                elif 'OMNIKEY'     in r.name:
                    if '00 01' in r.name: # the contactless interface must be choosen
                        self.readertype    = READER_PCSC
                        self.readersubtype = READER_OMNIKEY
                        print >>sys.stderr,rlist.index(r)
                        self.reader = r
                else:
                    print 'No supported readers found'
                    sys.exit(1)
        else:
            print 'No supported readers found'
            sys.exit(1)


        # Now connect to reader and attach observer
        self.connection =  self.reader.createConnection()
        print self.connection
        # If interactive turn off showing the bytes sent
        observer = CustomCardConnectionObserver() if self.args['interactive'] else CustomCardConnectionObserver(True)
        self.connection.addObserver(observer)
        self.reconnect_loop()

    def determine_tagtype(self):
        if self.readersubtype == READER_ACS:
            response = self.sendcmd( hex2bytes(PCSC_APDU['ACS_GET_TAGTYPE']) )
            if response[-2:] == (0x90,0x00):
                self.card = response[0][2]
                print ACS_TAG_TYPES[bytes2hex(response[0][2])]

    def sendcmd(self, cmdbytes):
    
        if cmdbytes:
            try:
                #print 'COMMAND:',bytes2hex(cmdbytes)
                responsedata, sw1, sw2 = self.connection.transmit(cmdbytes)
                return (responsedata, sw1, sw2)

            except CardConnectionException:
                self.connection.disconnect()
                self.reconnect_loop()

    def sendcmdnative(self, cmdbytes):
    
        if cmdbytes:
            try:
                #print 'COMMAND:',bytes2hex(cmdbytes)
                responsedata = self.connection.transmit(cmdbytes)
                return responsedata

            except CardConnectionException:
                self.connection.disconnect()
                self.reconnect_loop()
                
    
    def acs_authenticate(self, block,keytype, key):
        
        response = self.sendcmdnative( hex2bytes(PCSC_APDU['ACS_DIRECT_TRANSMIT'])+\
                                       [0x04]+\
                                       hex2bytes(PCSC_APDU['ACS_POLL_MIFARE']) # assumed Tg = 01
                                     )

        if response[0][2] > 0x00: 


            uid = response[0][-4:]
            login = hex2bytes(PCSC_APDU['ACS_MIFARE_LOGIN'])+keytype+block+key+uid
            response = self.sendcmdnative( hex2bytes(PCSC_APDU['ACS_DIRECT_TRANSMIT'])+[len(login)]+login) # assumed Tg = 01
            return response
        else:
            return response


    def authenticate(self, block,keytype,key):
        if self.readertype == READER_PCSC:
            if self.readersubtype == READER_ACS and self.args['native']:
                return acs_authenticate(block,keytype,key) # D5 41 00 - success
                    
            if self.readersubtype == READER_OMNIKEY or not self.args['native']:
                cla_ins = hex2bytes(PCSC_APDU['LOAD_KEY'])

                if self.readersubtype == READER_ACS:
                    #                            P1=0x00 5bit=0 vmem in acs
                    response = self.sendcmd(cla_ins+[0x00]+[0x00]+[len(key)]+key)
                else:
                    #                            P1=0x20 5bit=1 nvmem in omnikey
                    response = self.sendcmd(cla_ins+[0x20]+[0x00]+[len(key)]+key)
                    #response =  (0x90,0x00)

                if response[-2:] == (0x90,0x00):

                    cla_ins = hex2bytes(PCSC_APDU['AUTHENTICATE'])
                    #                      classIN    P1   P2    Lc    (AuthDataBytes             key nr )
                    response = self.sendcmd(cla_ins+[0x00,0x00, 0x05]+[0x01, 0x00]+block+keytype+[0x00])

                    return response

                else:
                    return respone
     


        
    def readblock(self, card, sector, block):
       
#       actuple = card.sector[sector].actuple_get(block)

        if self.readertype == READER_PCSC:
            if self.readersubtype == READER_ACS and self.args['native']:
                response = self.acs_authenticate(block,keytype,key)
                if response[0][:3] == [0xD5, 0x41, 0x00]:
                    read = hex2bytes(PCSC_APDU['ACS_READ_MIFARE'])+block
                    response = self.sendcmdnative( hex2bytes(PCSC_APDU['ACS_DIRECT_TRANSMIT'])+[len(read)]+read  ) 
                return response 
            if self.readersubtype == READER_OMNIKEY or not self.args['native']:      
                response = self.authenticate(block,keytype,key)

                if response[-2:] == (0x90,0x00):
                    cla_ins = hex2bytes(PCSC_APDU['READ_BLOCK'])
                    response = self.sendcmd(cla_ins+[0x00]+block+[self.cardblocksize])
                    return response

                else:
                    return response

    def writeblock(self, card, sector, block, data):
        


        if self.readertype == READER_PCSC:
            if self.readersubtype == READER_ACS and self.args['native']:
                response = self.acs_authenticate(block,keytype,key)
                if response[0][:3] == [0xD5, 0x41, 0x00]:
                    write = hex2bytes(PCSC_APDU['ACS_WRITE_MIFARE'])+block+data
                    response = self.sendcmdnative( hex2bytes(PCSC_APDU['ACS_DIRECT_TRANSMIT'])+[len(write)]+write  ) 
                return response 
            if self.readersubtype == READER_OMNIKEY or not self.args['native']:      
                response = self.authenticate(block,keytype,key)
                
                if response[-2:] == (0x90,0x00):
                    cla_ins = hex2bytes(PCSC_APDU['UPDATE_BLOCK'])
                    response = self.sendcmd(cla_ins+[0x00]+block+[self.cardblocksize]+data)

                    return response
                else:
                    return response


    def spawnshell(self):
        while True:
            try:
                cmd = raw_input('<< ')
                if cmd:
                    self.sendcmd(hex2bytes(cmd))
                    
            except KeyboardInterrupt:
                sys.exit(0)

class CardObserverExt(CardObserver):

    def __init__(self):
        CardObserver.__init__(self)
        self.cardshell = None

    def update(self, observable, (addedcards, removedcards)):
        for card in addedcards:
            #print observable.__name__
            #card.__dict__()
            print "\n+Inserted: ", toHexString(card.atr)
            #self.cardshell = CardShell(card)
        for card in removedcards:
            print "\n-Removed: ", toHexString(card.atr)
            sys.exit(0)

class RunAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        print '%r %r %r' % (namespace, values, option_string)
        setattr(namespace, self.dest, values)

if __name__=='__main__':
    parser = argparse.ArgumentParser(description='Operates on Mifare Classic tag')
    groupact = parser.add_mutually_exclusive_group(required=True)
    groupact.add_argument('-a','--action', nargs='?', choices=['read','write','ac'], help='Action to take, read/write, read AC')
    groupact.add_argument('-i','--interactive', const=True, action='store_const', help='Interactive mode (shell)' )

    groupinput = parser.add_mutually_exclusive_group(required=False)
    groupinput.add_argument('-f','--infile', nargs='?',default=argparse.SUPPRESS, help='FILE MODE, takes keys (and data) from file')
    groupinput.add_argument('-l','--line', const=True, action='store_const' ,default=argparse.SUPPRESS, help='LINE MODE, takes input from line')
    groupinput.add_argument('-s','--stupid', default=argparse.SUPPRESS , help='STUPID MODE, Check all default keys and read possibly whole card content and put in specified FILE.')
    parser.add_argument('-o','--output', nargs='?', default=argparse.SUPPRESS, help='FILE MODE output file for "data read" OR "data write result"' )


    groupauth = parser.add_argument_group('groupauth', 'authentication group')
    groupauth.add_argument('-b','--block', nargs='?',  default=argparse.SUPPRESS, help='block (in hex)')
    groupauth.add_argument('-k','--key', nargs='?',  default=argparse.SUPPRESS, help='authetication key (in hex)')
    groupauth.add_argument('-kt','--keytype', nargs='?',  default=argparse.SUPPRESS, help='authetication keytype (A/B)',choices=['A','B'])
    parser.add_argument('-d','--data', default=argparse.SUPPRESS, help='data to be written in ascii or hex' )

    parser.add_argument('-n','--native', const=True, action='store_const', help='turn on NATIVE MODE if reader has one (like ACR122U)' )
    args = parser.parse_args()

    print args.__dict__
    CardServer(args.__dict__).start()

