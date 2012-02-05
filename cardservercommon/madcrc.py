#CRC_PRESET=0xc7
CRC_PRESET=0xe3

SECTOR_0X00_AIDS=15
SECTOR_0X10_AIDS=23

def nxp_crc (crc, value):
    # x^8 + x^4 + x^3 + x^2 + 1 => 0x11d  (look at AN107870.pdf)
    poly = 0x1d;

    crc ^= value;
    for current_bit in range(7,-1,-1):
        bit_out = (crc) & 0x80
        print "przedCRC=",crc
        crc <<= 1
        crc %= 256
        print "CRC     =",crc
        if bit_out:
            crc ^= poly
    return crc


def sector_0x00_crc8 (data):
    crc = CRC_PRESET;

    crc = nxp_crc (crc, data[0])
    for n in range(1,SECTOR_0X00_AIDS+1,2):
        print "data[n+1]", data[n+1]
        print "data[n]", data[n]
        crc = nxp_crc (crc, data[n+1])
        crc = nxp_crc (crc, data[n])
 
    return crc

def sector_0x10_crc8 (data):
    crc = CRC_PRESET;

    crc = nxp_crc (crc, data[0])
    for n in range(1,SECTOR_0X10_AIDS+1,2):
        crc = nxp_crc (crc, data[n+1])
        crc = nxp_crc (crc, data[n])

    return crc
