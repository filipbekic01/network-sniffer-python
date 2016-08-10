import socket
import sys
import struct
import os


class Sniffer:
    def main(self):
        # the public network interface
        HOST = socket.gethostbyname(socket.gethostname())

        # create a raw socket and bind it to the public interface
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((HOST, 0)) # ip like 192.168.1.1

        # Include IP headers
        s.setsockopt(socket.IPPROTO_TCP, socket.IP_HDRINCL, 1)

        # receive all packages
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        # receive a package
        # os.system('cls')
        data = self.getData(s)
        # get the IP header (the first 20 bytes) and unpack them
        # ! - network
        # B - unsigned char (1 byte)
        # H - unsigned short (2 bytes)
        # s - string
        unpackedData = struct.unpack('!BBHHHBBH4s4s', data[:20])
        info = {
            '[4 bits]  Version': self.getVersion(unpackedData),
            '[4 bits]  IHL': self.getIHL(unpackedData),
            '[8 bits]  Type of Services': self.getTypeOfService(unpackedData),
            '[16 bits] Total Length': unpackedData[2],
            '[16 bits] Identification': unpackedData[3],
            '[3 bits]  Flags': self.getFlags(unpackedData),
            '[13 bits] Fragment Offset': unpackedData[4] & 0x1FFF,
            '[8 bits]  Time to Live (TTL)': str(unpackedData[5]),
            '[8 bits]  Protocol': self.getProtocol(unpackedData[6]),
            '[16 bits] Checksum': str(unpackedData[7]),
            '[32 bits] Source Address': socket.inet_ntoa(unpackedData[8]),
            '[32 bits] Destination Address': socket.inet_ntoa(unpackedData[9]),
            '[rest]    Payload': data[20:]
        }



        '''
        for key, value in info.items():
            print '\033[92m' + key + '\033[0m'
            if key == '[8 bit]  Type of Services':
                for key1, value1 in value.iteritems():
                    print "  " + key1 + ": " + value1
            else:
                print "  " + str(value)
        '''

        # disabled promiscuous mode
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

    def getData(self, s):
        data = ''
        try:
            data = s.recvfrom(65565)
        except socket.timeout:
            data = ''
        except:
            print 'An error happened'
            # exit program
            sys.exc_info()
        return data[0]

    # 4 bits
    def getVersion(self, unpackedData):
        version_IHL = unpackedData[0]
        # shift to the right (example: 01000101 => 0000 0100) which is 4 (IP Internet Protocol)
        version = version_IHL >> 4
        versions = {
            0: '[0] Reserved.',
            1: '[1]',
            2: '[2]',
            3: '[3]',
            4: '[4] IP, Internet Protocol.',
            5: '[5] ST, ST Datagram Mode.',
            6: '[6] SIP, Simple Internet Protocol. SIPP, Simple Internet Protocol Plus. IPv6, Internet Protocol.',
            7: '[7] TP/IX, The Next Internet.',
            8: '[8] PIP, The P Internet Protocol.',
            9: '[9] TUBA.',
            10: '[10]',
            11: '[11]',
            12: '[12]',
            13: '[13] ',
            14: '[14]',
            15: '[15] Reserved.'
        }
        return versions[version]

    # 4 bits
    def getIHL(self, unpackedData):
        version_IHL = unpackedData[0]
        return version_IHL & 0xF

    # 8 bits
    def getTypeOfService(self, unpackedData):
        data = unpackedData[1]
        precedence = {
            0: '[0] Routine',
            1: '[1] Priority',
            2: '[2] Immediate',
            3: '[3] Flash',
            4: '[4] Flash override',
            5: '[5] CRITIC/ECP',
            6: '[6] Internetwork control',
            7: '[7] Network control'
        }
        delay = {0: '[0] Normal delay', 1: '[1] Low delay'}
        throughput = {0: '[0] Normal throughput', 1: '[1] High throughput'}
        reliability = {0: '[0] Normal reliability', 1: '[1] High reliability'}
        monetary_cost = {0: '[0] Normal monetary cost', 1: '[1] Minimize monetary cost'}
        d = data & 0x10
        t = data & 0x8
        r = data & 0x4
        m = data & 0x2
        result = {
            'precedence': precedence[data >> 5],
            'delay': delay[d >> 4],
            'throughput': throughput[t >> 3],
            'reliability': reliability[r >> 2],
            'monetary_cost': monetary_cost[m >> 1]
        }
        return result

    # 3 bits
    def getFlags(self, unpackedData):
        data = unpackedData[4]
        flagR = {0: "[0] Reserved bit"}
        flagDF = {0: "[0] Fragment if necessary", 1: "[1] Do not fragment"}
        flagMF = {0: "[0] Last fragment", 1: "[1] More fragments"}
        #   get the 1st bit and shift right
        R = data & 0x8000
        R >>= 15
        #   get the 2nd bit and shift right
        DF = data & 0x4000
        DF >>= 14
        #   get the 3rd bit and shift right
        MF = data & 0x2000
        MF >>= 13
        result = {
            'R': flagR[R],
            'DF': flagDF[DF],
            'MF': flagMF[MF]
        }
        return result

    # 8 bits
    def getProtocol(self, protocolId):
        pfile = open('protocols', 'r')
        pdata = pfile.readlines()
        for line in pdata:
            exploded_line = line.split('\t')
            exploded_line[1] = exploded_line[1].replace('\n', '')
            if (int(exploded_line[0]) == protocolId):
                return exploded_line[1]


if __name__ == "__main__":
    sniffer = Sniffer()
    while True:
        sniffer.main()
