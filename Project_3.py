import os
from socket import *
import struct
import time
import select


class IcmpHelperLibrary:
    class IcmpPacket:
        __icmpTarget = ""  # Remote Host
        __destinationIpAddress = ""  # Remote Host IP Address
        __header = b''  # Header after byte packing
        __data = b''  # Data after encoding
        __dataRaw = ""  # Raw string data before encoding
        __icmpType = 0  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        __ttl = 255  # Time to live

        __DEBUG_IcmpPacket = False  # Allows for debug output

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            # print statement runs if DEBUG is true if not, nothing happens
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            # at this point the header data and the actual data have been converted into byte stream
            # so they are now added together by using a join on an empty bytes string
            packetAsByteData = b''.join([self.__header, self.__data])
            # set checksum to 0
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff  # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff  # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)  # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum  # Rotate and add

            answer = ~checksum  # Invert bits
            answer = answer & 0xffff  # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits

            # this function converts all these python data passed into the struct.pack() into a byte stream because
            # python does not have a byte type where the string is equal to a byte stream or a byte array,
            # so we do this to convert it to a byte stream. ! indicates it wants it in network byte order which is
            # big endian, B is an unsigned char(1 byte) in C from an int in python, H is an unsigned short (2 bytes)
            # in C from an integer in Python
            self.__header = struct.pack("!BBHHH",
                                        self.getIcmpType(),  # 8 bits / 1 byte  / Format code B
                                        self.getIcmpCode(),  # 8 bits / 1 byte  / Format code B
                                        self.getPacketChecksum(),  # 16 bits / 2 bytes / Format code H
                                        self.getPacketIdentifier(),  # 16 bits / 2 bytes / Format code H
                                        self.getPacketSequenceNumber()  # 16 bits / 2 bytes / Format code H
                                        )

        def __encodeData(self):
            # d is a double (8 bytes) in c from a float in python
            data_time = struct.pack("d", time.time())  # Used to track overall round trip time
            # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()  # packHeader() and encodeData() transfer data to their respective bit
            # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()  # Result will set new checksum value
            self.__packHeader()  # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Hint: Work through comparing each value and identify if this is a valid response.
            # checks if sequence number, identified, and data of packet echoed back is the
            # same as current self packet

            # checks valid type if not valid prints out bug message
            if 0 == icmpReplyPacket.getIcmpType():
                icmpReplyPacket.setIsValidType(True)
            else:
                print("Expected Type: %d, type received: %d" % (self.getIcmpType(), icmpReplyPacket.getIcmpType()))

            # checks valid code if not valid prints out bug message
            if self.getIcmpCode() == icmpReplyPacket.getIcmpCode():
                icmpReplyPacket.setIsValidCode(True)
            else:
                print("Expected Code: %d, code received: %d" % (self.getIcmpCode(), icmpReplyPacket.getIcmpCode()))

            # checks valid checksum if not valid prints out bug message
            if self.getPacketChecksum() + 2048 == icmpReplyPacket.getIcmpHeaderChecksum():
                icmpReplyPacket.setIsValidHeaderChecksum(True)
            else:
                print("Expected checksum: %d, checksum received: %d" % (
                self.getPacketChecksum() + 2048, icmpReplyPacket.getIcmpHeaderChecksum()))

            # checks valid identifier if not valid prints out bug message
            if self.getPacketIdentifier() == icmpReplyPacket.getIcmpIdentifier():
                icmpReplyPacket.setIsValidIdentifier(True)
            else:
                print("Expected checksum: %d, checksum received: %d" % (
                self.getPacketIdentifier(), icmpReplyPacket.getIcmpIdentifier()))

            # checks valid sequence number if not valid prints out bug message
            if self.getPacketSequenceNumber() == icmpReplyPacket.getIcmpSequenceNumber():
                icmpReplyPacket.setIsValidSequenceNumber(True)
            else:
                print("Expected sequence number: %d, sequence number received: %d" % (
                    self.getPacketSequenceNumber(), icmpReplyPacket.getIcmpSequenceNumber()))

            # checks valid data if not valid prints out bug message
            if self.getDataRaw() == icmpReplyPacket.getIcmpData():
                icmpReplyPacket.setIsValidIcmpData(True)
            else:
                print("Expected data: %s, data received: %s" % (
                    self.getDataRaw(), icmpReplyPacket.getIcmpData()))

            if icmpReplyPacket.getIsValidSequenceNumber() and icmpReplyPacket.getIsValidIdentifier() \
                    and icmpReplyPacket.getIsValidIcmpData():
                icmpReplyPacket.setIsValidResponse(True)
            else:
                icmpReplyPacket.setIsValidResponse(False)

        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)  # set Icmp type to 8
            self.setIcmpCode(0)  # set Icmp code to 0
            self.setPacketIdentifier(packetIdentifier)  # set packet identifier to pid, all packets will be the same #
            self.setPacketSequenceNumber(packetSequenceNumber)  # set sequence number to one of 0 - 3 since 4 packets
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"  # set data to this string
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self, stats):
            # if there is no source ip or destination ip then set target IP to "127.0.0.1"
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)
            # stats used for calculating minimum and max, avg, and packet loss
            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]

                    if icmpType == 11:  # Time Exceeded
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                              (
                                  self.getTtl(),
                                  (timeReceived - pingStartTime) * 1000,
                                  icmpType,
                                  icmpCode,
                                  addr[0]
                              )
                              )

                    elif icmpType == 3:  # Destination Unreachable
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                              (
                                  self.getTtl(),
                                  (timeReceived - pingStartTime) * 1000,
                                  icmpType,
                                  icmpCode,
                                  addr[0]
                              )
                              )


                    elif icmpType == 0:  # Echo Reply
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr, self, stats)
                        return  # Echo reply is the end and therefore should return

                    else:
                        print("error")
            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
            finally:

                mySocket.close()

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i + 1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False

        __IcmpType_isValid = False
        __IcmpCode_isValid = False
        __IcmpHeaderChecksum_isValid = False
        __IcmpIdentifier_isValid = False
        __IcmpSequenceNumber_isValid = False
        __IcmpData_isValid = False

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)  # Used to track overall round trip time
            # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse

        def getIsValidType(self):
            return self.__IcmpType_isValid

        def getIsValidCode(self):
            return self.__IcmpCode_isValid

        def getIsValidHeaderChecksum(self):
            return self.__IcmpHeaderChecksum_isValid

        def getIsValidIdentifier(self):
            return self.__IcmpIdentifier_isValid

        def getIsValidSequenceNumber(self):
            return self.__IcmpSequenceNumber_isValid

        def getIsValidIcmpData(self):
            return self.__IcmpData_isValid

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        def setIsValidType(self, boolVal):
            self.__IcmpType_isValid = boolVal

        def setIsValidCode(self, boolVal):
            self.__IcmpCode_isValid = boolVal

        def setIsValidHeaderChecksum(self, boolVal):
            self.__IcmpHeaderChecksum_isValid = boolVal

        def setIsValidIdentifier(self, boolVal):
            self.__IcmpIdentifier_isValid = boolVal

        def setIsValidSequenceNumber(self, boolVal):
            self.__IcmpSequenceNumber_isValid = boolVal

        def setIsValidIcmpData(self, boolVal):
            self.__IcmpData_isValid = boolVal

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #

        def printResultToConsole(self, ttl, timeReceived, addr, sentPacket, stats):

            # if data is not valid print bug message for that specific data
            if not self.getIsValidType():
                print("Type Bug: Expected: %d, Received: %d" % (0, self.getIcmpCode()))
            if not self.getIsValidCode():
                print("Code Bug: Expected: %d, Received: %d" % (sentPacket.getIcmpCode(), self.getIcmpCode()))
            if not self.getIsValidHeaderChecksum():
                print("Checksum Bug: Expected: %s, Received: %s" % (
                sentPacket.getPacketChecksum() + 2048, self.getIcmpHeaderChecksum()))
            if not self.getIsValidIdentifier():
                print("Identifier Bug: Expected: %d, Received: %d" % (
                sentPacket.getPacketIdentifier(), self.getIcmpIdentifier()))
            if not self.getIsValidSequenceNumber():
                print("Sequence Number Bug: Expected: %d, Received: %d" % (
                sentPacket.getPacketSequenceNumber(), self.getIcmpSequenceNumber()))
            if not self.getIsValidIcmpData():
                print("Data Bug: Expected: %d, Received: %d" % (sentPacket.getDataRaw(), self.getIcmpData()))

            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d        Identifier=%d    Sequence Number=%d    %s" %
                  (
                      ttl,
                      (timeReceived - timeSent) * 1000,
                      self.getIcmpType(),
                      self.getIcmpCode(),
                      self.getIcmpIdentifier(),
                      self.getIcmpSequenceNumber(),
                      addr[0]
                  )
                  )
            if stats[0] > (timeReceived - timeSent) * 1000:
                stats[0] = (timeReceived - timeSent) * 1000
            if stats[1] < (timeReceived - timeSent) * 1000:
                stats[1] = (timeReceived - timeSent) * 1000
            stats[2] = stats[2] + (timeReceived - timeSent) * 1000
            stats[3] += 1

    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host):
        # host is the target IP from main

        # if the DEBUG variable is true then print the print statement else do nothing
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        stats = [1000000, 0, 0, 0]
        # loop 4 times with i values (0, 1, 2, 3)
        for i in range(4):
            # create icmp packet which is a class inside the IcmpHelper class. This function is currently inside the
            # Icmp echo reply class
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            # gets current process id as a 16 bit numbers
            randomIdentifier = (os.getpid() & 0xffff)  # Get as 16 bit number - Limit based on ICMP header standards
            # Some PIDs are larger than 16 bit

            # set packetIdentifier to that current process number
            packetIdentifier = randomIdentifier
            # set packetSequence number to current i value (0, 1, 2, 3)
            packetSequenceNumber = i

            # calls the IcmpPacket class function buildPacket_echoRequest and passes in the packer identifier (PID)
            # and passes in the packet sequence numbers which is "i" in the for loop.
            # sets Icmp type and code to 8 and 0
            # sets the packets identifier and sequence number to argurments passed in
            # sets the data to random string (same for every Icmp packet)
            # calls recalculate check sum function
            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)

            icmpPacket.sendEchoRequest(stats)  # Build IP
            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data

        # prints out resulting end values
        print("Packet sent %d, received: %d, lost %d (Percentage: %.0f%%)" % (
            4, stats[3], 4 - stats[3], (stats[3] / 4) * 100))
        print("Minimum: %dms, Maximum: %dms, Average: %dms" % (stats[0], stats[1], stats[2]/stats[3]))

    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        # Build code for trace route here

    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost):
        # if __DEBUG_IcmpHelperLibrary is true, then print ping started else do nothing
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        # calls the send ICMP echo request function with the target IP as the argument
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()

    # Choose one of the following by uncommenting out the line
    icmpHelperPing.sendPing("209.233.126.254")
    # icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("oregonstate.edu")
    # icmpHelperPing.sendPing("gaia.cs.umass.edu")
    # icmpHelperPing.traceRoute("oregonstate.edu")


if __name__ == "__main__":
    main()
