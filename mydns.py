#STUDENT ID: 5847813
#STUDENT NAME: BILL LIZA
#CNT4713 - PROJECT 2 2020

import socket, glob, json

port = 53
ip = '127.0.0.1'
#DNS operates on port 53 by default

sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.bind((ip,port))


def load_zones():
    jsonzone = {}
    zonefiles = glob.glob('zones/*.zone')
    for zone in zonefiles:
        with open(zone) as zoneData:
            data = json.load(zoneData)
            zonename = data["$origin"]
            jsonzone[zonename] = data
    return jsonzone


zoneData = load_zones()

def getFlags(flags):

    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:2])
    rflags = ''

    QR = '1'
    OPCODE = ''

    for bit in range(1,5):
        OPCODE += str(ord(byte1)&(1<<bit)) 

    AA='1'    
    TC = '0'
    RD = '0'
    RA = '0'
    Z = '000'
    RCODE = '0000'

    return int(QR+OPCODE+AA+TC+RD,2).to_bytes(1,byteorder='big')+int(RA+Z+RCODE,2).to_bytes(1,byteorder='big')

def getquestiondomain(data):
    state = 0
    expectedLength = 0
    domainString = ''
    domainParts = []
    x=0
    y=0

    for byte in data:
        if state == 1:
            if byte != 0:
                domainString += chr(byte)
            x+=1
            if x == expectedLength:
                domainParts.append(domainString)
                domainString = ''
                state = 0
                x = 0

            if byte == 0:
                domainParts.append(domainString)
                break
            
        else:
            state = 1
            expectedLength = byte
        y+=1
    questiontype = data[y:y+2]

    return (domainParts, questiontype)

def getZone(domain):
    global zoneData

    zone_name = '.'.join(domain)
    return zoneData[zone_name] 

def getRecs(data):
    domain, questiontype = getquestiondomain(data)
    qt = ''
    if questiontype == b'\x00\x01':
        qt='a'

    zone = getZone(domain)
    return (zone[qt], qt, domain)

def buildQuestion(domainName, rectype):
    qbytes = b''

    for part in domainName:
        length = len(part)
        qbytes += bytes([length])
         
        for char in part:
            qbytes += ord(char).to_bytes(1,byteorder='big')

        if rectype == 'a':
            qbytes += (1).to_bytes(2,byteorder='big')

        qbytes += (1).to_bytes(2,byteorder='big')
    
        return qbytes

def rectobytes(domainName,rectype,recttl, recval):
    rbytes= b'\xc0\x0c'

    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes += int(recttl).to_bytes(4,byteorder='big')
    
    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([4])

        for part in recval.split('.'):
            rbytes += bytes([int(part)])
    return rbytes

def buildResponse(data):

    TransactionID = data[:2]

    Flags = getFlags(data[2:4])

    #Question count
    QDCOUNT = b'\x00\x01'

    #Answer count
    ANCOUNT = len(getRecs(data[12:])[0]).to_bytes(2,byteorder='big')

    #Name server count
    NSCOUNT = (0).to_bytes(2,byteorder='big')

    #Additional count
    ARCOUNT = (0).to_bytes(2,byteorder='big')

    dnsheader = TransactionID+Flags+QDCOUNT+ANCOUNT+NSCOUNT+ARCOUNT

    dnsbody = b''

    #answer for query
    records, rectype, domainName = getRecs(data[12:])

    dnsquestion = buildQuestion(domainName, rectype)
    
    for record in records:
        dnsbody += rectobytes(domainName, rectype, record["ttl"], record["value"])

    return dnsheader + dnsquestion + dnsbody


while 1:
    data, addr = sock.recvfrom(512)
    r = buildResponse(data)
    sock.sendto(r,addr)