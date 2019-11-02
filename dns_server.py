import sys
import socket
from easyzone import easyzone
from easyzone.zone_check import ZoneCheck
import ipaddress
import struct
import time



rootDnsIndex = 1
rootDnsServers = ['192.58.128.30', '192.203.230.10', '192.228.79.201', '192.33.4.12', '199.7.91.13', '192.5.5.241', '198.41.0.4'
'192.112.36.4', '128.63.2.53', '192.36.148.17', '193.0.14.129', '199.7.83.42', '202.12.27.33']

caching = dict()

def getOpcode(byte):
    temp = 2
    res = ''
    for _ in range (0,4):
        res += str(ord(byte) & temp)
        temp = temp * 2
    return res

def getRespFlags(reqFlags):
    
    qr = '1'
    opcode = getOpcode(bytes(reqFlags[:1]))
    aa = '1'
    tc = '0'
    rd = '0'
    ra = '1'
    z = '000'
    rcode = '0000'

    firstByte = qr + opcode + aa + tc + rd
    secondByte = ra + z + rcode
    return int(firstByte, 2).to_bytes(1, 'big') + int(secondByte, 2).to_bytes(1, 'big')

def getDomainAndQType(data):
    res = ""
    index = 12
    length = data[index]
    while length != 0:
        curr = str(data[index + 1 : index + length + 1])
        res += curr[2:len(curr)-1] + "."
        index += length + 1
        length = data[index]

    qtype = data[index + 1 : index + 3]
    return (res[:len(res) - 1], qtype)

def qtypeValue(qtype):

    if qtype == (1).to_bytes(2, 'big'):
        return 'A'
    elif qtype == (2).to_bytes(2, 'big'):
        return 'NS'
    elif qtype == (15).to_bytes(2, 'big'):
        return 'MX'
    elif qtype == (16).to_bytes(2, 'big'):
        return 'TXT'
    elif qtype == (5).to_bytes(2, 'big'):
        return 'CNAME'
    elif qtype == (6).to_bytes(2, 'big'):
        return 'SOA'
    elif qtype == (28).to_bytes(2, 'big'):
        return 'AAAA'

    return 'NULL'

def getDomainbytes(domain):
    res = b''
    if domain[-1] == '.':
        domain = domain[:-1]
    domainArr = domain.split('.')

    for curr in domainArr:
        res += bytes([len(curr)])

        for ch in curr:
            res += ord(ch).to_bytes(1, 'big')

    res += bytes([0])
    return res

def lengthAndData(item, qtypeValue, ttl, domain):
    res = b''
    if qtypeValue == 'A':
        res += (4).to_bytes(2, 'big')
        res += ipaddress.IPv4Address(item).packed
        print(domain + '   '+str(ttl)+'  IN   ' + qtypeValue + '   ' + item)

    elif qtypeValue == 'NS':
        res += (len(item) + 1).to_bytes(2, 'big')
        res += getDomainbytes(item)
        print(domain + '   '+str(ttl)+'  IN   ' + qtypeValue + '   ' + item)

    elif qtypeValue == 'MX':
        res += (len(item[1]) + 3).to_bytes(2, 'big')
        res += item[0].to_bytes(2, 'big')
        res += getDomainbytes(item[1])
        print(domain + '   '+str(ttl)+'  IN   ' + qtypeValue + '   ' + str(item[0]) + ' ' + item[1])

    elif qtypeValue == 'TXT':
        res += (len(item) - 1).to_bytes(2, 'big')
        res += (len(item) - 2).to_bytes(1, 'big')
        for ch in item[1:-1]:
            res += ord(ch).to_bytes(1, 'big')
        print(domain + '   '+str(ttl)+'  IN   ' + qtypeValue + '   ' + item)

    elif qtypeValue == 'CNAME':
        res += (len(item) + 1).to_bytes(2, 'big')
        res += getDomainbytes(item)
        print(domain + '   '+str(ttl)+'  IN   ' + qtypeValue + '   ' + item)

    elif qtypeValue == 'SOA':
        itemList = item.split(' ')
        res += (20 + len(itemList[0]) + 1 + len(itemList[1])+ 1).to_bytes(2, 'big')
        res += getDomainbytes(itemList[0])
        res += getDomainbytes(itemList[1])
        res += int(itemList[2]).to_bytes(4, 'big')
        res += int(itemList[3]).to_bytes(4, 'big')
        res += int(itemList[4]).to_bytes(4, 'big')
        res += int(itemList[5]).to_bytes(4, 'big')
        res += int(itemList[6]).to_bytes(4, 'big')
        print(domain + '   '+str(ttl)+'  IN   ' + qtypeValue + '   ' + item)
    elif qtypeValue == 'AAAA':
        res += (16).to_bytes(2, 'big')
        res += ipaddress.IPv6Address(item).packed
        print(domain + '   '+str(ttl)+'  IN   ' + qtypeValue + '   ' + item)

    return res


def hasAnswerSection(response):
    answersNumber , = struct.unpack('>H', bytes(response[6:8]))
    return answersNumber > 0

def recReconrdSearch(response, index):

    length = response[index]
    if length & 192 == 192:
        offset, = struct.unpack('>H', bytes(response[index:index + 2]))
        offset = offset ^ 49152

        return recReconrdSearch(response, offset)
    
    currRes = ''
    while length != 0:
        curr = str(response[index + 1: index + length + 1])
        currRes += curr[2:len(curr)-1] + "."
        index += length + 1
        length = response[index]

        if length & 192 == 192:
            offset, = struct.unpack('>H', bytes(response[index:index + 2]))
            offset = offset ^ 49152

            currRes += recReconrdSearch(response, offset)
            
            break
       
    return currRes

def getNsRecords(response, domain):
    question, answersNumber, nscount, arcount  = struct.unpack('>HHHH', bytes(response[4:12]))
    
    res = []
    index = 12
    if domain[-1] == '.':
        domain = domain[:-1]
    index += len(domain) + 6

    for _ in range (0, nscount):
        index += 6

        index += 4
        rdlength, = struct.unpack('>H', bytes(response[index:index + 2]))
        index += 2

        currRes = recReconrdSearch(response, index)
        res.append(currRes)
        index += rdlength


    return (res, index)

def getIp(data):
    return str(data[0]) + '.' + str(data[1]) + '.' + str(data[2]) + '.' + str(data[3])

def getAddRecords(response, index):
    res = dict()
    question, answersNumber, nscount, arcount  = struct.unpack('>HHHH', bytes(response[4:12]))

    for _ in range(0, arcount - 1):
        name = recReconrdSearch(response, index)
        index += 2
        qtype , = struct.unpack('>H', bytes(response[index:index + 2]))
        index += 8
        rdlength, = struct.unpack('>H', bytes(response[index:index + 2]))
        index += 2

        if qtypeValue(qtype.to_bytes(2, 'big')) == 'A':
            
            res[name] = getIp(response[index:index + rdlength])
        
        
        index += rdlength


    return res

def createRequest(nsRecord, response):

    #Transaction id
    tranID = (3).to_bytes(2, 'big')

    zero = 0
    flags = (zero).to_bytes(2, 'big')
    

    one = 1
    qdcount = one.to_bytes(2,'big')

    ancount = zero.to_bytes(2, 'big')
    nscount = zero.to_bytes(2, 'big')
    arcount = zero.to_bytes(2, 'big')

    #question
    question = b''
    if nsRecord[-1] == '.':
        nsRecord = nsRecord[:-1]
    question += getDomainbytes(nsRecord)

    #add qtype and class
    question += (one).to_bytes(2, 'big')
    question += one.to_bytes(2,'big')

    header = tranID + flags + qdcount + ancount + nscount + arcount
    
    return header + question


def getIpsFromResp(data, domain):
    
    question, answersNumber, nscount, arcount  = struct.unpack('>HHHH', bytes(data[4:12]))
    res = []
    index = 12

    if domain[-1] == '.':
        domain = domain[:-1]
    index += len(domain) + 6

    for _ in range(0, answersNumber):
        index += 2
        
        qtype , = struct.unpack('>H', bytes(data[index:index + 2]))
        index += 8
        
        rdlength, = struct.unpack('>H', bytes(data[index:index + 2]))

        index += 2

        if qtypeValue(qtype.to_bytes(2, 'big')) == 'A':            
            res.append(getIp(data[index:index + rdlength]))
        
        index += rdlength
    
    return res

def logAnswerSection(data, domain):

    question, answersNumber, nscount, arcount  = struct.unpack('>HHHH', bytes(data[4:12]))
    if answersNumber <= 0:
        return
    print(';; Answer SECTION:')
    
    index = 12
    if domain[-1] == '.':
        domain = domain[:-1]
    index += len(domain) + 6

    for _ in range(0, answersNumber):
        
        index += 2
        
        qtype , = struct.unpack('>H', bytes(data[index:index + 2]))
        index += 4
        
        ttl, = struct.unpack('>I', bytes(data[index:index + 4]))
        index +=4

        rdlength, = struct.unpack('>H', bytes(data[index:index + 2]))



        index += 2
        print(domain + '   '+ str(ttl) +'  IN   ' + qtypeValue(qtype.to_bytes(2, 'big')) + '   ' + getIp(data[index:index + rdlength]))
        
        index += rdlength

def getTtl(data, domain):
    try:
        question, answersNumber, nscount, arcount  = struct.unpack('>HHHH', bytes(data[4:12]))
        if answersNumber <= 0:
            return

        index = 12
        if domain[-1] == '.':
            domain = domain[:-1]
        index += len(domain) + 6


        for _ in range(0, answersNumber):
            
            try:
                index += 6
                
                ttl, = struct.unpack('>I', bytes(data[index:index + 4]))

                return ttl + 1000
            except expression as identifier:
                break

    except expression as identifier:
        return 10000
    
def recSearchResult(data, roots, currIps):
    global rootDnsIndex

    (domain, qtype) = getDomainAndQType(data)
    
    if (domain, qtype) in caching:
        currTime = int(round(time.time() * 1000))

        ttl = getTtl(caching[(domain, qtype)][0], domain)
        if currTime - caching[(domain, qtype)][1] < ttl:
            return (data[:2] + caching[(domain, qtype)][0][2:], True)

    for curr in currIps:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


        server_address = (curr, 53)
        try:
            # Send data
            sock.sendto(data, server_address)

            # Receive response
            sock.settimeout(2)
            response, server = sock.recvfrom(4096)


            if hasAnswerSection(response):
                print(';; QUESTION SECTION:')
                print(domain + '         IN     ' + qtypeValue(qtype)  + '   ' + curr)
                caching[(domain, qtype)] = (response, int(round(time.time() * 1000)))
                logAnswerSection(response, domain)
                return (response, True)


            NSRecords, index = getNsRecords(response, domain)
            AdditionalRecords = getAddRecords(response, index)
            
            for currNsRecord in NSRecords:
                if currNsRecord in AdditionalRecords:
                    res = recSearchResult(data, roots, [AdditionalRecords[currNsRecord]])
                    if res[1]:
                        print(';; QUESTION SECTION:')
                        print(domain + '         IN     ' + qtypeValue(qtype)  + '   ' + curr)
                        caching[(domain, qtype)] = (res[0], int(round(time.time() * 1000)))
                        logAnswerSection(response, domain)
                        return res
                else:
                    request = createRequest(currNsRecord, response)
                    rsRes = recSearchResult(request, roots, roots)
                    if rsRes[1]:
                        foundIps = getIpsFromResp(rsRes[0], currNsRecord)
                        res = recSearchResult(data, roots, foundIps)
                        if res[1]:
                            print(';; QUESTION SECTION:')
                            print(domain + '         IN     ' + qtypeValue(qtype)  + '   ' + curr)
                            caching[(domain, qtype)] = (res[0], int(round(time.time() * 1000)))
                            logAnswerSection(response, domain)
                            return res

        except Exception:
            pass
        finally:
            sock.close()

    return (data, False)

def makeResponse(data, config):

    #Transaction id
    tranID = bytes(data[0:2])

    # Flags
    reqflags = data[2:4]
    responseFlags = getRespFlags(reqflags)

    # QDCOUNT
    one = 1
    qdcount = one.to_bytes(2,'big')

    # NSCOUNT AND ARCOUNT
    zero = 0
    nscount = zero.to_bytes(2, 'big')
    arcount = zero.to_bytes(2, 'big')

    # Domain and Question type
    (domain, qtype) = getDomainAndQType(data)


    try:
        z = easyzone.zone_from_file(domain, config + 'example.com.conf')

        # finish dns header
        ancount = len(z.root.records(qtypeValue(qtype)).items).to_bytes(2, 'big')
        header = tranID + responseFlags + qdcount + ancount + nscount + arcount

        # build question
        question = b''
        question += getDomainbytes(domain)
        print(';; QUESTION SECTION:')
        print(domain + '         IN   ' + qtypeValue(qtype))

        #add qtype and class
        question += qtype
        question += one.to_bytes(2,'big')

        #build body
        body = b''

        print(';; ANSWER SECTION:')
        for item in z.root.records(qtypeValue(qtype)).items:
            body += b'\xc0\x0c'
            body += qtype
            body += one.to_bytes(2,'big')
            ttl = 1800
            body += (ttl).to_bytes(4,'big')
            body += lengthAndData(item, qtypeValue(qtype), ttl, domain)


        return header + question + body
    except:
        pass


    
    return recSearchResult(data, rootDnsServers, rootDnsServers)[0]




def run_dns_server(CONFIG, IP, PORT):
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind the socket to the port
    server_address = (IP, int(PORT))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)

    while True:
        data, address = sock.recvfrom(512)
        response = makeResponse(data, CONFIG)
        sock.sendto(response, address)



# do not change!
if __name__ == '__main__':
    CONFIG = sys.argv[1]
    IP = sys.argv[2]
    PORT = sys.argv[3]
    run_dns_server(CONFIG, IP, PORT)