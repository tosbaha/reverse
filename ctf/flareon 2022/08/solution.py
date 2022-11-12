#!/usr/bin/python
import socket
from dnslib import *

host = ''
port = 53
size = 512
cmds = [2,10,8,19,11,1,15,13,22,16,5,12,21,3,18,17,20,14,9,7,4]

def ipaddress(i,qname):
    # don't handle if domain doesn't include flare-on or we exhausted cmds
    if qname.find('flare-on') == -1 or i >= len(cmds) * 2: 
        return "127.0.0.1"   
    elif i == -1: # first subdomain request gets the agent id
        print("Sending 1 as agent id")
        return "129.0.0.1"
    elif i % 2 == 0: # return the length of the command
        cmd = cmds[i//2]
        length = len(str(cmd)) + 1
        print("Returning Length of [",cmd,"] length",length)
        return ("129.0.0.%d" % length)
    else: # return the command
        cmd = cmds[i//2]
        print("Sending cmd [",cmd,"]")
        ip = bytearray(str(cmd),'utf-8')
        ip  += bytes(3 - len(ip))
        return "43." + '.'.join(f'{c}' for c in ip)

if __name__ == "__main__":
    print("Flare-on Backdoor DNS started on port %d" % port)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((host, port))
    index = -1
    while True:
        try:
            data, addr = s.recvfrom(size)
            d = DNSRecord.parse(data)
            qname =  str(d.q.qname)
            q = DNSRecord(DNSHeader(id=d.header.id, qr=1, aa=1, ra=1), q=d.q)
            reply = q.reply()
            ip = ipaddress(index,qname)
            reply.add_answer(RR(qname, QTYPE.A,rdata=A(ip),ttl=0))
            if (qname.find("flare-on.com")) > 0:
                index += 1
            response_packet = reply.pack()
            s.sendto(response_packet, addr)
        except Exception as e:
            print(e)
