#-*- coding: utf-8 -*-
from scapy.all import *
import sys

interface = sys.argv[1]
my_mac_addr = get_if_hwaddr(interface)

HTTP_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10

def usage():
    print('syntax: python tcp_block.py [interface]')
    sys.exit(1)

def block(origin_pkt):
    if (Ether in origin_pkt) and (IP in origin_pkt):
        #본 패킷이 RST, FIN일 때
        if (origin_pkt[TCP].flags & RST() or (origin_pkt[TCP].flags & FIN):
            sendp(origin_pkt, iface = interface)
            return
        #본 패킷이 RST, FIN이 아닐 때
        fake_pkt = origin_pkt[Ether]/origin_pkt[IP]/origin_pkt[TCP]
        fake_pkt[TCP].remove_payload()
        del fake_pkt[TCP].chksum
        del fake_pkt[IP].chksum
        fake_pkt[Ether].src = my_mac_addr

        try:
            payload_len = len(origin_pkt[TCP].Raw)
        except:
            payload_len = 1

        fake_pkt[TCP].seq += payload_len
        fake_pkt[TCP].flags = RST | ACK
        #send fake packet to original destination
        sendp(fake_pkt, iface=interface)

        if ("HTTP" in str(origin_pkt)) and (origin_pkt[TCP].load.split()[0] in HTTP_METHODS):
            fake_pkt[TCP].flags = FIN | ACK
            fake_pkt = fake_pkt / "blocked\r\n"
            print("HTTP Packet Blocked")
        else:
            print("Not HTTP But TCP Packet Blocked")

        fake_pkt[Ether].dst                     = origin_pkt[Ether].src
        fake_pkt[IP].src,   fake_pkt[IP].dst    = origin_pkt[IP].dst, origin_pkt[IP].src
        fake_pkt[TCP].seq,  fake_pkt[TCP].ack   = origin_pkt[TCP].ack, origin_pkt[TCP].seq + payload_len
        #send fake packet to original source
        sendp(fake_pkt, iface=interface)

if __name__== "__main__":

    if len(sys.argv) != 2:
        usage()

    try:
        print('+++ TCP_BLOCK Running')
        print('+++ If you want to Quit, Press Ctrl-C')
        sniff(iface = interface, filter = 'tcp', prn = block)
    except KeyboardInterrupt:
        print('--- Server OUT....')
        sys.exit(1)
