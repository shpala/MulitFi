from scapy.all import conf, Dot11, Ether, sendp
from fcntl import ioctl
import socket
import struct
import os

SIOCGIFFLAGS    = 0x8913
SIOCSIFFLAGS    = 0x8914
TUNSETIFF       = 0x400454ca
IFF_TAP         = 0x0002
IFF_UP          = 0x1

class Sniffer(object):

    
    def __init__(self, ifname):
        self.sock = conf.L2listen(filter='link[0x12]&0xff == 8 and (link[0x13]&0x42 == 2 or link[0x13]&0x41 == 1)', iface=ifname)
        self.if_count = 0
        self.bssid2if = {}

    def get_addrs(self, pkt):
        d11 = pkt.getlayer(Dot11)
        # to-DS
        if d11.FCfield == 1:
            return (d11.addr1, d11.addr2, d11.addr3)
        # from-DS
        else:
            return (d11.addr2, d11.addr3, d11.addr1)

    def ifup(self, ifname):
        ifsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        io_ret = ioctl(ifsock.fileno(), SIOCGIFFLAGS, struct.pack("18s", ifname))
        flags = struct.unpack('16sh', io_ret)[1]
        flags = flags | IFF_UP
        return ioctl(ifsock.fileno(), SIOCSIFFLAGS, struct.pack("16sh", ifname, flags))

    def recv_loop(self):
        while True:
            pkt = self.sock.recv(1234)
            addrs = self.get_addrs(pkt)
            bssid = addrs[0]
            if bssid not in self.bssid2if:
                tun_dev = os.open("/dev/net/tun", os.O_RDWR)
                self.bssid2if[bssid] = ioctl(tun_dev, TUNSETIFF, struct.pack("16sH", 'virt%d', IFF_TAP))[:16].strip("\x00")
                self.ifup(self.bssid2if[bssid])
            snap = pkt.getlayer('SNAP')
            new_pkt = Ether(src=addrs[1], dst=addrs[2], type=snap.code)/snap.payload
            print new_pkt.src, new_pkt.dst
            sendp(new_pkt, iface=self.bssid2if[bssid])

s = Sniffer('mon0')
s.recv_loop();
"""
class Link:
    def __init__(self,interfaceName):
       self.netDeviceFD = os.open("/dev/net/tun", os.O_RDWR)
       ifs = ioctl(self.netDeviceFD, TUNSETIFF, struct.pack("16sH", interfaceName, IFF_TAP))
       print "Using interface %s" % ifs[:16].strip("\x00")
       #packet = os.read(self.netDeviceFD,1500)
       #os.write(self.netDeviceFD, str(Ether(dst='00:0c:29:a6:5e:2f', src='00:0c:29:48:55:1f', type=0x0800)/ARP()))
"""
"""
def probe_req(ssid, iface):
    beacon_packet = RadioTap(version=0,pad=0,len=25,present='Flags+Rate+Channel+dBm_AntSignal+Antenna+b14',notdecoded='\x00\x00\x00\x00\x00\x00\x00\x00\x02\xa3\t\xa0\x00\xf1\x00\x00\x00')/\
        Dot11(subtype=4L, type='Management', proto=0L, FCfield=0, ID=0x0FFF, addr1='ff:ff:ff:ff:ff:ff', addr2='00:12:F0:6F:A9:3B', addr3='ff:ff:ff:ff:ff:ff', SC=0, addr4=None)/\
        Dot11ProbeReq()/\
        Dot11Elt(ID='SSID', len=len(ssid), info=ssid)/\
        Dot11Elt(ID='Rates', len=8, info='\x02\x04\x0b\x16\x0c\x12\x18$')/\
        Dot11Elt(ID='ESRates', len=4, info='0H`l')/\
        Dot11Elt(ID='DSset', len=1, info='\x0b')

    sendp(beacon_packet, iface='mon0')

x = Link('ex')
"""
#while True:
#    probe_req('', 'mon0')