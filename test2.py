from scapy.all import*
import threading
import time

def handler(pkt):
    if 'IP' in pkt:
        if 'TCP' in pkt:
            if 'Raw' in pkt:
                if not str(pkt[Raw].load).find('POST') == -1:
                    payload = str(pkt[Raw].load).replace('\\r\\n',' ').split()
                    print(payload[payload.index('Content-Length:') + 1])
sniff(prn=handler,count=0)