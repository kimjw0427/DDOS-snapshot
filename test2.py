import os
from scapy.all import*

print(conf.iface)

conf.iface = IFACES.dev_from_name('802.11n USB Wireless LAN Card')

print(conf.iface)

print(get_if_addr(conf.iface))