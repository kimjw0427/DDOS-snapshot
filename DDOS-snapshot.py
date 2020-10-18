#-*- coding:utf-8 -*-

from PyQt5 import uic
from PyQt5.QtWidgets import*
from PyQt5.QtCore import*
from PyQt5.QtGui import*
from scapy.all import *
import time
import os
import ctypes

default_interface = str(conf.iface).replace('[','***').replace(']','***').split('***')[1]

interface = conf.iface

traffic_result = 0
total_traffic_result = 0
danger_traffic_limit = 5000
traffic_limit = False
over_traffic = True

low_traffic_dos_multiply = 5

attacker_list = {0:0}
except_attacker_list = [0]

def check_su():
    if ctypes.windll.shell32.IsUserAnAdmin():
        return True
    else:
        return False


def tm():
    return time.strftime('%I:%M:%S', time.localtime(time.time()))


def check_error():
    try:
        send(IP(dst="127.0.0.1") / ICMP() / 'Whereisnpcap', verbose=False)
        return True
    except:
        return '[오류] npcap이 존재하지 않습니다. npcap을 설치해주세요. (https://nmap.org/npcap/)'


def check_interface(interface):
    try:
        send(IP(dst="127.0.0.1") / ICMP() / 'Whereisnpcap',iface=interface, verbose=False)
        return True
    except:
        return False


def online():
    while(1):
        if(time.strftime('%M', time.localtime(time.time())) == '00'):
            send(IP(dst="ipsnetwork.kro.kr") / ICMP() / 'ddossnapshot', verbose=False)
        time.sleep(40)


thread_change_ip_start = False

def change_ip(self):
    def thread_change_ip(self):
        global thread_change_ip_start
        os.system('cmd /c IPchanger\IPchanger.bat')
        thread_change_ip_start = False
        self.console.append(f'[{tm()}] IP가 변경되었습니다. 프로그램을 재시작해주세요.')
    if not(thread_change_ip_start):
        thread_change_ip_start = True
        thread_thread_change_ip = Thread(target=thread_change_ip, args=(self,))
        thread_thread_change_ip.daemon = True
        thread_thread_change_ip.start()


def activate_proto(self, proto):
    if proto == 'TCP':
        if self.checkbox_tcp.isChecked():
            return True
        else:
            return False
    if proto == 'UDP':
        if self.checkbox_udp.isChecked():
            return True
        else:
            return False
    if proto == 'ICMP':
        if self.checkbox_icmp.isChecked():
            return True
        else:
            return False
    if proto == 'HTTP':
        if self.checkbox_http.isChecked():
            return True
        else:
            return False
    else:
        return False


def detect_traffic():
    global traffic_result
    global total_traffic_result
    while(1):
        traffic = sniff(filter='IP', timeout=1)
        traffic_result = len(traffic)
        total_traffic_result = total_traffic_result + traffic_result


image_on = 'GUI/__ON.png'
image_off = 'GUI/__OFF.png'
danger_icon = 'GUI/DANGERLIGHT.png'
traffic_box_icon = 'GUI/__DANGERTRAFFIC.png'
icon = 'GUI/ICON.png'

packet = None

temp_packet = None


def del_except(src_ip):
    global attacker_list
    global except_attacker_list
    time.sleep(60)
    del attacker_list[src_ip]
    del except_attacker_list[except_attacker_list.index(src_ip)]

def del_except_traffic():
    global over_traffic
    time.sleep(60)
    over_traffic = True


def attack_type(type): # Protocol/Attack_type/High_traffic_attack = HT or Low_traffic_attack = LT
    type = type.replace('(',',').replace(')',',').split(',')
    if 'ICMP' in type:
        if '8' in type:
            if 'POD' in type:
                return 'ICMP/Ping Of Death/HT'
            elif 'None' in type:
                return 'ICMP/ICMP Flood/HT'
        elif '3' in type:
            return 'ICMP/Black Nurse/LT'
        elif '0' in type:
            return 'ICMP/Smurf Attack/HT'
    if 'UDP' in type:
        if 'DNS' in type:
            return 'UDP/DNS Query DRDOS/HT'
        elif 'NTP' in type:
            return 'UDP/NTP DRDOS/HT'
        else:
            return 'UDP/UDP Flood/HT'
    if 'TCP' in type:
        if 'S' in type:
            if 'TSUNAMI' in type:
                return 'TCP/TSUNAMI SYN Flood/HT'
            elif 'None' in type:
                return 'TCP/SYN Flood/HT'
        if 'R' in type:
            return 'TCP/TCP Reset Attack/HT'
        if 'SA' in type:
            return 'TCP/SYN-ACK DRDOS/HT'
        if 'F' in type:
            return 'TCP/FIN Flood/HT'
    if 'HTTP' in type:
        if 'SlowGet' in type:
            return 'HTTP/Slowloris/LT'
        if 'SlowPost' in type:
            return 'HTTP/RUDY/LT'
        if 'SlowRead' in type:
            return 'HTTP/Slow HTTP Read Attack/LT'
    return 'None/None/None'

def analyze_icmp(pkt): # type = Packet_type,~/High_traffic_attack = 1 or Low_traffic_attack = low_traffic_dos_multiply
    if 'Raw' in pkt:
        if len(pkt[Raw].load) >= 1000:
            type = f'{pkt[ICMP].type},POD/1'
        else:
            type = f'{pkt[ICMP].type},None/1'
    else:
        type = f'{pkt[ICMP].type},None/1'
    if pkt[ICMP].type == 3:
        type = f'{pkt[ICMP].type},None/{str(low_traffic_dos_multiply)}'
    if not f'ICMP({type.split("/")[0]}) {pkt[IP].src} None' in temp_packet:
        temp_packet[f'ICMP({type.split("/")[0]}) {pkt[IP].src} None'] = 0
    else:
        temp_packet[f'ICMP({type.split("/")[0]}) {pkt[IP].src} None'] = temp_packet.get(
            f'ICMP({type.split("/")[0]}) {pkt[IP].src} None') + 1*int(type.split("/")[1])
    if not f'ICMP({type.split("/")[0]}) None' in packet:
        packet[f'ICMP({type.split("/")[0]}) None'] = 0
    else:
        packet[f'ICMP({type.split("/")[0]}) None']\
            = packet.get(f'ICMP({type.split("/")[0]}) None') + 1*int(type.split("/")[1])

def analyze_udp(pkt):
    if 'DNS' in pkt:
        if not pkt[DNS].qd == None or not pkt[DNS].an == None or not pkt[DNS].ns == None or not pkt[DNS].ar == None:
            type = 'DNS/1'
        else:
            type = 'None/1'
    elif 'NTP' in pkt:
        type = 'NTP/1'
    else:
        type = 'None/1'
    if not f'UDP({type.split("/")[0]}) {pkt[IP].src} {pkt[UDP].dport}' in temp_packet:
        temp_packet[f'UDP({type.split("/")[0]}) {pkt[IP].src} {pkt[UDP].dport}'] = 0
    else:
        temp_packet[f'UDP({type.split("/")[0]}) {pkt[IP].src} {pkt[UDP].dport}'] = temp_packet.get(
            f'UDP({type.split("/")[0]}) {pkt[IP].src} {pkt[UDP].dport}') + 1*int(type.split("/")[1])
    if not f'UDP({type.split("/")[0]}) {pkt[UDP].dport}' in packet:
        packet[f'UDP({type.split("/")[0]}) {pkt[UDP].dport}'] = 0
    else:
        packet[f'UDP({type.split("/")[0]}) {pkt[UDP].dport}']\
            = packet.get(f'UDP({type.split("/")[0]}) {pkt[UDP].dport}') + 1*int(type.split("/")[1])

def analyze_tcp(pkt):
    if 'Raw' in pkt:
        if len(pkt[Raw].load) >= 1000:
            type = f'{pkt[TCP].flags},TSUNAMI/1'
        else:
            type = f'{pkt[TCP].flags},None/1'
    else:
        type = f'{pkt[TCP].flags},None/1'
    if not f'TCP({type.split("/")[0]}) {pkt[IP].src} {pkt[TCP].dport}' in temp_packet:
        temp_packet[f'TCP({type.split("/")[0]}) {pkt[IP].src} {pkt[TCP].dport}'] = 0
    else:
        temp_packet[f'TCP({type.split("/")[0]}) {pkt[IP].src} {pkt[TCP].dport}'] = temp_packet.get(
            f'TCP({type.split("/")[0]}) {pkt[IP].src} {pkt[TCP].dport}') + 1*int(type.split("/")[1])
    if not f'TCP({type.split("/")[0]}) {pkt[TCP].dport}' in packet:
        packet[f'TCP({type.split("/")[0]}) {pkt[TCP].dport}'] = 0
    else:
        packet[f'TCP({type.split("/")[0]}) {pkt[TCP].dport}'] = packet.get(
            f'TCP({type.split("/")[0]}) {pkt[TCP].dport}') + 1*int(type.split("/")[1])

def analyze_http(pkt):
    if pkt[TCP].window <= 200:
        type = f'SlowRead/{str(low_traffic_dos_multiply)}'
    elif 'Raw' in pkt:
        if not str(pkt[Raw].load).find('GET') == -1:
            if str(pkt[Raw].load).find('\\r\\n\\r\\n') == -1:
                type = f'SlowGet/{str(low_traffic_dos_multiply)}'
            else:
                type = 'None/1'
        elif not str(pkt[Raw].load).find('POST') == -1:
            payload = str(pkt[Raw].load).replace('\\r\\n',' ').split()
            if int(payload[payload.index('Content-Length:')+1]) >= 5000:
                type = f'SlowPost/{str(low_traffic_dos_multiply)}'
            else:
                type = 'None/1'
        else:
            type = 'None/1'
    else:
        type = 'None/1'
    if not f'HTTP({type.split("/")[0]}) {pkt[IP].src} {pkt[TCP].dport}' in temp_packet:
        temp_packet[f'HTTP({type.split("/")[0]}) {pkt[IP].src} {pkt[TCP].dport}'] = 0
    else:
        temp_packet[f'HTTP({type.split("/")[0]}) {pkt[IP].src} {pkt[TCP].dport}'] = temp_packet.get(
            f'HTTP({type.split("/")[0]}) {pkt[IP].src} {pkt[TCP].dport}') + 1*int(type.split("/")[1])
    if not f'HTTP({type.split("/")[0]}) {pkt[TCP].dport}' in packet:
        packet[f'HTTP({type.split("/")[0]}) {pkt[TCP].dport}'] = 0
    else:
        packet[f'HTTP({type.split("/")[0]}) {pkt[TCP].dport}'] = packet.get(
            f'HTTP({type.split("/")[0]}) {pkt[TCP].dport}') + 1*int(type.split("/")[1])


def handler(pkt):
    global packet
    global temp_packet
    if 'IP' in pkt:
        if not pkt[IP].src == get_if_addr(conf.iface):
            if 'ICMP' in pkt:
                analyze_icmp(pkt)
            if 'UDP' in pkt:
                analyze_udp(pkt)
            if 'TCP' in pkt:
                if 'Raw' in pkt:
                    if str(pkt[Raw].load).find('HTTP') == -1:
                        analyze_tcp(pkt)
                    else:
                        analyze_http(pkt)
                else:
                    analyze_tcp(pkt)

def snapshot():
    while(1):
        global temp_packet
        global attacker_list
        global packet
        temp_packet = {None:None}
        packet = {None:None}
        sniff(prn=handler, timeout=2)
        for name in temp_packet:
            if not name == None:
                print(name)
                P_type = name.split()[0]
                P_ip = name.split()[1]
                P_port = name.split()[2]
                P_count = temp_packet.get(name)
                if P_count > (danger_traffic_limit*2 / (danger_traffic_limit/30)):
                    if not f'{P_ip} {P_type}' in attacker_list:
                        if attack_type(P_type).split('/')[2] == 'LT' or traffic_limit:
                            attacker_list[f'{P_ip} {P_type}'] = f'{P_type} {P_port}'
                            thread_del = Thread(target=del_except, args=(f'{P_ip} {P_type}',))
                            thread_del.daemon = True
                            thread_del.start()
                    packet[f'{P_type} {P_port}'] = packet[f'{P_type} {P_port}'] - P_count
        for name in packet:
            if not name == None:
                P_type = name.split()[0]
                P_port = name.split()[1]
                P_count = packet.get(name)
                if P_count > (danger_traffic_limit / 2):
                    if not f'[위조된_IP] {P_type}' in attacker_list:
                        if attack_type(P_type).split('/')[2] == 'LT' or traffic_limit:
                            attacker_list[f'[위조된_IP] {P_type}'] = f'{P_type} {P_port}'
                            thread_del = Thread(target=del_except, args=(f'[위조된_IP] {P_type}',))
                            thread_del.daemon = True
                            thread_del.start()

def start_thread():
    online_thread = Thread(target=online)
    online_thread.daemon = True
    online_thread.start()
    traffic_thread = Thread(target=detect_traffic)
    traffic_thread.daemon = True
    traffic_thread.start()
    snapshot_thread = Thread(target=snapshot)
    snapshot_thread.daemon = True
    snapshot_thread.start()

class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(400, 550)
        self.backgrounnd = QLabel(Form)
        self.backgrounnd.setGeometry(QRect(-7, 0, 407, 550))
        self.backgrounnd.setText("")
        self.backgrounnd.setPixmap(QPixmap("GUI\GUI.png"))
        self.backgrounnd.setScaledContents(False)
        self.backgrounnd.setObjectName("backgrounnd")
        self.light = QLabel(Form)
        self.light.setGeometry(QRect(20, 70, 29, 29))
        self.light.setText("")
        self.light.setObjectName("light")
        self.exit = QPushButton(Form)
        self.exit.setGeometry(QRect(60, 68, 70, 35))
        self.exit.setStyleSheet("background-color: rgba(0,0, 0, 0);")
        self.exit.setText("")
        self.exit.setObjectName("exit")
        self.minimize = QPushButton(Form)
        self.minimize.setGeometry(QRect(340, 10, 51, 31))
        self.minimize.setStyleSheet("background-color: rgba(0,0, 0, 0);")
        self.minimize.setText("")
        self.minimize.setObjectName("minimize")
        self.interfacetext = QTextEdit(Form)
        self.interfacetext.setEnabled(True)
        self.interfacetext.setGeometry(QRect(8, 135, 125, 58))
        self.interfacetext.setStyleSheet("background-color: rgba(255, 255, 255, 0);\n"
"color: rgb(255, 255, 255);")
        self.interfacetext.setFrameShape(QFrame.NoFrame)
        self.interfacetext.setObjectName("interfacetext")
        self.reset = QPushButton(Form)
        self.reset.setGeometry(QRect(8, 250, 125, 25))
        self.reset.setStyleSheet("background-color: rgba(0,0, 0, 0);")
        self.reset.setText("")
        self.reset.setObjectName("reset")
        self.checkbox_icmp = QCheckBox(Form)
        self.checkbox_icmp.setGeometry(QRect(30, 460, 61, 20))
        self.checkbox_icmp.setStyleSheet("color: rgba(255, 255, 255, 0);")
        self.checkbox_icmp.setChecked(True)
        self.checkbox_icmp.setObjectName("checkbox_icmp")
        self.checkbox_udp = QCheckBox(Form)
        self.checkbox_udp.setGeometry(QRect(20, 430, 71, 20))
        self.checkbox_udp.setStyleSheet("color: rgba(255, 255, 255, 0);")
        self.checkbox_udp.setChecked(True)
        self.checkbox_udp.setObjectName("checkbox_udp")
        self.checkbox_http = QCheckBox(Form)
        self.checkbox_http.setGeometry(QRect(25, 490, 111, 20))
        self.checkbox_http.setStyleSheet("color: rgba(255, 255, 255, 0);")
        self.checkbox_http.setChecked(True)
        self.checkbox_http.setObjectName("checkbox_http")
        self.checkbox_tcp = QCheckBox(Form)
        self.checkbox_tcp.setGeometry(QRect(20, 400, 71, 20))
        self.checkbox_tcp.setStyleSheet("color: rgba(255, 255, 255, 0);")
        self.checkbox_tcp.setChecked(True)
        self.checkbox_tcp.setObjectName("checkbox_tcp")
        self.checkbox_alarm = QCheckBox(Form)
        self.checkbox_alarm.setGeometry(QRect(25, 320, 101, 20))
        self.checkbox_alarm.setStyleSheet("color: rgba(255, 255, 255, 0);")
        self.checkbox_alarm.setChecked(True)
        self.checkbox_alarm.setObjectName("checkbox_alarm")
        self.checkbox_defender = QCheckBox(Form)
        self.checkbox_defender.setGeometry(QRect(25, 350, 101, 20))
        self.checkbox_defender.setStyleSheet("color: rgba(255, 255, 255, 0);")
        self.checkbox_defender.setChecked(False)
        self.checkbox_defender.setObjectName("checkbox_defender")
        self.icon_icmp = QLabel(Form)
        self.icon_icmp.setGeometry(QRect(10, 460, 40, 20))
        self.icon_icmp.setText("")
        self.icon_icmp.setPixmap(QPixmap("GUI\__ON.png"))
        self.icon_icmp.setObjectName("icon_icmp")
        self.icon_udp = QLabel(Form)
        self.icon_udp.setGeometry(QRect(10, 430, 40, 20))
        self.icon_udp.setText("")
        self.icon_udp.setPixmap(QPixmap("GUI\__ON.png"))
        self.icon_udp.setObjectName("icon_udp")
        self.icon_http = QLabel(Form)
        self.icon_http.setGeometry(QRect(10, 490, 40, 20))
        self.icon_http.setText("")
        self.icon_http.setPixmap(QPixmap("GUI\__ON.png"))
        self.icon_http.setObjectName("icon_http")
        self.icon_tcp = QLabel(Form)
        self.icon_tcp.setGeometry(QRect(10, 400, 40, 20))
        self.icon_tcp.setText("")
        self.icon_tcp.setPixmap(QPixmap("GUI\__ON.png"))
        self.icon_tcp.setObjectName("icon_tcp")
        self.icon_alarm = QLabel(Form)
        self.icon_alarm.setGeometry(QRect(10, 320, 40, 20))
        self.icon_alarm.setText("")
        self.icon_alarm.setPixmap(QPixmap("GUI\__ON.png"))
        self.icon_alarm.setObjectName("icon_alarm")
        self.icon_defender = QLabel(Form)
        self.icon_defender.setGeometry(QRect(10, 350, 40, 20))
        self.icon_defender.setText("")
        self.icon_defender.setPixmap(QPixmap("GUI\__OFF.png"))
        self.icon_defender.setObjectName("icon_defender")
        self.button_alarm = QPushButton(Form)
        self.button_alarm.setGeometry(QRect(10, 320, 40, 20))
        self.button_alarm.setStyleSheet("color: rgba(255, 255, 255, 0);\n"
"background-color: rgba(255, 255, 255, 0);")
        self.button_alarm.setObjectName("button_alarm")
        self.button_defender = QPushButton(Form)
        self.button_defender.setGeometry(QRect(10, 350, 40, 20))
        self.button_defender.setStyleSheet("color: rgba(255, 255, 255, 0);\n"
"background-color: rgba(255, 255, 255, 0);")
        self.button_defender.setObjectName("button_defender")
        self.button_icmp = QPushButton(Form)
        self.button_icmp.setGeometry(QRect(10, 460, 40, 20))
        self.button_icmp.setStyleSheet("color: rgba(255, 255, 255, 0);\n"
"background-color: rgba(255, 255, 255, 0);")
        self.button_icmp.setObjectName("button_icmp")
        self.button_udp = QPushButton(Form)
        self.button_udp.setGeometry(QRect(10, 430, 40, 20))
        self.button_udp.setStyleSheet("color: rgba(255, 255, 255, 0);\n"
"background-color: rgba(255, 255, 255, 0);")
        self.button_udp.setObjectName("button_udp")
        self.button_http = QPushButton(Form)
        self.button_http.setGeometry(QRect(10, 490, 40, 20))
        self.button_http.setStyleSheet("color: rgba(255, 255, 255, 0);\n"
"background-color: rgba(255, 255, 255, 0);")
        self.button_http.setObjectName("button_http")
        self.button_tcp = QPushButton(Form)
        self.button_tcp.setGeometry(QRect(10, 400, 40, 20))
        self.button_tcp.setStyleSheet("color: rgba(255, 255, 255, 0);\n"
"background-color: rgba(255, 255, 255, 0);")
        self.button_tcp.setObjectName("button_tcp")
        self.console = QTextEdit(Form)
        self.console.setGeometry(QRect(140, 69, 250, 211))
        self.console.setStyleSheet("background-color: rgba(255, 255, 255, 0);\n"
"font: 63 8pt;\n"
"color: rgb(255, 255, 255);")
        self.console.setFrameShape(QFrame.NoFrame)
        self.console.setReadOnly(True)
        self.console.setObjectName("console")
        self.status_console = QTextEdit(Form)
        self.status_console.setGeometry(QRect(150, 300, 231, 51))
        self.status_console.setStyleSheet("background-color: rgba(255, 255, 255, 0);\n"
"font: 63 10pt;\n"
"color: rgb(255, 255, 255);")
        self.status_console.setFrameShape(QFrame.NoFrame)
        self.status_console.setReadOnly(True)
        self.status_console.setObjectName("status_console")
        self.traffictext = QTextEdit(Form)
        self.traffictext.setEnabled(True)
        self.traffictext.setGeometry(QRect(8, 215, 125, 25))
        self.traffictext.setStyleSheet("background-color: rgba(255, 255, 255, 0);\n"
"color: rgb(255, 255, 255);")
        self.traffictext.setFrameShape(QFrame.NoFrame)
        self.traffictext.setObjectName("traffictext")
        self.apply = QPushButton(Form)
        self.apply.setGeometry(QRect(8, 285, 125, 25))
        self.apply.setStyleSheet("background-color: rgba(0,0, 0, 0);")
        self.apply.setText("")
        self.apply.setObjectName("apply")
        self.traffic_limit = QCheckBox(Form)
        self.traffic_limit.setGeometry(QRect(30, 80, 81, 16))
        self.traffic_limit.setText("")
        self.traffic_limit.setObjectName("traffic_limit")
        self.traffic_box_1 = QLabel(Form)
        self.traffic_box_1.setGeometry(QRect(338, 501, 45, 30))
        self.traffic_box_1.setText("")
        self.traffic_box_1.setObjectName("traffic_box_1")
        self.traffic_box_2 = QLabel(Form)
        self.traffic_box_2.setGeometry(QRect(338, 471, 45, 30))
        self.traffic_box_2.setText("")
        self.traffic_box_2.setObjectName("traffic_box_2")
        self.traffic_box_3 = QLabel(Form)
        self.traffic_box_3.setGeometry(QRect(338, 441, 45, 30))
        self.traffic_box_3.setText("")
        self.traffic_box_3.setObjectName("traffic_box_3")
        self.traffic_box_4 = QLabel(Form)
        self.traffic_box_4.setGeometry(QRect(338, 411, 45, 30))
        self.traffic_box_4.setText("")
        self.traffic_box_4.setObjectName("traffic_box_4")
        self.traffic_box_5 = QLabel(Form)
        self.traffic_box_5.setGeometry(QRect(338, 381, 45, 30))
        self.traffic_box_5.setText("")
        self.traffic_box_5.setObjectName("traffic_box_5")
        self.traffic_limit.raise_()
        self.backgrounnd.raise_()
        self.light.raise_()
        self.exit.raise_()
        self.minimize.raise_()
        self.interfacetext.raise_()
        self.reset.raise_()
        self.checkbox_icmp.raise_()
        self.checkbox_udp.raise_()
        self.checkbox_http.raise_()
        self.checkbox_tcp.raise_()
        self.checkbox_alarm.raise_()
        self.checkbox_defender.raise_()
        self.icon_icmp.raise_()
        self.icon_udp.raise_()
        self.icon_http.raise_()
        self.icon_tcp.raise_()
        self.icon_alarm.raise_()
        self.icon_defender.raise_()
        self.button_alarm.raise_()
        self.button_defender.raise_()
        self.button_icmp.raise_()
        self.button_udp.raise_()
        self.button_http.raise_()
        self.button_tcp.raise_()
        self.console.raise_()
        self.status_console.raise_()
        self.traffictext.raise_()
        self.apply.raise_()
        self.traffic_box_1.raise_()
        self.traffic_box_2.raise_()
        self.traffic_box_3.raise_()
        self.traffic_box_4.raise_()
        self.traffic_box_5.raise_()

        self.retranslateUi(Form)
        QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.interfacetext.setHtml(_translate("Form", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'Gulim\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-family:\'Gulim\';\"><br /></p></body></html>"))
        self.checkbox_icmp.setText(_translate("Form", "CheckBox"))
        self.checkbox_udp.setText(_translate("Form", "CheckBox"))
        self.checkbox_http.setText(_translate("Form", "CheckBox"))
        self.checkbox_tcp.setText(_translate("Form", "CheckBox"))
        self.checkbox_alarm.setText(_translate("Form", "CheckBox"))
        self.checkbox_defender.setText(_translate("Form", "CheckBox"))
        self.button_alarm.setText(_translate("Form", "PushButton"))
        self.button_defender.setText(_translate("Form", "PushButton"))
        self.button_icmp.setText(_translate("Form", "PushButton"))
        self.button_udp.setText(_translate("Form", "PushButton"))
        self.button_http.setText(_translate("Form", "PushButton"))
        self.button_tcp.setText(_translate("Form", "PushButton"))
        self.console.setHtml(_translate("Form", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'Gulim\'; font-size:8pt; font-weight:56; font-style:normal;\">\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-family:\'Segoe UI Semibold\'; font-size:14pt;\"><br /></p></body></html>"))
        self.status_console.setHtml(_translate("Form", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'Gulim\'; font-size:10pt; font-weight:56; font-style:normal;\">\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-family:\'Gulim\';\"><br /></p></body></html>"))
        self.traffictext.setHtml(_translate("Form", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'Gulim\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-family:\'Gulim\';\"><br /></p></body></html>"))


class MyWindow(QMainWindow, Ui_Form):
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        self.trayIcon = QSystemTrayIcon(QIcon(icon), parent=app)
        self.trayIcon.setToolTip('Detecting DDOS!')
        self.trayIcon.show()

        menu = QMenu()
        exitAction = menu.addAction('Exit')
        exitAction.triggered.connect(self.window_exit)
        self.trayIcon.setContextMenu(menu)
        self.trayIcon.activated.connect(self.click_trayicon)

        self.traffictext.setText(str(danger_traffic_limit))

        self.exit.clicked.connect(self.window_exit)
        self.minimize.clicked.connect(self.window_minimize)
        self.reset.clicked.connect(self.reset_option)
        self.apply.clicked.connect(self.apply_option)

        self.interfacetext.setText(str(conf.iface).replace('[','***').replace(']','***').split('***')[1])

        self.checkbox_alarm.stateChanged.connect(self.change_image_alarm)
        self.button_alarm.clicked.connect(self.change_checkbox_alarm)

        self.checkbox_defender.stateChanged.connect(self.change_image_defender)
        self.button_defender.clicked.connect(self.change_checkbox_defender)

        self.checkbox_tcp.stateChanged.connect(self.change_image_tcp)
        self.button_tcp.clicked.connect(self.change_checkbox_tcp)

        self.checkbox_icmp.stateChanged.connect(self.change_image_icmp)
        self.button_icmp.clicked.connect(self.change_checkbox_icmp)

        self.checkbox_udp.stateChanged.connect(self.change_image_udp)
        self.button_udp.clicked.connect(self.change_checkbox_udp)

        self.checkbox_http.stateChanged.connect(self.change_image_http)
        self.button_http.clicked.connect(self.change_checkbox_http)

        self.status_timer = QTimer(self)
        self.status_timer.start(1000)
        self.status_timer.timeout.connect(self.refresh_status)


        self.status_timer = QTimer(self)
        self.status_timer.start(3000)
        self.status_timer.timeout.connect(self.indicate_snapshot)

        self.exit.setStyleSheet(
            '''
            QPushButton{background-color: rgba(39, 39, 39, 0);}
            QPushButton:hover{background-color: rgba(39, 39, 39, 100);}
            '''
        )
        self.minimize.setStyleSheet(
            '''
            QPushButton{background-color: rgba(39, 39, 39, 0);}
            QPushButton:hover{background-color: rgba(39, 39, 39, 100);}
            '''
        )
        self.reset.setStyleSheet(
            '''
            QPushButton{background-color: rgba(39, 39, 39, 0);}
            QPushButton:hover{background-color: rgba(39, 39, 39, 100);}
            '''
        )
        self.apply.setStyleSheet(
            '''
            QPushButton{background-color: rgba(39, 39, 39, 0);}
            QPushButton:hover{background-color: rgba(39, 39, 39, 100);}
            '''
        )
        if (check_error() == True):
            self.console.append(f'[{tm()}] 정상적으로 프로그램이 실행되었습니다. DDOS 탐지를 시작합니다.')
        else:
            self.console.setText(check_error())


    def indicate_snapshot(self):
        global except_attacker_list
        for name in attacker_list:
            if not name in except_attacker_list:
                type = attack_type(attacker_list.get(name).split()[0]).split('/')
                if activate_proto(self, type[0]):
                    if (type[2] == 'LT'):
                        self.console.append(f' \n[{tm()}] 공격자: {name.split()[0]}\n'
                                            f'└> 공격유형: {type[1]} △ 저대역폭 공격\n'
                                            f'└> 포트: {attacker_list.get(name).split()[1]}')
                        if self.checkbox_alarm.isChecked():
                            self.trayIcon.showMessage(
                                "DDOS 스냅샷",
                                f'[{tm()}] 공격을 감지했습니다!\n공격자: {name.split()[0]}\n'
                                f'공격유형: {type[1]} △ 저대역폭 공격',
                                QSystemTrayIcon.Information,
                                2000
                            )
                        if self.checkbox_defender.isChecked():
                            if check_su():
                                self.console.append(f'\n[{tm()}] IP를 바꿔 공격을 우회하는 중입니다.')
                                change_ip(self)
                            else:
                                self.console.append(f'[{tm()}] 관리자 권한이 없습니다. 방어기능이 작동하지 않습니다.')
                    elif traffic_limit:
                        self.console.append(f' \n[{tm()}] 공격자: {name.split()[0]}\n'
                                            f'└> 공격유형: {type[1]}\n'
                                            f'└> 포트: {attacker_list.get(name).split()[1]}')
                        if self.checkbox_alarm.isChecked():
                            self.trayIcon.showMessage(
                                "DDOS 스냅샷",
                                f'[{tm()}] 공격을 감지했습니다!\n공격자: {name.split()[0]}\n'
                                f'공격유형: {type[1]}',
                                QSystemTrayIcon.Information,
                                2000
                            )
                        if self.checkbox_defender.isChecked():
                            if check_su():
                                self.console.append(f'\n[{tm()}] IP를 바꿔 공격을 우회하는 중입니다.')
                                change_ip(self)
                            else:
                                self.console.append(f'[{tm()}] 관리자 권한이 없습니다. 방어기능이 작동하지 않습니다.')
            except_attacker_list.append(name)


    def refresh_traffic_box(self):
        if traffic_result >= danger_traffic_limit/5:
            self.traffic_box_1.setPixmap(QPixmap(traffic_box_icon))
        else:
            self.traffic_box_1.setPixmap(QPixmap(None))
        if traffic_result >= danger_traffic_limit/5*2:
            self.traffic_box_2.setPixmap(QPixmap(traffic_box_icon))
        else:
            self.traffic_box_2.setPixmap(QPixmap(None))
        if traffic_result >= danger_traffic_limit/5*3:
            self.traffic_box_3.setPixmap(QPixmap(traffic_box_icon))
        else:
            self.traffic_box_3.setPixmap(QPixmap(None))
        if traffic_result >= danger_traffic_limit/5*4:
            self.traffic_box_4.setPixmap(QPixmap(traffic_box_icon))
        else:
            self.traffic_box_4.setPixmap(QPixmap(None))
        if traffic_result >= danger_traffic_limit/5*5:
            self.traffic_box_5.setPixmap(QPixmap(traffic_box_icon))
        else:
            self.traffic_box_5.setPixmap(QPixmap(None))


    def refresh_status(self):
        global traffic_limit
        global over_traffic
        self.status_console.setText(f'{traffic_result} Packets/sec\nTotal: {total_traffic_result} Packets')
        self.refresh_traffic_box()
        if(traffic_result > danger_traffic_limit):
            if not traffic_limit:
                traffic_limit = True
                self.light.setPixmap(QPixmap(danger_icon))
                if over_traffic:
                    over_traffic = False
                    self.console.append(f'[{tm()}] 트래픽이 임계치를 넘겼습니다. 패킷을 분석합니다.')
                    if self.checkbox_alarm.isChecked():
                        self.trayIcon.showMessage(
                            "DDOS 스냅샷",
                            f'[{tm()}] 트래픽이 임계치를 넘겼습니다. 패킷을 분석합니다.',
                            QSystemTrayIcon.Information,
                            2000
                        )
                    traffic_thread = Thread(target=del_except_traffic)
                    traffic_thread.daemon = True
                    traffic_thread.start()
        else:
            traffic_limit = False
            self.light.setPixmap(QPixmap(None))

    def click_trayicon(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            self.show()

    def window_exit(self):
        if self.checkbox_alarm.isChecked():
            self.trayIcon.showMessage(
                "DDOS 스냅샷",
                f"[{tm()}] 프로그램이 꺼졌습니다. DDOS 탐지가 비활성화됩니다.",
                QSystemTrayIcon.Information,
                2000
            )
        sys.exit(app.exec_())

    def closeEvent(self, event):
        event.ignore()
        self.window_minimize()

    def window_minimize(self):
        self.hide()
        if self.checkbox_alarm.isChecked():
            self.trayIcon.showMessage(
                "DDOS 스냅샷",
                f"[{tm()}] 백그라운드 상태입니다.",
                QSystemTrayIcon.Information,
                2000
            )

    def set_traffic(self):
        global danger_traffic_limit
        if not self.traffictext.toPlainText() == str(danger_traffic_limit):
            if self.traffictext.toPlainText().isdigit() == True:
                danger_traffic_limit = int(self.traffictext.toPlainText())
                self.console.append(f'[{tm()}] 새로운 트래픽 임계치 적용: {danger_traffic_limit}')
            else:
                self.console.append(f'[{tm()}] 트래픽 임계치 설정을 할 수 없습니다. 숫자를 입력해주세요.')

    def set_interface(self):
        if not str(conf.iface).replace('[','***').replace(']','***').split('***')[1] == self.interfacetext.toPlainText():
            if check_interface(self.interfacetext.toPlainText()):
                conf.iface = IFACES.dev_from_name(self.interfacetext.toPlainText())
                self.console.append(f'[{tm()}] 새로운 네트워크 인터페이스 적용: {self.interfacetext.toPlainText()}')
            else:
                self.console.append(f'[{tm()}] {self.interfacetext.toPlainText()} 올바르지 않은 네트워크 인터페이스 입니다.')

    def apply_option(self):
        self.set_interface()
        self.set_traffic()

    def reset_option(self):
        conf.iface = default_interface
        self.interfacetext.setText(str(default_interface))
        self.console.append(f'[{tm()}] 네트워크 인터페이스 리셋')

    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def mousePressEvent(self, event):
        self.oldPos = event.globalPos()

    def mouseMoveEvent(self, event):
        delta = QPoint(event.globalPos() - self.oldPos)
        self.move(self.x() + delta.x(), self.y() + delta.y())
        self.oldPos = event.globalPos()

    def change_image_alarm(self):
        if self.checkbox_alarm.isChecked():
            self.icon_alarm.setPixmap(QPixmap(image_on))
        else:
            self.icon_alarm.setPixmap(QPixmap(image_off))

    def change_checkbox_alarm(self):
        if self.checkbox_alarm.isChecked():
            self.checkbox_alarm.setChecked(False)
        else:
            self.checkbox_alarm.setChecked(True)

    def change_image_defender(self):
        if self.checkbox_defender.isChecked():
            self.icon_defender.setPixmap(QPixmap(image_on))
            self.console.append(f'[{tm()}] 공격방어 기능이 활성화되었습니다. 공유기가 없는 직접연결 환경에서만 작동합니다.')
        else:
            self.icon_defender.setPixmap(QPixmap(image_off))

    def change_checkbox_defender(self):
        global check_defender
        if self.checkbox_defender.isChecked():
            self.checkbox_defender.setChecked(False)
        else:
            self.checkbox_defender.setChecked(True)

    def change_image_tcp(self):
        if self.checkbox_tcp.isChecked():
            self.icon_tcp.setPixmap(QPixmap(image_on))
        else:
            self.icon_tcp.setPixmap(QPixmap(image_off))

    def change_checkbox_tcp(self):
        if self.checkbox_tcp.isChecked():
            self.checkbox_tcp.setChecked(False)
        else:
            self.checkbox_tcp.setChecked(True)

    def change_image_icmp(self):
        if self.checkbox_icmp.isChecked():
            self.icon_icmp.setPixmap(QPixmap(image_on))
        else:
            self.icon_icmp.setPixmap(QPixmap(image_off))

    def change_checkbox_icmp(self):
        if self.checkbox_icmp.isChecked():
            self.checkbox_icmp.setChecked(False)
        else:
            self.checkbox_icmp.setChecked(True)

    def change_image_udp(self):
        if self.checkbox_udp.isChecked():
            self.icon_udp.setPixmap(QPixmap(image_on))
        else:
            self.icon_udp.setPixmap(QPixmap(image_off))

    def change_checkbox_udp(self):
        if self.checkbox_udp.isChecked():
            self.checkbox_udp.setChecked(False)
        else:
            self.checkbox_udp.setChecked(True)

    def change_image_http(self):
        if self.checkbox_http.isChecked():
            self.icon_http.setPixmap(QPixmap(image_on))
        else:
            self.icon_http.setPixmap(QPixmap(image_off))

    def change_checkbox_http(self):
        if self.checkbox_http.isChecked():
            self.checkbox_http.setChecked(False)
        else:
            self.checkbox_http.setChecked(True)


if __name__ == "__main__":
    start_thread()
    app = QApplication(sys.argv)
    myWindow = MyWindow()
    myWindow.setWindowFlags(Qt.FramelessWindowHint)
    myWindow.show()
    app.exec_()