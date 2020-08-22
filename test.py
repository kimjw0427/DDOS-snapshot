#-*- coding:utf-8 -*-

from PyQt5 import uic
from PyQt5.QtWidgets import*
from PyQt5.QtCore import*
from PyQt5.QtGui import*
from scapy.all import *
import time
import os
import ctypes

interface = conf.iface

traffic_result = 0
total_traffic_result = 0
danger_traffic_limit = 1000
traffic_limit = False
over_traffic = True

attacker_list = {0:0}
except_attacker_list = [0]

def tm():
    return time.strftime('%I:%M:%S', time.localtime(time.time()))

def check_error():
    try:
        send(IP(dst="127.0.0.1") / ICMP() / 'Whereisnpcap', verbose=False)
        return True
    except:
        return '[오류] npcap이 존재하지 않습니다. npcap을 설치해주세요. (https://nmap.org/npcap/)'

def online():
    while(1):
        if(time.strftime('%M', time.localtime(time.time())) == '00'):
            send(IP(dst="ipsnetwork.kro.kr") / ICMP() / 'ddossnapshot', verbose=False)
        time.sleep(40)

def detect_traffic():
    global traffic_result
    global total_traffic_result
    while(1):
        traffic = sniff(filter='IP', timeout=1)
        traffic_result = len(traffic)
        total_traffic_result = total_traffic_result + traffic_result


form_class = uic.loadUiType("GUI\MyWindow.ui")[0]


image_on = 'GUI/__ON.png'
image_off = 'GUI/__OFF.png'
danger_icon = 'GUI/DANGERLIGHT.png'
traffic_box_icon = 'GUI/__DANGERTRAFFIC.png'

packet = None

temp_syn = None
temp_icmp = None
temp_udp = None
temp_http = None
temp_ntp = None
temp_ssdp = None
temp_tcp = None
temp_dns = None


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


def snapshot_icmp():
    while(1):
        global temp_icmp
        global attacker_list
        global packet
        def analyze_icmp(pkt):
            global packet
            global temp_icmp
            if not pkt[0].getlayer(IP).src == get_if_addr(conf.iface):
                if 'IMCP' in pkt:
                    if pkt[0].getlayer(ICMP).type == 8:
                        if not pkt[0].getlayer(IP).src in temp_icmp:
                            temp_icmp[f'ICMP(type=8) {pkt[0].getlayer(IP).src} None'] = 0
                        else:
                            temp_icmp[f'ICMP(type=8) {pkt[0].getlayer(IP).src} None'] = temp_icmp[f'ICMP(type=8) {pkt[0].getlayer(IP).src} None'] + 1
                        if not 'ICMP(type=8)' in packet:
                            packet['ICMP(type=8) None'] = 0
                        else:
                            packet['ICMP(type=8) None'] = packet.get('ICMP(type=8) None') + 1
        temp_icmp = {None:None}
        packet = {None: [None, None]}
        sniff(prn=analyze_icmp, timeout=2)
        if traffic_limit:
            for name in temp_icmp:
                P_type = name.split()[0]
                P_IP = name.split()[1]
                P_PORT = name.split()[2]
                P_COUNT = temp_icmp.get(name)
                if P_COUNT > (danger_traffic_limit / 100):
                    if not name in attacker_list:
                        attacker_list[P_IP] = f'{P_type} {}'
                        thread_del = Thread(target=del_except, args=(src_ip,))
                        thread_del.daemon = True
                        thread_del.start()
                    not_spoofed_packet = not_spoofed_packet + temp_icmp.get(src_ip)
            if not_spoofed_packet < (danger_traffic_limit / 2):
                if not 'IP 스푸핑(ICMP)' in attacker_list:
                    attacker_list['IP 스푸핑(ICMP)'] = 'icmp'
                    thread_del = Thread(target=del_except, args=('IP 스푸핑(ICMP)',))
                    thread_del.daemon = True
                    thread_del.start()


def snapshot():
    thread_snapshot_icmp = Thread(target=snapshot_icmp)
    thread_snapshot_icmp.daemon = True
    thread_snapshot_icmp.start()
    # thread_snapshot_udp = Thread(target=snapshot_udp)
    # thread_snapshot_udp.daemon = True
    # thread_snapshot_udp.start()


def start_thread():
    online_thread = Thread(target=online)
    online_thread.daemon = True
    online_thread.start()
    traffic_thread = Thread(target=detect_traffic)
    traffic_thread.daemon = True
    traffic_thread.start()
    traffic_thread = Thread(target=snapshot)
    traffic_thread.daemon = True
    traffic_thread.start()


class MyWindow(QMainWindow, form_class):
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        self.trayIcon = QSystemTrayIcon(QIcon('GUI/SAFELIGHT.png'), parent=app)
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

        self.porttext.textChanged.connect(self.set_port)

        self.checkbox_alarm.stateChanged.connect(self.change_image_alarm)
        self.button_alarm.clicked.connect(self.change_checkbox_alarm)

        self.checkbox_defender.stateChanged.connect(self.change_image_defender)
        self.button_defender.clicked.connect(self.change_checkbox_defender)

        self.checkbox_syn.stateChanged.connect(self.change_image_syn)
        self.button_syn.clicked.connect(self.change_checkbox_syn)

        self.checkbox_icmp.stateChanged.connect(self.change_image_icmp)
        self.button_icmp.clicked.connect(self.change_checkbox_icmp)

        self.checkbox_udp.stateChanged.connect(self.change_image_udp)
        self.button_udp.clicked.connect(self.change_checkbox_udp)

        self.checkbox_http.stateChanged.connect(self.change_image_http)
        self.button_http.clicked.connect(self.change_checkbox_http)

        self.checkbox_ntp.stateChanged.connect(self.change_image_ntp)
        self.button_ntp.clicked.connect(self.change_checkbox_ntp)

        self.checkbox_ssdp.stateChanged.connect(self.change_image_ssdp)
        self.button_ssdp.clicked.connect(self.change_checkbox_ssdp)

        self.checkbox_tcp.stateChanged.connect(self.change_image_tcp)
        self.button_tcp.clicked.connect(self.change_checkbox_tcp)

        self.checkbox_dns.stateChanged.connect(self.change_image_dns)
        self.button_dns.clicked.connect(self.change_checkbox_dns)

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
        if traffic_limit:
            for src_ip in attacker_list:
                if not src_ip in except_attacker_list:
                    if attacker_list.get(src_ip) == 'icmp':
                        self.console.append(f'[{tm()}] 공격자: {src_ip} 공격유형: ICMP flood')
                        except_attacker_list.append(src_ip)
                        if self.checkbox_alarm.isChecked():
                            self.trayIcon.showMessage(
                                "DDOS 스냅샷",
                                f'[{tm()}] 공격을 감지했습니다!\n공격자: {src_ip}\n공격유형: ICMP flood.',
                                QSystemTrayIcon.Information,
                                2000
                            )


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

    def apply_option(self):
        if self.traffictext.toPlainText().isdigit() == True:
            global danger_traffic_limit
            danger_traffic_limit = int(self.traffictext.toPlainText())
            self.console.append(f'[{tm()}] 새로운 트래픽 임계치 적용: {danger_traffic_limit}')
        else:
            self.console.append(f'[{tm()}] 트래픽 임계치 설정을 할 수 없습니다. 숫자를 입력해주세요.')

    def set_port(self):
        print(self.porttext.toPlainText())

    def reset_option(self):
        self.console.setText(None)
        self.porttext.setText('0~65535')

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
        else:
            self.icon_defender.setPixmap(QPixmap(image_off))

    def change_checkbox_defender(self):
        global check_defender
        if self.checkbox_defender.isChecked():
            self.checkbox_defender.setChecked(False)
        else:
            self.checkbox_defender.setChecked(True)

    def change_image_syn(self):
        if self.checkbox_syn.isChecked():
            self.icon_syn.setPixmap(QPixmap(image_on))
        else:
            self.icon_syn.setPixmap(QPixmap(image_off))

    def change_checkbox_syn(self):
        if self.checkbox_syn.isChecked():
            self.checkbox_syn.setChecked(False)
        else:
            self.checkbox_syn.setChecked(True)

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

    def change_image_ntp(self):
        if self.checkbox_ntp.isChecked():
            self.icon_ntp.setPixmap(QPixmap(image_on))
        else:
            self.icon_ntp.setPixmap(QPixmap(image_off))

    def change_checkbox_ntp(self):
        if self.checkbox_ntp.isChecked():
            self.checkbox_ntp.setChecked(False)
        else:
            self.checkbox_ntp.setChecked(True)

    def change_image_ssdp(self):
        if self.checkbox_ssdp.isChecked():
            self.icon_ssdp.setPixmap(QPixmap(image_on))
        else:
            self.icon_ssdp.setPixmap(QPixmap(image_off))

    def change_checkbox_ssdp(self):
        if self.checkbox_ssdp.isChecked():
            self.checkbox_ssdp.setChecked(False)
        else:
            self.checkbox_ssdp.setChecked(True)

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

    def change_image_dns(self):
        if self.checkbox_dns.isChecked():
            self.icon_dns.setPixmap(QPixmap(image_on))
        else:
            self.icon_dns.setPixmap(QPixmap(image_off))

    def change_checkbox_dns(self):
        if self.checkbox_dns.isChecked():
            self.checkbox_dns.setChecked(False)
        else:
            self.checkbox_dns.setChecked(True)


if __name__ == "__main__":
    start_thread()
    app = QApplication(sys.argv)
    myWindow = MyWindow()
    myWindow.setWindowFlags(Qt.FramelessWindowHint)
    myWindow.show()
    app.exec_()