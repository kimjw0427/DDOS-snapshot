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


check_alarm = True
check_defender = False
check_syn = True
check_icmp = True
check_udp = True
check_http = True
check_ntp = True
check_ssdp = True
check_tcp = True
check_dns = True


def start_thread():
    online_thread = Thread(target=online)
    online_thread.daemon = True
    online_thread.start()
    traffic_thread = Thread(target=detect_traffic)
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

    def refresh_status(self):
        self.status_console.setText(f'{traffic_result} Packets/sec\nTotal: {total_traffic_result}')
        if(traffic_result > danger_traffic_limit):
            self.light.setPixmap(QPixmap(danger_icon))
        else:
            self.light.setPixmap(QPixmap(None))

    def click_trayicon(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            self.show()

    def window_exit(self):
        self.trayIcon.showMessage(
            "DDOS Snapshot",
            "프로그램이 꺼졌습니다. DDOS 탐지가 비활성화됩니다.",
            QSystemTrayIcon.Information,
            2000
        )
        sys.exit(app.exec_())

    def closeEvent(self, event):
        event.ignore()
        self.window_minimize()

    def window_minimize(self):
        self.hide()
        self.trayIcon.showMessage(
            "DDOS Snapshot",
            "백그라운드 상태입니다.",
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
        global check_alarm
        if self.checkbox_alarm.isChecked():
            self.checkbox_alarm.setChecked(False)
            check_alarm = False
        else:
            self.checkbox_alarm.setChecked(True)
            check_alarm = True

    def change_image_defender(self):
        if self.checkbox_defender.isChecked():
            self.icon_defender.setPixmap(QPixmap(image_on))
        else:
            self.icon_defender.setPixmap(QPixmap(image_off))

    def change_checkbox_defender(self):
        global check_defender
        if self.checkbox_defender.isChecked():
            self.checkbox_defender.setChecked(False)
            check_defender = False
        else:
            self.checkbox_defender.setChecked(True)
            check_defender = True

    def change_image_syn(self):
        if self.checkbox_syn.isChecked():
            self.icon_syn.setPixmap(QPixmap(image_on))
        else:
            self.icon_syn.setPixmap(QPixmap(image_off))

    def change_checkbox_syn(self):
        global check_syn
        if self.checkbox_syn.isChecked():
            self.checkbox_syn.setChecked(False)
            check_syn = False
        else:
            self.checkbox_syn.setChecked(True)
            check_syn = True

    def change_image_icmp(self):
        if self.checkbox_icmp.isChecked():
            self.icon_icmp.setPixmap(QPixmap(image_on))
        else:
            self.icon_icmp.setPixmap(QPixmap(image_off))

    def change_checkbox_icmp(self):
        global check_icmp
        if self.checkbox_icmp.isChecked():
            self.checkbox_icmp.setChecked(False)
            check_icmp = False
        else:
            self.checkbox_icmp.setChecked(True)
            check_tcp = True

    def change_image_udp(self):
        if self.checkbox_udp.isChecked():
            self.icon_udp.setPixmap(QPixmap(image_on))
        else:
            self.icon_udp.setPixmap(QPixmap(image_off))

    def change_checkbox_udp(self):
        global check_udp
        if self.checkbox_udp.isChecked():
            self.checkbox_udp.setChecked(False)
            check_udp = False
        else:
            self.checkbox_udp.setChecked(True)
            check_udp = True

    def change_image_http(self):
        if self.checkbox_http.isChecked():
            self.icon_http.setPixmap(QPixmap(image_on))
        else:
            self.icon_http.setPixmap(QPixmap(image_off))

    def change_checkbox_http(self):
        global check_http
        if self.checkbox_http.isChecked():
            self.checkbox_http.setChecked(False)
            check_http = False
        else:
            self.checkbox_http.setChecked(True)
            check_http = True

    def change_image_ntp(self):
        if self.checkbox_ntp.isChecked():
            self.icon_ntp.setPixmap(QPixmap(image_on))
        else:
            self.icon_ntp.setPixmap(QPixmap(image_off))

    def change_checkbox_ntp(self):
        global check_ntp
        if self.checkbox_ntp.isChecked():
            self.checkbox_ntp.setChecked(False)
            check_ntp = False
        else:
            self.checkbox_ntp.setChecked(True)
            check_ntp = True

    def change_image_ssdp(self):
        if self.checkbox_ssdp.isChecked():
            self.icon_ssdp.setPixmap(QPixmap(image_on))
        else:
            self.icon_ssdp.setPixmap(QPixmap(image_off))

    def change_checkbox_ssdp(self):
        global check_ssdp
        if self.checkbox_ssdp.isChecked():
            self.checkbox_ssdp.setChecked(False)
            check_ssdp = False
        else:
            self.checkbox_ssdp.setChecked(True)
            check_ssdp = True

    def change_image_tcp(self):
        if self.checkbox_tcp.isChecked():
            self.icon_tcp.setPixmap(QPixmap(image_on))
        else:
            self.icon_tcp.setPixmap(QPixmap(image_off))

    def change_checkbox_tcp(self):
        global check_tcp
        if self.checkbox_tcp.isChecked():
            self.checkbox_tcp.setChecked(False)
            check_tcp = False
        else:
            self.checkbox_tcp.setChecked(True)
            check_tcp = True

    def change_image_dns(self):
        if self.checkbox_dns.isChecked():
            self.icon_dns.setPixmap(QPixmap(image_on))
        else:
            self.icon_dns.setPixmap(QPixmap(image_off))

    def change_checkbox_dns(self):
        global check_dns
        if self.checkbox_dns.isChecked():
            self.checkbox_dns.setChecked(False)
            check_dns = False
        else:
            self.checkbox_dns.setChecked(True)
            check_dns = True


if __name__ == "__main__":
    start_thread()
    app = QApplication(sys.argv)
    myWindow = MyWindow()
    myWindow.setWindowFlags(Qt.FramelessWindowHint)
    myWindow.show()
    app.exec_()
