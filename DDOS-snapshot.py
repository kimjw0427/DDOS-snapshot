#-*- coding:utf-8 -*-

from PyQt5 import uic
from PyQt5.QtWidgets import*
from PyQt5.QtCore import*
from PyQt5.QtGui import*
from scapy.all import *
import os
import ctypes

form_class = uic.loadUiType("GUI\MyWindow.ui")[0]

image_on = 'GUI/__ON.png'
image_off = 'GUI/__OFF.png'

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

        self.exit.clicked.connect(self.window_exit)
        self.minimize.clicked.connect(self.window_minimize)
        self.reset.clicked.connect(self.reset_option)

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

    def reset_option(self):
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
    app = QApplication(sys.argv)
    myWindow = MyWindow()
    myWindow.setWindowFlags(Qt.FramelessWindowHint)
    myWindow.show()
    app.exec_()