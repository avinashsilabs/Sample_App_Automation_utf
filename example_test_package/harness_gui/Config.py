#########################################################################################################################


# MAIN FILE TO RUN HARNESS_EDITOR


########################################################################################################################
import sys
import os
import ruamel.yaml
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QFileDialog, QMainWindow, QMessageBox
from PyQt5 import QtCore

from Application import Ui_MainWindow

from _testbed_defaults import load_testbed, save_testbed
from _WiFiSettings import load_wifi, save_wifi
from _http_mqtt import load_http_mqtt, save_http_mqtt
from _sniffer import load_wifi_sniffer, save_wifi_sniffer
from _raspberry import load_raspi_wifi_ssh, save_raspberry
from _switch_ap_settings import wifi_clients, ble_clients, switch_ap
from _clear_event import clear_application


# defined a event that quits the current application
def quit_btn_event():
    sys.exit(app.exec_())


class Base:
    def __init__(self, file_path):
        self.main_win = QMainWindow()
        self.ui = Ui_MainWindow()  # ui is a object of Ui_MainWindow() Class
        self.ui.setupUi(self.main_win)  # we made a call to setupUi method
        self.main_win.setWindowIcon(QIcon("Silicon.jpg"))
        # self.main_win.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        self.main_win.setAttribute(QtCore.Qt.WA_TranslucentBackground)

        self.file_path = file_path  # file_path is accessible throughout the Base Class
        self.yaml_dict = {}
        self.ui.frame_1.setEnabled(False)
        self.ui.frame.setEnabled(False)
        self.ui.groupBox_tab2.setEnabled(False)
        self.ui.groupBox1_tab2.setEnabled(False)
        self.ui.static_httpgroupBox.setEnabled(False)
        self.ui.static_mqttlabelBox.setEnabled(False)
        self.ui.capture_groupBox.setEnabled(False)
        self.ui.local_shell_groupBox.setEnabled(False)
        self.ui.groupBox_8.setEnabled(False)
        self.ui.wible_frame1.setEnabled(False)
        self.ui.wible_frame2.setEnabled(False)

        self.ui.pushButton.clicked.connect(self.load_btn_event)
        self.ui.pushButton_4.clicked.connect(quit_btn_event)
        self.ui.pushButton_2.clicked.connect(self.save_btn_event)
        self.ui.pushButton_3.clicked.connect(self.clear_btn_event)
        self.ui.wiap_btn.currentTextChanged.connect(self.switch_ap_settings)
        self.ui.comboBox_4.currentTextChanged.connect(self.switch_ble_clients)
        self.ui.comboBox_5.currentTextChanged.connect(self.switch_wifi_clients)

    def show(self):
        self.main_win.show()

    def OpenFileDialog(self):
        file = QFileDialog.getOpenFileName(self.main_win, 'Open File', self.file_path, 'YAML Files(*.yaml)')
        if not file:
            return
        else:
            return file[0]

    def load_btn_event(self):

        # Enable the essential frames

        self.ui.frame_1.setEnabled(True)  # Enable the testbed defaults frame
        self.ui.frame.setEnabled(True)  # Enable the testbed defaults frame
        self.ui.static_httpgroupBox.setEnabled(True)  # Enable the http settings
        self.ui.static_mqttlabelBox.setEnabled(True)  # Enable the mqtt settings
        self.ui.capture_groupBox.setEnabled(True)  # Enable the airpcap settings
        self.ui.local_shell_groupBox.setEnabled(True)  # Enable the airpcap settings
        self.ui.groupBox_8.setEnabled(True)  # Enable raspi_wifi_ssh settings
        self.ui.wible_frame1.setEnabled(True)  # Enable wifi clients
        self.ui.wible_frame2.setEnabled(True)  # Enable ble clients

        # Open the yaml file and specify the path

        yaml = ruamel.yaml.YAML()
        yaml.preserve_quotes = True
        self.file_path = self.OpenFileDialog()
        with open(self.file_path) as f:
            yaml_dict = yaml.load(f)  # load_yaml_dict is the loaded dictionary
        self.yaml_dict = yaml_dict

        # Load all testbed defaults

        load_testbed(self, self.yaml_dict)

        # Load the WiFi Settings according to wifi_access_point

        load_wifi(self, self.yaml_dict)

        # load static_http Settings

        load_http_mqtt(self, self.yaml_dict)

        # load airpcap settings

        load_wifi_sniffer(self, self.yaml_dict)

        # load raspi_wifi_ssh settings

        load_raspi_wifi_ssh(self, self.yaml_dict)

    def save_btn_event(self):  # Is used to save changes to yaml file.

        # Save the changes against key values in YAML file

        save_testbed(self, self.yaml_dict)

        # Saving the wifi_clients and ble_clients and ap settings

        save_wifi(self, self.yaml_dict)

        # static_http settings are saved

        save_http_mqtt(self, self.yaml_dict)

        # airpcap settings are saved

        save_wifi_sniffer(self, self.yaml_dict)

        # raspi_wifi_ssh settings are saved

        save_raspberry(self, self.yaml_dict)

        # Dumping the changes back to the YAML file.

        yaml = ruamel.yaml.YAML()
        with open(self.file_path, 'w') as f:
            yaml.dump(self.yaml_dict, f)
        # MessageBox will confirm the user that the changes have been saved.
        msg = QMessageBox()
        msg.setWindowIcon(QIcon("Silicon.jpg"))
        msg.setWindowTitle("Confirmation")
        msg.setText("User Changes have been saved successfully!!!")
        msg.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        msg.setStyleSheet("border-radius:10px;background-color: black; color: white")
        msg.setIcon(QMessageBox.Information)
        msg.exec_()

    def clear_btn_event(self):
        clear_application(self)

    def switch_ap_settings(self):
        switch_ap(self, self.yaml_dict)

    def switch_ble_clients(self):
        ble_clients(self, self.yaml_dict)

    def switch_wifi_clients(self):
        wifi_clients(self, self.yaml_dict)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    temp = "../../config/harnesses"
    main_win = Base(temp)
    main_win.show()
    sys.exit(app.exec_())
