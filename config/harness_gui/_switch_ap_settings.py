from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QMessageBox
from PyQt5 import QtCore


def switch_ap(self, yaml_dict):
    if self.ui.wiap_btn.currentText() == 'static_ap':
        self.ui.groupBox1_tab2.setEnabled(True)
        self.ui.groupBox_tab2.setEnabled(False)
        if 'ip_address' in yaml_dict['devices']['static_ap']['interfaces']['wifi'].keys():
            self.ui.iP_ADDRESSLineEdit_3.setEnabled(True)
            self.ui.iP_ADDRESSLineEdit_3.setText(
                yaml_dict['devices']['static_ap']['interfaces']['wifi']['ip_address'])
        else:
            self.ui.iP_ADDRESSLineEdit_3.setEnabled(False)
        if 'security' in yaml_dict['devices']['static_ap']['interfaces']['wifi'].keys():
            self.ui.securityComboBox_4.setEnabled(True)
            self.ui.securityComboBox_4.setCurrentText(
                yaml_dict['devices']['static_ap']['interfaces']['wifi']['security'])
        else:
            self.ui.securityComboBox_4.setEnabled(False)
        if 'ssid' in yaml_dict['devices']['static_ap']['interfaces']['wifi'].keys():
            self.ui.sSIDLineEdit_4.setEnabled(True)
            self.ui.sSIDLineEdit_4.setText(yaml_dict['devices']['static_ap']['interfaces']['wifi']['ssid'])
        else:
            self.ui.sSIDLineEdit_4.setEnabled(False)
        if 'passphrase' in yaml_dict['devices']['static_ap']['interfaces']['wifi'].keys():
            self.ui.passPhraseLineEdit_4.setEnabled(True)
            self.ui.passPhraseLineEdit_4.setText(
                yaml_dict['devices']['static_ap']['interfaces']['wifi']['passphrase'])
        else:
            self.ui.passPhraseLineEdit_4.setEnabled(False)
        if 'channel' in yaml_dict['devices']['static_ap']['interfaces']['wifi'].keys():
            self.ui.spinBox.setEnabled(True)
            self.ui.spinBox.setValue(yaml_dict['devices']['static_ap']['interfaces']['wifi']['channel'])
        else:
            self.ui.spinBox.setEnabled(False)

    elif self.ui.wiap_btn.currentText() == 'dlink_ap':
        self.ui.groupBox1_tab2.setEnabled(True)
        self.ui.groupBox_tab2.setEnabled(False)
        if 'ip_address' in yaml_dict['devices']['dlink_ap']['interfaces']['wifi'].keys():
            self.ui.iP_ADDRESSLineEdit_3.setEnabled(True)
            self.ui.iP_ADDRESSLineEdit_3.setText(
                yaml_dict['devices']['dlink_ap']['interfaces']['wifi']['ip_address'])
        else:
            self.ui.iP_ADDRESSLineEdit_3.setEnabled(False)

        if 'security' in yaml_dict['devices']['dlink_ap']['interfaces']['wifi'].keys():
            self.ui.securityComboBox_4.setEnabled(True)
            self.ui.securityComboBox_4.setCurrentText(
                yaml_dict['devices']['dlink_ap']['interfaces']['wifi']['security'])
        else:
            self.ui.securityComboBox_4.setEnabled(False)

        if 'ssid' in yaml_dict['devices']['dlink_ap']['interfaces']['wifi'].keys():
            self.ui.sSIDLineEdit_4.setEnabled(True)
            self.ui.sSIDLineEdit_4.setText(yaml_dict['devices']['dlink_ap']['interfaces']['wifi']['ssid'])
        else:
            self.ui.sSIDLineEdit_4.setEnabled(False)

        if 'passphrase' in yaml_dict['devices']['dlink_ap']['interfaces']['wifi'].keys():
            self.ui.passPhraseLineEdit_4.setEnabled(True)
            self.ui.passPhraseLineEdit_4.setText(
                yaml_dict['devices']['dlink_ap']['interfaces']['wifi']['passphrase'])
        else:
            self.ui.passPhraseLineEdit_4.setEnabled(False)

        if 'channel' in yaml_dict['devices']['dlink_ap']['interfaces']['wifi'].keys():
            self.ui.spinBox.setEnabled(True)
            self.ui.spinBox.setValue(yaml_dict['devices']['dlink_ap']['interfaces']['wifi']['channel'])
        else:
            self.ui.spinBox.setEnabled(False)

    elif self.ui.wiap_btn.currentText() == 'asus_rt_ax3000_ap':
        self.ui.groupBox1_tab2.setEnabled(True)
        self.ui.groupBox_tab2.setEnabled(False)
        if 'ip_address' in yaml_dict['devices']['asus_rt_ax3000_ap']['interfaces']['wifi'].keys():
            self.ui.iP_ADDRESSLineEdit_3.setEnabled(True)
            self.ui.iP_ADDRESSLineEdit_3.setText(
                yaml_dict['devices']['asus_rt_ax3000_ap']['interfaces']['wifi']['ip_address'])
        else:
            self.ui.iP_ADDRESSLineEdit_3.setEnabled(False)

        if 'security' in yaml_dict['devices']['asus_rt_ax3000_ap']['interfaces']['wifi'].keys():
            self.ui.securityComboBox_4.setEnabled(True)
            self.ui.securityComboBox_4.setCurrentText(
                yaml_dict['devices']['asus_rt_ax3000_ap']['interfaces']['wifi']['security'])
        else:

            self.ui.securityComboBox_4.setEnabled(False)

        if 'ssid' in yaml_dict['devices']['asus_rt_ax3000_ap']['interfaces']['wifi'].keys():
            self.ui.sSIDLineEdit_4.setEnabled(True)
            self.ui.sSIDLineEdit_4.setText(
                yaml_dict['devices']['asus_rt_ax3000_ap']['interfaces']['wifi']['ssid'])
        else:
            self.ui.sSIDLineEdit_4.setEnabled(False)

        if 'passphrase' in yaml_dict['devices']['asus_rt_ax3000_ap']['interfaces']['wifi'].keys():
            self.ui.passPhraseLineEdit_4.setEnabled(True)
            self.ui.passPhraseLineEdit_4.setText(
                yaml_dict['devices']['asus_rt_ax3000_ap']['interfaces']['wifi']['passphrase'])
        else:
            self.ui.passPhraseLineEdit_4.setEnabled(False)

        if 'channel' in yaml_dict['devices']['asus_rt_ax3000_ap']['interfaces']['wifi'].keys():
            self.ui.spinBox.setEnabled(True)
            self.ui.spinBox.setValue(
                yaml_dict['devices']['asus_rt_ax3000_ap']['interfaces']['wifi']['channel'])
        else:
            self.ui.spinBox.setEnabled(False)

    elif self.ui.wiap_btn.currentText() == 'switched_ap':
        self.ui.groupBox_tab2.setEnabled(True)
        self.ui.groupBox1_tab2.setEnabled(False)
        if 'security' in yaml_dict['devices']['switched_ap']['interfaces']['wifi'].keys():
            self.ui.securityComboBox.setEnabled(True)
            self.ui.securityComboBox.setCurrentText(
                yaml_dict['devices']['switched_ap']['interfaces']['wifi']['security'])
        else:
            self.ui.securityComboBox.setEnabled(False)

        if 'ssid' in yaml_dict['devices']['switched_ap']['interfaces']['wifi'].keys():
            self.ui.sSIDLineEdit.setEnabled(True)
            self.ui.sSIDLineEdit.setText(yaml_dict['devices']['switched_ap']['interfaces']['wifi']['ssid'])
        else:
            self.ui.sSIDLineEdit.setEnabled(False)

        if 'passphrase' in yaml_dict['devices']['switched_ap']['interfaces']['wifi'].keys():
            self.ui.passPhraseLineEdit.setEnabled(True)
            self.ui.passPhraseLineEdit.setText(
                yaml_dict['devices']['switched_ap']['interfaces']['wifi']['passphrase'])
        else:
            self.ui.passPhraseLineEdit.setEnabled(False)

        if 'channel' in yaml_dict['devices']['switched_ap']['interfaces']['wifi'].keys():
            self.ui.channelSpinBox.setEnabled(True)
            self.ui.channelSpinBox.setValue(
                yaml_dict['devices']['switched_ap']['interfaces']['wifi']['channel'])
        else:
            self.ui.channelSpinBox.setEnabled(False)

        if 'hostname' in yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch'].keys():
            self.ui.hostnameLineEdit.setEnabled(True)
            self.ui.hostNameLineEdit.setText(
                yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch']['hostname'])
        else:
            self.ui.hostNameLineEdit.setEnabled(False)
        if 'user' in yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch'].keys():
            self.ui.userLineEdit.setEnabled(True)
            self.ui.userLineEdit.setText(
                yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch']['user'])
        else:
            self.ui.userLineEdit.setEnabled(False)
        if 'password' in yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch'].keys():
            self.ui.passwordLineEdit.setEnabled(True)
            self.ui.passwordLineEdit.setText(
                yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch']['password'])
        else:
            self.ui.passwordLineEdit.setEnabled(False)
        if 'outlet' in yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch'].keys():
            self.ui.outletSpinBox.setEnabled(True)
            self.ui.outletSpinBox.setValue(
                yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch']['outlet'])
        else:
            self.ui.outletSpinBox.setEnabled(False)
        if 'use_persistent_state' in yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch'].keys():
            self.ui.user_persistent_stateComboBox.setEnabled(True)
            check = 'true'
            if not yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch']['use_persistent_state']:
                check = 'false'
            self.ui.user_persistent_stateComboBox.setCurrentText(check)
        else:
            self.ui.user_persistent_stateComboBox.setEnabled(False)

    else:
        self.ui.groupBox1_tab2.setEnabled(False)
        self.ui.groupBox_tab2.setEnabled(False)


def wifi_clients(self, yaml_dict):
    selected_num_wifi = int(self.ui.comboBox_5.currentText())
    new_list = list(yaml_dict['defaults']['wifi_clients'])
    self.ui.plainTextEdit_2.clear()
    if selected_num_wifi <= len(new_list):
        for temp in range(selected_num_wifi):
            self.ui.plainTextEdit_2.appendPlainText(new_list[temp])
    else:
        msg = QMessageBox()
        msg.setWindowIcon(QIcon("Silicon.jpg"))
        msg.setWindowTitle("Information")
        msg.setText("WiFi_Clients Limit Exceeded!!!")
        msg.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        msg.setStyleSheet("border-radius:10px;background-color: black; color: white")
        msg.setIcon(QMessageBox.Warning)
        msg.exec_()
        for temp in new_list:
            self.ui.plainTextEdit_2.appendPlainText(temp)


def ble_clients(self, yaml_dict):
    selected_num_ble = int(self.ui.comboBox_4.currentText())
    new_list = list(yaml_dict['defaults']['ble_clients'])
    self.ui.plainTextEdit.clear()
    if selected_num_ble <= len(new_list):
        for temp in range(selected_num_ble):
            self.ui.plainTextEdit.appendPlainText(new_list[temp])
    else:
        msg = QMessageBox()
        msg.setWindowIcon(QIcon("Silicon.jpg"))
        msg.setWindowTitle("Information")
        msg.setText("BLE_Clients Limit Exceeded!!!")
        msg.setWindowFlags(QtCore.Qt.FramelessWindowHint)
        msg.setStyleSheet("border-radius:10px;background-color: black; color: white")
        msg.setIcon(QMessageBox.Information)
        msg.exec_()
        for temp in new_list:
            self.ui.plainTextEdit.appendPlainText(temp)
