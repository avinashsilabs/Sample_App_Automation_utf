
def load_wifi(self,yaml_dict):

    access_point = yaml_dict['defaults']['wifi_access_point']

    if access_point != 'switched_ap':
        self.ui.groupBox_tab2.setEnabled(False)
        self.ui.groupBox1_tab2.setEnabled(True)
        if 'ip_address' in yaml_dict['devices'][access_point]['interfaces']['wifi'].keys():
            self.ui.iP_ADDRESSLineEdit_3.setText(
                yaml_dict['devices'][access_point]['interfaces']['wifi']['ip_address'])
        else:
            self.ui.iP_ADDRESSLineEdit_3.setEnabled(False)
        if 'security' in yaml_dict['devices'][access_point]['interfaces']['wifi'].keys():
            self.ui.securityComboBox_4.setCurrentText(
                yaml_dict['devices'][access_point]['interfaces']['wifi']['security'])
        else:
            self.ui.securityComboBox_4.setEnabled(False)
        if 'ssid' in yaml_dict['devices'][access_point]['interfaces']['wifi'].keys():
            self.ui.sSIDLineEdit_4.setText(yaml_dict['devices'][access_point]['interfaces']['wifi']['ssid'])
        else:
            self.ui.sSIDLineEdit_4.setEnabled(False)
        if 'passphrase' in yaml_dict['devices'][access_point]['interfaces']['wifi'].keys():
            self.ui.passPhraseLineEdit_4.setText(
                yaml_dict['devices'][access_point]['interfaces']['wifi']['passphrase'])
        else:
            self.ui.passPhraseLineEdit_4.setEnabled(False)
        if 'channel' in yaml_dict['devices'][access_point]['interfaces']['wifi'].keys():
            self.ui.spinBox.setValue(yaml_dict['devices'][access_point]['interfaces']['wifi']['channel'])
        else:
            self.ui.spinBox.setEnabled(False)

    elif access_point == 'switched_ap':
        self.ui.groupBox1_tab2.setEnabled(False)
        if 'security' in yaml_dict['devices']['switched_ap']['interfaces']['wifi'].keys():
            self.ui.securityComboBox.setCurrentText(
                yaml_dict['devices']['switched_ap']['interfaces']['wifi']['security'])
        else:
            self.ui.securityComboBox.setEnabled(False)

        if 'ssid' in yaml_dict['devices']['switched_ap']['interfaces']['wifi'].keys():
            self.ui.sSIDLineEdit.setText(yaml_dict['devices']['switched_ap']['interfaces']['wifi']['ssid'])
        else:
            self.ui.sSIDLineEdit.setEnabled(False)

        if 'passphrase' in yaml_dict['devices']['switched_ap']['interfaces']['wifi'].keys():
            self.ui.passPhraseLineEdit.setText(
                yaml_dict['devices']['switched_ap']['interfaces']['wifi']['passphrase'])
        else:
            self.ui.passPhraseLineEdit.setEnabled(False)

        if 'channel' in yaml_dict['devices']['switched_ap']['interfaces']['wifi'].keys():
            self.ui.channelSpinBox.setValue(
                yaml_dict['devices']['switched_ap']['interfaces']['wifi']['channel'])
        else:
            self.ui.channelSpinBox.setEnabled(False)

        if 'hostname' in yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch'].keys():
            self.ui.hostNameLineEdit.setText(
                yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch']['hostname'])
        else:
            self.ui.hostNameLineEdit.setEnabled(False)
        if 'user' in yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch'].keys():
            self.ui.userLineEdit.setText(
                yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch']['user'])
        else:
            self.ui.userLineEdit.setEnabled(False)
        if 'password' in yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch'].keys():
            self.ui.passwordLineEdit.setText(
                yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch']['password'])
        else:
            self.ui.passwordLineEdit.setEnabled(False)
        if 'outlet' in yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch'].keys():
            self.ui.outletSpinBox.setValue(
                yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch']['outlet'])
        else:
            self.ui.outletSpinBox.setEnabled(False)
        if 'use_persistent_state' in yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch'].keys():
            check = 'true'
            if not yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch']['use_persistent_state']:
                check = 'false'
            self.ui.user_persistent_stateComboBox.setCurrentText(check)
        else:
            self.ui.user_persistent_stateComboBox.setEnabled(False)
    else:
        self.ui.groupBox1_tab2.setEnabled(False)
        self.ui.groupBox_tab2.setEnabled(False)
    if 'ble_clients' in yaml_dict['defaults'].keys():
        for num in range(1,len(list(yaml_dict['defaults']['ble_clients']))+1):
            self.ui.comboBox_4.addItem(str(num))
        temp = len(yaml_dict['defaults']['ble_clients'])
        self.ui.comboBox_4.setCurrentText(str(temp))

    else:
        self.ui.frame_3.setEnabled(False)
        self.ui.plainTextEdit.setEnabled(False)

    if 'wifi_clients' in yaml_dict['defaults'].keys():
        for num in range(1,(len(list(yaml_dict['defaults']['wifi_clients']))+1)):
            self.ui.comboBox_5.addItem(str(num))
        temp = len(yaml_dict['defaults']['wifi_clients'])
        self.ui.comboBox_5.setCurrentText(str(temp))
    else:
        self.ui.frame_4.setEnabled(False)
        self.ui.plainTextEdit_2.setEnabled(False)


def save_wifi(self,yaml_dict):

    access_point = self.ui.wiap_btn.currentText()
    if access_point == 'dlink_ap':
        if 'ip_address' in yaml_dict['devices']['dlink_ap']['interfaces']['wifi'].keys():
            yaml_dict['devices']['dlink_ap']['interfaces']['wifi']['ip_address'] = self.ui.iP_ADDRESSLineEdit_3.text()
        if 'security' in yaml_dict['devices']['dlink_ap']['interfaces']['wifi'].keys():
            yaml_dict['devices']['dlink_ap']['interfaces']['wifi'][
                'security'] = self.ui.securityComboBox_4.currentText()
        if 'ssid' in yaml_dict['devices']['dlink_ap']['interfaces']['wifi'].keys():
            yaml_dict['devices']['dlink_ap']['interfaces']['wifi']['ssid'] = self.ui.sSIDLineEdit_4.text().strip()
        if 'passphrase' in yaml_dict['devices']['dlink_ap']['interfaces']['wifi'].keys():
            yaml_dict['devices']['dlink_ap']['interfaces']['wifi']['passphrase'] = self.ui.passPhraseLineEdit_4.text()
        if 'channel' in yaml_dict['devices']['dlink_ap']['interfaces']['wifi'].keys():
            yaml_dict['devices']['dlink_ap']['interfaces']['wifi']['channel'] = int(self.ui.spinBox.text())

    elif access_point == 'asus_rt_ax3000_ap':

        if 'ip_address' in yaml_dict['devices']['asus_rt_ax3000_ap']['interfaces']['wifi'].keys():
            yaml_dict['devices']['asus_rt_ax3000_ap']['interfaces']['wifi'][
                'ip_address'] = self.ui.iP_ADDRESSLineEdit_3.text()
        if 'security' in yaml_dict['devices']['asus_rt_ax3000_ap']['interfaces']['wifi'].keys():
            yaml_dict['devices']['asus_rt_ax3000_ap']['interfaces']['wifi'][
                'security'] = self.ui.securityComboBox_4.currentText()
        if 'ssid' in yaml_dict['devices']['asus_rt_ax3000_ap']['interfaces']['wifi'].keys():
            yaml_dict['devices']['asus_rt_ax3000_ap']['interfaces']['wifi'][
                'ssid'] = self.ui.sSIDLineEdit_4.text().strip()
        if 'passphrase' in yaml_dict['devices']['asus_rt_ax3000_ap']['interfaces']['wifi'].keys():
            yaml_dict['devices']['asus_rt_ax3000_ap']['interfaces']['wifi'][
                'passphrase'] = self.ui.passPhraseLineEdit_4.text()
        if 'channel' in yaml_dict['devices']['asus_rt_ax3000_ap']['interfaces']['wifi'].keys():
            yaml_dict['devices']['asus_rt_ax3000_ap']['interfaces']['wifi']['channel'] = int(self.ui.spinBox.text())

    elif access_point == 'static_ap':

        if 'ip_address' in yaml_dict['devices']['static_ap']['interfaces']['wifi'].keys():
            yaml_dict['devices']['static_ap']['interfaces']['wifi']['ip_address'] = self.ui.iP_ADDRESSLineEdit_3.text()
        if 'security' in yaml_dict['devices']['static_ap']['interfaces']['wifi'].keys():
            yaml_dict['devices']['static_ap']['interfaces']['wifi'][
                'security'] = self.ui.securityComboBox_4.currentText()
        if 'ssid' in yaml_dict['devices']['static_ap']['interfaces']['wifi'].keys():
            yaml_dict['devices']['static_ap']['interfaces']['wifi']['ssid'] = self.ui.sSIDLineEdit_4.text().strip()
        if 'passphrase' in yaml_dict['devices']['static_ap']['interfaces']['wifi'].keys():
            yaml_dict['devices']['static_ap']['interfaces']['wifi']['passphrase'] = self.ui.passPhraseLineEdit_4.text()
        if 'channel' in yaml_dict['devices']['static_ap']['interfaces']['wifi'].keys():
            yaml_dict['devices']['static_ap']['interfaces']['wifi']['channel'] = int(self.ui.spinBox.text())

    elif access_point == 'switched_ap':

        if 'security' in yaml_dict['devices']['switched_ap']['interfaces']['wifi'].keys():
            yaml_dict['devices']['switched_ap']['interfaces']['wifi'][
                'security'] = self.ui.securityComboBox.currentText()
        if 'ssid' in yaml_dict['devices']['switched_ap']['interfaces']['wifi'].keys():
            yaml_dict['devices']['switched_ap']['interfaces']['wifi']['ssid'] = self.ui.sSIDLineEdit.text().strip()
        if 'passphrase' in yaml_dict['devices']['switched_ap']['interfaces']['wifi'].keys():
            yaml_dict['devices']['switched_ap']['interfaces']['wifi']['passphrase'] = self.ui.passPhraseLineEdit.text()
        if 'channel' in yaml_dict['devices']['switched_ap']['interfaces']['wifi'].keys():
            yaml_dict['devices']['switched_ap']['interfaces']['wifi']['channel'] = int(self.ui.channelSpinBox.text())
        if 'hostname' in yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch'].keys():
            yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch'][
                'hostname'] = self.ui.hostNameLineEdit.text()
        if 'user' in yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch'].keys():
            yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch'][
                'user'] = self.ui.userLineEdit.text().strip()
        if 'password' in yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch'].keys():
            yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch'][
                'password'] = self.ui.passwordLineEdit.text()
        if 'outlet' in yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch'].keys():
            yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch']['outlet'] = int(
                self.ui.outletSpinBox.text())
        if 'use_persistent_state' in yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch'].keys():
            if self.ui.user_persistent_stateComboBox.currentText() == 'true':
                yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch']['use_persistent_state'] = True
            else:
                yaml_dict['devices']['switched_ap']['interfaces']['pdu_switch']['use_persistent_state'] = False
    if 'wifi_clients' in yaml_dict['defaults']:
        wifi_clients = self.ui.plainTextEdit_2.toPlainText()
        yaml_dict['defaults']['wifi_clients'] = wifi_clients.split("\n")

    if 'ble_clients' in yaml_dict['defaults']:
        ble_clients = self.ui.plainTextEdit.toPlainText()
        yaml_dict['defaults']['ble_clients'] = ble_clients.split("\n")
