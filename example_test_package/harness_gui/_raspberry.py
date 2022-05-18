def load_raspi_wifi_ssh(self, yaml_dict):
    if 'remote' in yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['linux_shell'].keys():
        self.ui.remoteLineEdit_2.setText(
            yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['linux_shell']['remote'])
    else:
        self.ui.remoteLineEdit_2.setEnabled(False)

    if 'username' in yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['linux_shell'].keys():
        self.ui.usernameLineEdit_2.setText(
            yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['linux_shell']['username'])
    else:
        self.ui.usernameLineEdit_2.setEnabled(False)

    if 'password' in yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['linux_shell'].keys():
        self.ui.passwordLineEdit_3.setText(
            yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['linux_shell']['password'])
    else:
        self.ui.passwordLineEdit_3.setEnabled(False)

    if 'use_paramiko_expect' in yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['linux_shell'].keys():
        check = yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['linux_shell']['use_paramiko_expect']
        if check:
            self.ui.comboBox_3.setCurrentText('true')
        else:
            self.ui.comboBox_3.setCurrentText('false')
    else:
        self.ui.comboBox_3.setEnabled(False)

    if 'ip_address' in yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi'].keys():
        self.ui.iP_ADDRESSLineEdit.setText(
            yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi']['ip_address'])
    else:
        self.ui.iP_ADDRESSLineEdit.setEnabled(False)
    if 'shell' in yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi'].keys():
        self.ui.shellLineEdit_2.setText(yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi']['shell'])
    else:
        self.ui.shellLineEdit_2.setEnabled(False)
    if 'ssid' in yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi'].keys():
        self.ui.sSIDLineEdit_2.setText(yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi']['ssid'])
    else:
        self.ui.sSIDLineEdit_2.setEnabled(False)
    if 'passphrase' in yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi'].keys():
        self.ui.passphraseLineEdit.setText(
            yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi']['passphrase'])
    else:
        self.ui.passphraseLineEdit.setEnabled(False)
    if 'interface' in yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi'].keys():
        self.ui.interfaceLineEdit_2.setText(
            yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi']['interface'])
    else:
        self.ui.interfaceLineEdit_2.setEnabled(False)
    if 'standard' in yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi'].keys():
        self.ui.standardLineEdit.setText(
            yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi']['standard'])
    else:
        self.ui.standardLineEdit.setEnabled(False)


def save_raspberry(self, yaml_dict):
    if 'remote' in yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['linux_shell'].keys():
        yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['linux_shell']['remote'] = self.ui.remoteLineEdit_2.text()
    if 'username' in yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['linux_shell'].keys():
        yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['linux_shell'][
            'username'] = self.ui.usernameLineEdit_2.text().strip()
    if 'password' in yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['linux_shell'].keys():
        yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['linux_shell'][
            'password'] = self.ui.passwordLineEdit_3.text()
    if 'use_paramiko_expect' in yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['linux_shell'].keys():
        check = self.ui.comboBox_3.currentText()
        if check == 'true':
            yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['linux_shell']['use_paramiko_expect'] = True
        else:
            yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['linux_shell']['use_paramiko_expect'] = False

    if 'shell' in yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi'].keys():
        yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi']['shell'] = self.ui.shellLineEdit_2.text()
    if 'ip_address' in yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi'].keys():
        yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi'][
            'ip_address'] = self.ui.iP_ADDRESSLineEdit.text()
    if 'ssid' in yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi'].keys():
        yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi']['ssid'] = self.ui.sSIDLineEdit_2.text().strip()
    if 'passphrase' in yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi'].keys():
        yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi']['passphrase'] = self.ui.passphraseLineEdit.text()
    if 'interface' in yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi'].keys():
        yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi']['interface'] = self.ui.interfaceLineEdit_2.text()
    if 'standard' in yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi'].keys():
        yaml_dict['devices']['raspi_wifi_ssh']['interfaces']['wifi']['standard'] = self.ui.standardLineEdit.text()
