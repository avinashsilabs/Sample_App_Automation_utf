def load_wifi_sniffer(self,yaml_dict):
    if 'type' in yaml_dict['devices']['airpcap']['interfaces']['capture'].keys():
        self.ui.typeLineEdit_4.setText(yaml_dict['devices']['airpcap']['interfaces']['capture']['type'])
    else:
        self.ui.typeLineEdit_4.setEnabled(False)

    if 'shell' in yaml_dict['devices']['airpcap']['interfaces']['capture'].keys():
        self.ui.shellLineEdit.setText(yaml_dict['devices']['airpcap']['interfaces']['capture']['shell'])
    else:
        self.ui.shellLineEdit.setEnabled(False)

    if 'interface' in yaml_dict['devices']['airpcap']['interfaces']['capture'].keys():
        self.ui.interfaceLineEdit.setText(
            yaml_dict['devices']['airpcap']['interfaces']['capture']['interface'])
    else:
        self.ui.interfaceLineEdit.setEnabled(False)

    if 'type' in yaml_dict['devices']['airpcap']['interfaces']['local_shell'].keys():
        self.ui.typeLineEdit_3.setText(yaml_dict['devices']['airpcap']['interfaces']['local_shell']['type'])
    else:
        self.ui.typeLineEdit_3.setEnabled(False)

    if 'remote' in yaml_dict['devices']['airpcap']['interfaces']['local_shell'].keys():
        self.ui.remoteLineEdit.setText(yaml_dict['devices']['airpcap']['interfaces']['local_shell']['remote'])
    else:
        self.ui.remoteLineEdit.setEnabled(False)
    if 'username' in yaml_dict['devices']['airpcap']['interfaces']['local_shell'].keys():
        self.ui.usernameLineEdit.setText(
            yaml_dict['devices']['airpcap']['interfaces']['local_shell']['username'])
    else:
        self.ui.usernameLineEdit.setEnabled(False)

    if 'password' in yaml_dict['devices']['airpcap']['interfaces']['local_shell'].keys():
        self.ui.passwordLineEdit_2.setText(
            yaml_dict['devices']['airpcap']['interfaces']['local_shell']['password'])
    else:
        self.ui.passwordLineEdit_2.setEnabled(False)

    if 'use_paramiko_expect' in yaml_dict['devices']['airpcap']['interfaces']['local_shell'].keys():
        if yaml_dict['devices']['airpcap']['interfaces']['local_shell']['use_paramiko_expect']:
            self.ui.comboBox_2.setCurrentText('true')
        else:
            self.ui.comboBox_2.setCurrentText('false')
    else:
        self.ui.comboBox_2.setEnabled(False)

def save_wifi_sniffer(self,yaml_dict):
    if 'type' in yaml_dict['devices']['airpcap']['interfaces']['capture'].keys():
        yaml_dict['devices']['airpcap']['interfaces']['capture']['type'] = self.ui.typeLineEdit_4.text()
    if 'shell' in yaml_dict['devices']['airpcap']['interfaces']['capture'].keys():
        yaml_dict['devices']['airpcap']['interfaces']['capture']['shell'] = self.ui.shellLineEdit.text()
    if 'interface' in yaml_dict['devices']['airpcap']['interfaces']['capture'].keys():
        yaml_dict['devices']['airpcap']['interfaces']['capture']['interface'] = self.ui.interfaceLineEdit.text()

    if 'type' in yaml_dict['devices']['airpcap']['interfaces']['local_shell'].keys():
        yaml_dict['devices']['airpcap']['interfaces']['local_shell']['type'] = self.ui.typeLineEdit_3.text()
    if 'remote' in yaml_dict['devices']['airpcap']['interfaces']['local_shell'].keys():
        yaml_dict['devices']['airpcap']['interfaces']['local_shell']['remote'] = self.ui.remoteLineEdit.text()
    if 'username' in yaml_dict['devices']['airpcap']['interfaces']['local_shell'].keys():
        yaml_dict['devices']['airpcap']['interfaces']['local_shell'][
            'username'] = self.ui.usernameLineEdit.text().strip()
    if 'password' in yaml_dict['devices']['airpcap']['interfaces']['local_shell'].keys():
        yaml_dict['devices']['airpcap']['interfaces']['local_shell']['password'] = self.ui.passwordLineEdit_2.text()
    if 'use_parmiko_expect' in yaml_dict['devices']['airpcap']['interfaces']['local_shell'].keys():
        if self.ui.comboBox_2.currentText() == 'true':
            yaml_dict['devices']['airpcap']['interfaces']['local_shell'][
                'use_parmiko_except'] = True
        else:
            yaml_dict['devices']['airpcap']['interfaces']['local_shell'][
                'use_parmiko_except'] = False
