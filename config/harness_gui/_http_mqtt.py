def load_http_mqtt(self,yaml_dict):
    if 'type' in yaml_dict['devices']['static_http']['interfaces']['http']:
        self.ui.typeLineEdit.setText(yaml_dict['devices']['static_http']['interfaces']['http']['type'])
    else:
        self.ui.typeLineEdit.setEnabled(False)
    if 'hostname' in yaml_dict['devices']['static_http']['interfaces']['http']:
        self.ui.hostnameLineEdit.setText(yaml_dict['devices']['static_http']['interfaces']['http']['hostname'])
    else:
        self.ui.hostnameLineEdit.setEnabled(False)
    if 'port' in yaml_dict['devices']['static_http']['interfaces']['http']:
        self.ui.portLineEdit.setText(str(yaml_dict['devices']['static_http']['interfaces']['http']['port']))
    else:
        self.ui.portLineEdit.setEnabled(False)

    if 'tls_enabled' in yaml_dict['devices']['static_http']['interfaces']['http']:
        if yaml_dict['devices']['static_http']['interfaces']['http']['tls_enabled']:
            self.ui.tls_enabledComboBox.setCurrentText('true')
        else:
            self.ui.tls_enabledComboBox.setCurrentText('false')
    else:
        self.ui.tls_enabledComboBox.setEnabled(False)
    if 'tls_ca_chain' in yaml_dict['devices']['static_http']['interfaces']['http']:
        self.ui.tls_ca_chainLineEdit.setText(
            yaml_dict['devices']['static_http']['interfaces']['http']['tls_ca_chain'])
    else:
        self.ui.tls_ca_chainLineEdit.setEnabled(False)

    # load static_mqtt_settings

    if 'type' in yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt'].keys():
        self.ui.typeLineEdit_2.setText(
            yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt']['type'])
    else:
        self.ui.typeLineEdit_2.setEnabled(False)

    if 'hostname' in yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt'].keys():
        self.ui.lineEdit.setText(yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt']['hostname'])
    else:
        self.ui.lineEdit.setEnabled(False)
    if 'port' in yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt'].keys():
        self.ui.lineEdit_2.setText(
            str(yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt']['port']))
    else:
        self.ui.lineEdit_2.setEnabled(False)
    if 'username' in yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt'].keys():
        self.ui.lineEdit_3.setText(
            yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt']['username'])
    else:
        self.ui.lineEdit_3.setEnabled(False)
    if 'password' in yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt'].keys():
        self.ui.lineEdit_4.setText(
            yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt']['password'])
    else:
        self.ui.lineEdit_4.setEnabled(False)

    if 'tls_enabled' in yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt'].keys():
        if yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt']['tls_enabled']:
            self.ui.comboBox.setCurrentText('true')
        else:
            self.ui.comboBox.setCurrentText('false')
    else:
        self.ui.comboBox.setEnabled(False)

    if 'tls_ca_chain' in yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt'].keys():
        self.ui.lineEdit_5.setText(
            yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt']['tls_ca_chain'])
    else:
        self.ui.lineEdit_5.setEnabled(False)

def save_http_mqtt(self,yaml_dict):
    if 'type' in yaml_dict['devices']['static_http']['interfaces']['http'].keys():
        yaml_dict['devices']['static_http']['interfaces']['http']['type'] = self.ui.typeLineEdit.text()

    if 'hostname' in yaml_dict['devices']['static_http']['interfaces']['http'].keys():
        yaml_dict['devices']['static_http']['interfaces']['http']['hostname'] = self.ui.hostnameLineEdit.text()

    if 'port' in yaml_dict['devices']['static_http']['interfaces']['http'].keys():
        yaml_dict['devices']['static_http']['interfaces']['http']['port'] = int(self.ui.portLineEdit.text())

    if 'tls_enabled' in yaml_dict['devices']['static_http']['interfaces']['http'].keys():

        if self.ui.tls_enabledComboBox.currentText() == 'true':
            yaml_dict['devices']['static_http']['interfaces']['http']['tls_enabled'] = True
        else:
            yaml_dict['devices']['static_http']['interfaces']['http']['tls_enabled'] = False

    if 'tls_ca_chain' in yaml_dict['devices']['static_http']['interfaces']['http'].keys():
        yaml_dict['devices']['static_http']['interfaces']['http']['tls_ca_chain'] = self.ui.tls_ca_chainLineEdit.text()

    # static_mqtt_broker settings are saved

    if 'type' in yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt'].keys():
        yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt']['type'] = self.ui.typeLineEdit_2.text()
    if 'hostname' in yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt'].keys():
        yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt']['hostname'] = self.ui.lineEdit.text().strip()
    if 'port' in yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt'].keys():
        yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt']['port'] = int(self.ui.lineEdit_2.text())
    if 'username' in yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt'].keys():
        yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt'][
            'username'] = self.ui.lineEdit_3.text().strip()
    if 'password' in yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt'].keys():
        yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt']['password'] = self.ui.lineEdit_4.text()
    if 'tls_enabled' in yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt'].keys():
        if self.ui.comboBox.currentText() == 'true':
            yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt']['tls_enabled'] = True
        else:
            yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt']['tls_enabled'] = False
    if 'tls_ca_chain' in yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt'].keys():
        yaml_dict['devices']['static_mqtt_broker']['interfaces']['mqtt']['tls_ca_chain'] = self.ui.lineEdit_5.text()