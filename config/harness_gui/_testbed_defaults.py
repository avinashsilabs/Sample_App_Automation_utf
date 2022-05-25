import re


def dynamic_load(path, regex):  # returns the list of matched
    list_temp = list(path.keys())  # expression values from a list
    list_regex = re.compile(regex)
    new_list = list(filter(list_regex.match, list_temp))
    return new_list


def load_testbed(self, yaml_dict):
    if 'dut' in self.yaml_dict['defaults'].keys():
        self.ui.dut_btn.clear()
        self.ui.dut_btn.addItem('None')
        new_list = dynamic_load(self.yaml_dict['devices'], '^rs')
        for temp in new_list:
            self.ui.dut_btn.addItem(temp)
        self.ui.dut_btn.setCurrentText(self.yaml_dict['defaults']['dut'])
    else:
        self.ui.dut_btn.setEnabled(False)

    if 'efx32' in self.yaml_dict['defaults'].keys():
        self.ui.efx_btn.clear()
        self.ui.efx_btn.addItem('None')
        new_list = dynamic_load(self.yaml_dict['devices'], '^efr')
        for temp in new_list:
            self.ui.efx_btn.addItem(temp)
        self.ui.efx_btn.setCurrentText(self.yaml_dict['defaults']['efx32'])
    else:
        self.ui.efx_btn.setEnabled(False)

    if 'wifi_access_point' in self.yaml_dict['defaults'].keys():
        self.ui.wiap_btn.clear()
        self.ui.wiap_btn.addItem('None')
        new_list = dynamic_load(self.yaml_dict['devices'], ".*_ap")
        for temp in new_list:
            self.ui.wiap_btn.addItem(temp)
        self.ui.wiap_btn.setCurrentText(self.yaml_dict['defaults']['wifi_access_point'])
    else:
        self.ui.wiap_btn.setEnabled(False)

    if 'wifi_client' in self.yaml_dict['defaults'].keys():
        if 'wifi_clients' in self.yaml_dict['defaults'].keys():
            self.ui.wicl_btn.clear()
            self.ui.wicl_btn.addItem('None')
            new_list = self.yaml_dict['defaults']['wifi_clients']
            for temp in new_list:
                self.ui.wicl_btn.addItem(temp)
            self.ui.wicl_btn.setCurrentText(self.yaml_dict['defaults']['wifi_client'])
        else:
            self.ui.wicl_btn.addItem(self.yaml_dict['defaults']['wifi_client'])
            self.ui.wicl_btn.setCurrentText(self.yaml_dict['defaults']['wifi_client'])
    else:
        self.ui.wicl_btn.setEnabled(False)

    if 'wifi_sniffer' in self.yaml_dict['defaults'].keys():
        self.ui.wisn_btn.clear()
        self.ui.wisn_btn.addItem('None')
        self.ui.wisn_btn.addItem(self.yaml_dict['defaults']['wifi_sniffer'])
        self.ui.wisn_btn.setCurrentText(self.yaml_dict['defaults']['wifi_sniffer'])
    else:
        self.ui.wisn_btn.setEnabled(False)

    if 'ble_client' in self.yaml_dict['defaults'].keys():
        if 'ble_clients' in self.yaml_dict['defaults'].keys():
            self.ui.blcl_btn.clear()
            self.ui.blcl_btn.addItem('None')
            new_list = self.yaml_dict['defaults']['ble_clients']
            for temp in new_list:
                self.ui.blcl_btn.addItem(temp)
            self.ui.blcl_btn.setCurrentText(self.yaml_dict['defaults']['ble_client'])
        else:
            self.ui.blcl_btn.addItem(self.yaml_dict['defaults']['ble_client'])
            self.ui.blcl_btn.setCurrentText(self.yaml_dict['defaults']['ble_client'])

    else:
        self.ui.blcl_btn.setEnabled(False)

    if 'bt_client' in self.yaml_dict['defaults'].keys():
        self.ui.btcl_btn.clear()
        self.ui.btcl_btn.addItem('None')
        new_list = dynamic_load(self.yaml_dict['devices'], ".*raspi_bt_client")
        for temp in new_list:
            self.ui.btcl_btn.addItem(temp)
        self.ui.btcl_btn.setCurrentText(self.yaml_dict['defaults']['bt_client'])
    else:
        self.ui.btcl_btn.setEnabled(False)

    if 'mqtt_server' in self.yaml_dict['defaults'].keys():
        self.ui.mqse_btn.clear()
        self.ui.mqse_btn.addItem('None')
        new_list = dynamic_load(self.yaml_dict['devices'], "^raspi_mosquitto")
        for temp in new_list:
            self.ui.mqse_btn.addItem(temp)
        self.ui.mqse_btn.setCurrentText(self.yaml_dict['defaults']['mqtt_server'])
    else:
        self.ui.mqse_btn.setEnabled(False)

    if 'mqtt_client' in self.yaml_dict['defaults'].keys():
        self.ui.mqcl_btn.clear()
        self.ui.mqcl_btn.addItem('None')
        self.ui.mqcl_btn.addItem(self.yaml_dict['defaults']['mqtt_client'])
        self.ui.mqcl_btn.setCurrentText(self.yaml_dict['defaults']['mqtt_client'])
    else:
        self.ui.mqcl_btn.setEnabled(False)

    if 'http_server' in self.yaml_dict['defaults'].keys():
        self.ui.htse_btn.clear()
        self.ui.htse_btn.addItem('None')
        new_list = dynamic_load(self.yaml_dict['devices'], "^raspi_lighttpd")
        for temp in new_list:
            self.ui.htse_btn.addItem(temp)
        self.ui.htse_btn.setCurrentText(self.yaml_dict['defaults']['http_server'])
    else:
        self.ui.htse_btn.setEnabled(False)

    if 'http_client' in self.yaml_dict['defaults'].keys():
        self.ui.htcl_btn.clear()
        self.ui.htcl_btn.addItem('None')
        self.ui.htcl_btn.addItem(self.yaml_dict['defaults']['http_client'])
        self.ui.htcl_btn.setCurrentText(self.yaml_dict['defaults']['http_client'])
    else:
        self.ui.htcl_btn.setEnabled(False)

    if 'ssl_server' in self.yaml_dict['defaults'].keys():
        self.ui.ssse_btn.clear()
        self.ui.ssse_btn.addItem('None')
        new_list = dynamic_load(self.yaml_dict['devices'], "^raspi_ssl_server")
        for temp in new_list:
            self.ui.ssse_btn.addItem(temp)
        self.ui.ssse_btn.setCurrentText(self.yaml_dict['defaults']['ssl_server'])
    else:
        self.ui.ssse_btn.setEnabled(False)

    if 'rf_attenuator' in self.yaml_dict['defaults'].keys():
        self.ui.ssse_btn_2.clear()
        self.ui.ssse_btn_2.addItem('None')
        self.ui.ssse_btn_2.addItem(self.yaml_dict['defaults']['rf_attenuator'])
        self.ui.ssse_btn_2.setCurrentText(self.yaml_dict['defaults']['rf_attenuator'])
    else:
        self.ui.ssse_btn_2.setEnabled(False)

    if 'logic_analyzer' in self.yaml_dict['defaults'].keys():
        self.ui.logic_btn.clear()
        self.ui.logic_btn.addItem('None')
        self.ui.logic_btn.addItem(self.yaml_dict['defaults']['logic_analyzer'])
        self.ui.logic_btn.setCurrentText(self.yaml_dict['defaults']['logic_analyzer'])
    else:
        self.ui.logic_btn.setEnabled(False)


def save_testbed(self, yaml_dict):
    if 'dut' in yaml_dict['defaults'].keys():
        yaml_dict['defaults']['dut'] = self.ui.dut_btn.currentText()

    if 'efx32' in yaml_dict['defaults'].keys():
        yaml_dict['defaults']['efx32'] = self.ui.efx_btn.currentText()

    if 'wifi_access_point' in yaml_dict['defaults'].keys():
        yaml_dict['defaults']['wifi_access_point'] = self.ui.wiap_btn.currentText()

    if 'wifi_client' in yaml_dict['defaults'].keys():
        yaml_dict['defaults']['wifi_client'] = self.ui.wicl_btn.currentText()

    if 'wifi_sniffer' in yaml_dict['defaults'].keys():
        yaml_dict['defaults']['wifi_sniffer'] = self.ui.wisn_btn.currentText()

    if 'ble_client' in yaml_dict['defaults'].keys():
        yaml_dict['defaults']['ble_client'] = self.ui.blcl_btn.currentText()

    if 'bt_client' in yaml_dict['defaults'].keys():
        yaml_dict['defaults']['bt_client'] = self.ui.btcl_btn.currentText()

    if 'mqtt_server' in yaml_dict['defaults'].keys():
        yaml_dict['defaults']['mqtt_server'] = self.ui.mqse_btn.currentText()

    if 'mqtt_client' in yaml_dict['defaults'].keys():
        yaml_dict['defaults']['mqtt_client'] = self.ui.mqcl_btn.currentText()

    if 'http_server' in yaml_dict['defaults'].keys():
        yaml_dict['defaults']['http_server'] = self.ui.htse_btn.currentText()

    if 'http_client' in yaml_dict['defaults'].keys():
        yaml_dict['defaults']['http_client'] = self.ui.htcl_btn.currentText()

    if 'ssl_server' in yaml_dict['defaults'].keys():
        yaml_dict['defaults']['ssl_server'] = self.ui.ssse_btn.currentText()

    if 'rf_attenuator' in yaml_dict['defaults'].keys():
        yaml_dict['defaults']['rf_attenuator'] = self.ui.ssse_btn_2.currentText()

    if 'logic_analyzer' in yaml_dict['defaults'].keys():
        yaml_dict['defaults']['logic_analyzer'] = self.ui.logic_btn.currentText()
