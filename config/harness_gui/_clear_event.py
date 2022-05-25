def clear_application(self):


    # Cleared all the defaults in testbed defaults:
    self.ui.frame.setEnabled(False)
    self.ui.frame_1.setEnabled(False)
    self.ui.dut_btn.setCurrentText('None')
    self.ui.efx_btn.setCurrentText('None')
    self.ui.wisn_btn.setCurrentText('None')

    self.ui.wiap_btn.setCurrentText('None')
    self.ui.htcl_btn.setCurrentText('None')
    self.ui.htse_btn.setCurrentText('None')
    self.ui.btcl_btn.setCurrentText('None')
    self.ui.mqcl_btn.setCurrentText('None')
    self.ui.mqse_btn.setCurrentText('None')
    self.ui.ssse_btn.setCurrentText('None')
    self.ui.ssse_btn_2.setCurrentText('None')
    self.ui.logic_btn.setCurrentText('None')
    # Cleared all the AP Settings

    self.ui.groupBox1_tab2.setEnabled(False)
    self.ui.groupBox_tab2.setEnabled(False)
    self.ui.iP_ADDRESSLineEdit_3.clear()
    self.ui.securityComboBox_4.setCurrentText('Open')
    self.ui.sSIDLineEdit_4.clear()
    self.ui.passPhraseLineEdit_4.clear()
    self.ui.spinBox.clear()
    self.ui.securityComboBox.setCurrentText('Open')
    self.ui.sSIDLineEdit.clear()
    self.ui.passPhraseLineEdit.clear()
    self.ui.channelSpinBox.clear()
    self.ui.hostNameLineEdit.clear()
    self.ui.userLineEdit.clear()
    self.ui.passwordLineEdit.clear()
    self.ui.outletSpinBox.clear()
    self.ui.user_persistent_stateComboBox.setCurrentText('true')

    # WIFI/BLE Settings

    self.ui.wible_frame1.setEnabled(False)
    self.ui.wible_frame2.setEnabled(False)
    self.ui.comboBox_4.setCurrentText('1')
    self.ui.comboBox_5.setCurrentText('1')
    self.ui.plainTextEdit.clear()
    self.ui.plainTextEdit_2.clear()
    self.ui.wicl_btn.setCurrentText('None')
    self.ui.blcl_btn.setCurrentText('None')

    #  Cleared static_http Settings

    self.ui.static_httpgroupBox.setEnabled(False)
    self.ui.typeLineEdit.clear()
    self.ui.hostnameLineEdit.clear()
    self.ui.portLineEdit.clear()
    self.ui.tls_enabledComboBox.setCurrentText('true')
    self.ui.tls_ca_chainLineEdit.clear()

    # Cleared static_mqtt_broker Settings

    self.ui.static_mqttlabelBox.setEnabled(False)
    self.ui.typeLineEdit_2.clear()
    self.ui.lineEdit.clear()
    self.ui.lineEdit_2.clear()
    self.ui.lineEdit_3.clear()
    self.ui.lineEdit_4.clear()
    self.ui.comboBox.setCurrentText('true')
    self.ui.lineEdit_5.clear()

    # Cleared airpcap Settings

    self.ui.capture_groupBox.setEnabled(False)
    self.ui.local_shell_groupBox.setEnabled(False)
    self.ui.typeLineEdit_4.clear()
    self.ui.shellLineEdit.clear()
    self.ui.interfaceLineEdit.clear()
    self.ui.typeLineEdit_3.clear()
    self.ui.remoteLineEdit.clear()
    self.ui.usernameLineEdit.clear()
    self.ui.passwordLineEdit_2.clear()
    self.ui.comboBox_2.setCurrentText('true')

    # Cleared raspi_wifi_ssh Settings

    self.ui.groupBox_8.setEnabled(False)
    self.ui.remoteLineEdit_2.clear()
    self.ui.usernameLineEdit_2.clear()
    self.ui.passwordLineEdit_3.clear()
    self.ui.comboBox_3.setCurrentText('true')
    self.ui.shellLineEdit_2.clear()
    self.ui.iP_ADDRESSLineEdit_3.clear()
    self.ui.sSIDLineEdit_2.clear()
    self.ui.passphraseLineEdit.clear()
    self.ui.interfaceLineEdit_2.clear()
    self.ui.standardLineEdit.clear()
    self.ui.iP_ADDRESSLineEdit.clear()