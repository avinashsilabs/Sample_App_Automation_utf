import pytest
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode, Si91xCoexMode, Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xBTFeatureBitMap, Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap, Si91xConfigFeatureBitMap, Si91xAesType, Si91xAesOperation, Si91xAesKeySize,
    Si91xKeyType, Si91xWrapIVMode)
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI


def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        
    Test Steps:
        1. Configure the DUT in Wlan mode for 2.4Ghz
        2. Verify aes encryption and decryption with aes key size 128
        3. Verify aes encryption and decryption with aes key size 256
        4. Verify aes encryption and decryption with aes key size 192
        
     Author: Harshitha 
     
"""

class WLanThread(ThreadBase):
    def __init__(self, wifi_dut=None, test_case_no=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.test_case_no = test_case_no

    def run(self):
        try:
            if self.test_case_no == 215179:
                data = "1234567812345678"
                key = "12345678901234567890123456789012"
                encrypted_data = self.wifi_dut.interfaces.wifi.aes_encrypt(aes_mode=Si91xAesType.SL_SI91X_AES_ECB,
                                                                           enc_mode=Si91xAesOperation.SL_SI91X_AES_ENCRYPT,
                                                                           msg=data,
                                                                           key_size=Si91xAesKeySize.SL_SI91X_AES_KEY_SIZE_128,
                                                                           wrap_iv_mode=Si91xWrapIVMode.SL_SI91X_WRAP_IV_ECB_MODE,
                                                                           key_type=Si91xKeyType.SL_SI91X_TRANSPARENT_KEY,
                                                                           key=key)
                logger().info(f"encrypted data is -> {encrypted_data}")
                decrypted_data = self.wifi_dut.interfaces.wifi.aes_decrypt(aes_mode=Si91xAesType.SL_SI91X_AES_ECB,
                                                                           enc_mode=Si91xAesOperation.SL_SI91X_AES_DECRYPT,
                                                                           key_size=Si91xAesKeySize.SL_SI91X_AES_KEY_SIZE_128,
                                                                           wrap_iv_mode=Si91xWrapIVMode.SL_SI91X_WRAP_IV_ECB_MODE,
                                                                           key_type=Si91xKeyType.SL_SI91X_TRANSPARENT_KEY,
                                                                           key=key,
                                                                           msg_len=len(data))
                logger().info(f"decrypted data is -> {decrypted_data}")
                split_data = decrypted_data.decode('utf-8').split(':')
                final_decrypted_data = split_data[-1].strip()
                logger().info(f"{final_decrypted_data}")
                input_message = data
                logger().info(f"*** Input message for encryption :{input_message}"
                              f" Decryption data for message :{final_decrypted_data}*****")
                assert input_message == final_decrypted_data, f"encryption data and decryption data are not matched"
                logger().info("Encryption data and decryption data are both same ")

            if self.test_case_no == 215180:
                data = "12345678901234567890123456789012"
                key = "12345678901234567890123456789012"
                encrypted_data = self.wifi_dut.interfaces.wifi.aes_encrypt(aes_mode=Si91xAesType.SL_SI91X_AES_ECB,
                                                                           enc_mode=Si91xAesOperation.SL_SI91X_AES_ENCRYPT,
                                                                           msg=data,
                                                                           key_size=Si91xAesKeySize.SL_SI91X_AES_KEY_SIZE_256,
                                                                           wrap_iv_mode=Si91xWrapIVMode.SL_SI91X_WRAP_IV_ECB_MODE,
                                                                           key_type=Si91xKeyType.SL_SI91X_TRANSPARENT_KEY,
                                                                           key=key)
                logger().info(f"encrypted data is -> {encrypted_data}")
                decrypted_data = self.wifi_dut.interfaces.wifi.aes_decrypt(aes_mode=Si91xAesType.SL_SI91X_AES_ECB,
                                                                           enc_mode=Si91xAesOperation.SL_SI91X_AES_DECRYPT,
                                                                           key_size=Si91xAesKeySize.SL_SI91X_AES_KEY_SIZE_256,
                                                                           wrap_iv_mode=Si91xWrapIVMode.SL_SI91X_WRAP_IV_ECB_MODE,
                                                                           key_type=Si91xKeyType.SL_SI91X_TRANSPARENT_KEY,
                                                                           key=key,
                                                                           msg_len=len(data))
                logger().info(f"decrypted data is -> {decrypted_data}")
                split_data = decrypted_data.decode('utf-8').split(':')
                final_decrypted_data = split_data[-1].strip()
                logger().info(f"{final_decrypted_data}")
                input_message = data
                logger().info(f"*** Input message for encryption :{input_message}"
                              f" Decryption data for message :{final_decrypted_data}*****")
                assert input_message == final_decrypted_data, f"encryption data and decryption data are not matched"
                logger().info("Encryption data and decryption data are both same ")

            if self.test_case_no == 215181:
                data = "1234567890123456"
                key = "12345678901234567890123456789012"
                encrypted_data = self.wifi_dut.interfaces.wifi.aes_encrypt(aes_mode=Si91xAesType.SL_SI91X_AES_ECB,
                                                                           enc_mode=Si91xAesOperation.SL_SI91X_AES_ENCRYPT,
                                                                           msg=data,
                                                                           key_size=Si91xAesKeySize.SL_SI91X_AES_KEY_SIZE_192,
                                                                           wrap_iv_mode=Si91xWrapIVMode.SL_SI91X_WRAP_IV_ECB_MODE,
                                                                           key_type=Si91xKeyType.SL_SI91X_TRANSPARENT_KEY,
                                                                           key=key)
                logger().info(f"encrypted data is -> {encrypted_data}")
                decrypted_data = self.wifi_dut.interfaces.wifi.aes_decrypt(aes_mode=Si91xAesType.SL_SI91X_AES_ECB,
                                                                           enc_mode=Si91xAesOperation.SL_SI91X_AES_DECRYPT,
                                                                           key_size=Si91xAesKeySize.SL_SI91X_AES_KEY_SIZE_192,
                                                                           wrap_iv_mode=Si91xWrapIVMode.SL_SI91X_WRAP_IV_ECB_MODE,
                                                                           key_type=Si91xKeyType.SL_SI91X_TRANSPARENT_KEY,
                                                                           key=key,
                                                                           msg_len=len(data))
                logger().info(f"decrypted data is -> {decrypted_data}")
                split_data = decrypted_data.decode('utf-8').split(':')
                final_decrypted_data = split_data[-1].strip()
                logger().info(f"{final_decrypted_data}")
                input_message = data
                logger().info(f"*** Input message for encryption :{input_message}"
                              f" Decryption data for message :{final_decrypted_data}*****")
                assert input_message == final_decrypted_data, f"encryption data and decryption data are not matched"
                logger().info("Encryption data and decryption data are both same ")

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case_no} thread: {str(e)} ****\n\n")
            raise e


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
            "oper_mode": Si91xOperatingMode.WiFiClient,
            "coex_mode": Si91xCoexMode.WLANOnly,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client,
            "features": Si91xFeatureBitMap.Default,
            "custom_features": Si91xCustomFeatureBitMap.Default,
            "ext_tcpip_features": 0,
            "config_features": 0,
            "bt_features": 0,
            "ble_features": 0,
            "ble_custom_ext_features": 0,
        },
    )
]


def test_wifi_sdk_aes_encryption_with_key_size_128_c215179(wifi_dut):
    """This test case verify aes encryption with aes key size 128 """
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, test_case_no=215179)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n****** Testcase failed with {e}******")
        raise e


def test_wifi_sdk_aes_encryption_with_key_size_256_c215180(wifi_dut):
    """This test case verify aes encryption with aes key size 256 """
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, test_case_no=215180)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n****** Testcase failed with {e}******")
        raise e


def test_wifi_sdk_aes_encryption_with_key_size_192_c215181(wifi_dut):
    """This test case verify aes encryption with aes key size 192 """
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, test_case_no=215181)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        logger().info(f"\n****** Testcase failed with {e}******")
        raise e