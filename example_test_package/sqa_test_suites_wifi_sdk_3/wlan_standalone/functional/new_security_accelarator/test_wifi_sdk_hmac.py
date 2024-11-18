import pytest
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode, Si91xCoexMode, Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xBTFeatureBitMap, Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap, Si91xConfigFeatureBitMap, Si91xKeyType, Si91xHMAC)
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI


def logger():
    return get_logger(__name__)


input_message = "abcdefghbcdefghicdefghijdefghijkefghijklfghsdfghhrdgjb"
key = "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901"

"""
    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan mode for 2.4Ghz
        2. compute hmac sha output with sha mode 1 and digest length 20
        3. compute hmac sha output with sha mode 256 and digest length 32
        4. compute hmac sha output with sha mode 384 and digest length 48
        5. compute hmac sha output with sha mode 512 and digest length 64

     Author: Harshitha 

"""


class WLanThread(ThreadBase):
    def __init__(self, wifi_dut=None, test_case=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.test_case = test_case

    def run(self):
        try:
            if self.test_case == 217757:
                expected_hmac_sha_1_digest_data = "2f66a9920e5bf9b0875836a52ebbdf47769267e0"
                digest = self.wifi_dut.interfaces.wifi.compute_hmac_digest(hmac_mode=Si91xHMAC.SL_SI91X_HMAC_SHA_1,
                                                                           key_type=Si91xKeyType.SL_SI91X_TRANSPARENT_KEY,
                                                                           msg=input_message,
                                                                           key=key)
                logger().info(f"digest is -> {digest}")
                split_data = digest.decode('utf-8').split(':')
                final_digest_data = split_data[-1].strip()
                logger().info(f"{final_digest_data}")
                output = len(final_digest_data)/2
                length = int(output)
                logger().info(f"digest length for hmac sha 1 mode is {length}")
                assert final_digest_data == expected_hmac_sha_1_digest_data, "Digest data of hmac sha 1 mode and " \
                                                                             "expected digest ore not same"
                logger().info(f"Digest data of hmac sha 1 mode : {final_digest_data} and"
                              f" Expected digest data of hmac sha 1 mode :{expected_hmac_sha_1_digest_data} are matched")

            if self.test_case == 217758:
                expected_hmac_sha_256_digest_data = "5d244c9f20c2dab77ffd79ce608fe164ba379282aee87a4dc4f076f6e3e1f1d9"
                digest = self.wifi_dut.interfaces.wifi.compute_hmac_digest(hmac_mode=Si91xHMAC.SL_SI91X_HMAC_SHA_256,
                                                                           key_type=Si91xKeyType.SL_SI91X_TRANSPARENT_KEY,
                                                                           msg=input_message,
                                                                           key=key)
                logger().info(f"digest is -> {digest}")
                split_data = digest.decode('utf-8').split(':')
                final_digest_data = split_data[-1].strip()
                logger().info(f"{final_digest_data}")
                output = len(final_digest_data)/2
                length = int(output)
                logger().info(f"digest length for sha 256 mode is {length}")
                assert final_digest_data == expected_hmac_sha_256_digest_data, "Digest data of hmac sha 256 mode and " \
                                                                               "expected digest ore not same"
                logger().info(f"Digest data of hmac sha 256 mode : {final_digest_data} and"
                              f" Expected digest data of hmac sha 256 mode :{expected_hmac_sha_256_digest_data} are matched")

            if self.test_case == 217759:
                expected_hmac_sha_384_digest_data = "c04a0a686396fb465896bcdd1dd8e2ed4389ff64f793b20321955" \
                                                    "8e8907df3709478aa926c5ded78c8333105bf6926a8"
                digest = self.wifi_dut.interfaces.wifi.compute_hmac_digest(hmac_mode=Si91xHMAC.SL_SI91X_HMAC_SHA_384,
                                                                           key_type=Si91xKeyType.SL_SI91X_TRANSPARENT_KEY,
                                                                           msg=input_message,
                                                                           key=key)
                logger().info(f"digest is -> {digest}")
                split_data = digest.decode('utf-8').split(':')
                final_digest_data = split_data[-1].strip()
                logger().info(f"{final_digest_data}")
                output = len(final_digest_data)/2
                length = int(output)
                logger().info(f"digest length for sha 384 mode is {length}")
                assert final_digest_data == expected_hmac_sha_384_digest_data, "Digest data of hmac sha 384 mode and " \
                                                                               "expected digest ore not same"
                logger().info(f"Digest data of hmac sha 384 mode : {final_digest_data} and"
                              f" Expected digest data of hmac sha 384 mode :{expected_hmac_sha_384_digest_data} are matched")

            if self.test_case == 217760:
                expected_hmac_sha_512_digest_data = "4e7d244a105d5f43c9c14b3234239b57a1d50f48d9b27fa8c9ccb8b69839c029d35061fc2f59e50bc509f3028fa5af2a5e9b29e22c42ae3706029aa1271ab4e5"
                digest = self.wifi_dut.interfaces.wifi.compute_hmac_digest(hmac_mode=Si91xHMAC.SL_SI91X_HMAC_SHA_512,
                                                                           key_type=Si91xKeyType.SL_SI91X_TRANSPARENT_KEY,
                                                                           msg=input_message,
                                                                           key=key)
                logger().info(f"digest is -> {digest}")
                split_data = digest.decode('utf-8').split(':')
                final_digest_data = split_data[-1].strip()
                logger().info(f"{final_digest_data}")
                output = len(final_digest_data)/2
                length = int(output)
                logger().info(f"digest length for sha 512 mode is {length}")
                assert final_digest_data == expected_hmac_sha_512_digest_data, "Digest data of hmac sha 512 mode and " \
                                                                               "expected digest ore not same"
                logger().info(f"Digest data of hmac sha 512 mode : {final_digest_data} and"
                              f" Expected digest data of hmac sha 512 mode :{expected_hmac_sha_512_digest_data} are matched")


        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case} thread: {str(e)} ****\n\n")
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


def test_wifi_sdk_hmac_sha_mode_1_digest_length_20_c217757(wifi_dut, sl_collections):
    """Verify hmac sha output with sha mode 1 digest length 20"""
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, test_case=217757)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


def test_wifi_sdk_hmac_sha_mode_256_digest_length_32_c217758(wifi_dut, sl_collections):
    """Verify hmac sha output with sha mode 256 digest length 32"""
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, test_case=217758)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


def test_wifi_sdk_hmac_sha_mode_384_digest_length_48_c217759(wifi_dut, sl_collections):
    """Verify hmac sha output with sha mode 384 digest length 48"""
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, test_case=217759)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


def test_wifi_sdk_hmac_sha_mode_512_digest_length_32_c217760(wifi_dut, sl_collections):
    """Verify hmac sha output with sha mode 512 digest length 32"""
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, test_case=217760)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
