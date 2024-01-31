import pytest
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode, Si91xCoexMode, Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xBTFeatureBitMap, Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap, Si91xConfigFeatureBitMap, Si91xSHA)
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI


def logger():
    return get_logger(__name__)


input_message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"

"""
    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan mode for 2.4Ghz
        2. compute sha output with sha mode 256 and digest length 32
        3. compute sha output with sha mode 384 and digest length 48
        4. compute sha output with sha mode 512 and digest length 64
        5. compute sha output with sha mode 224 and digest length 28
        6. compute sha output with sha mode 1 and digest length 20

     Author: Harshitha 

"""


class WLanThread(ThreadBase):
    def __init__(self, wifi_dut=None, test_case=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.test_case = test_case

    def run(self):
        try:
            if self.test_case == 215174:
                expected_digest_data = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
                digest = self.wifi_dut.interfaces.wifi.compute_sha_digest(sha_type=Si91xSHA.SL_SI91x_SHA_256,
                                                                          msg=input_message)
                logger().info(f"digest is -> {digest}")
                split_data = digest.decode('utf-8').split(':')
                final_digest_data = split_data[-1].strip()
                logger().info(f"{final_digest_data}")
                output = len(final_digest_data) / 2
                length = int(output)
                logger().info(f"digest length for sha 256 mode is {length}")
                assert final_digest_data == expected_digest_data, "Digest data of sha 256 mode and " \
                                                                  "expected digest ore not same"
                logger().info(f"Digest data of sha 256 mode : {final_digest_data} and"
                              f" Expected digest data of sha 256 mode :{expected_digest_data} are matched")

            if self.test_case == 215175:
                expected_digest_data = "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712f" \
                                       "cc7c71a557e2db966c3e9fa91746039"
                digest = self.wifi_dut.interfaces.wifi.compute_sha_digest(sha_type=Si91xSHA.SL_SI91x_SHA_384,
                                                                          msg=input_message)
                logger().info(f"digest is -> {digest}")
                split_data = digest.decode('utf-8').split(':')
                final_digest_data = split_data[-1].strip()
                logger().info(f"{final_digest_data}")
                output = len(final_digest_data) / 2
                length = int(output)
                logger().info(f"digest length for sha 384 mode is {length}")
                assert final_digest_data == expected_digest_data, "Digest data of sha 384 mode and " \
                                                                  "expected digest ore not same"
                logger().info(f"Digest data of sha 384 mode : {final_digest_data} and"
                              f" Expected digest data of sha 384 mode :{expected_digest_data} are matched")

            if self.test_case == 215176:
                expected_digest_data = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289" \
                                       "e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
                digest = self.wifi_dut.interfaces.wifi.compute_sha_digest(sha_type=Si91xSHA.SL_SI91x_SHA_512,
                                                                          msg=input_message)
                logger().info(f"digest is -> {digest}")
                split_data = digest.decode('utf-8').split(':')
                final_digest_data = split_data[-1].strip()
                logger().info(f"{final_digest_data}")
                output = len(final_digest_data) / 2
                length = int(output)
                logger().info(f"digest length for sha 512 mode is {length}")
                assert final_digest_data == expected_digest_data, "Digest data of sha 512 mode and " \
                                                                  "expected digest ore not same"
                logger().info(f"Digest data of sha 512 mode : {final_digest_data} and"
                              f" Expected digest data of sha 512 mode :{expected_digest_data} are matched")

            if self.test_case == 215177:
                expected_digest_data = "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3"
                digest = self.wifi_dut.interfaces.wifi.compute_sha_digest(sha_type=Si91xSHA.SL_SI91x_SHA_224,
                                                                          msg=input_message)
                logger().info(f"digest is -> {digest}")
                split_data = digest.decode('utf-8').split(':')
                final_digest_data = split_data[-1].strip()
                logger().info(f"{final_digest_data}")
                output = len(final_digest_data) / 2
                length = int(output)
                logger().info(f"digest length for sha 224 mode is {length}")
                assert final_digest_data == expected_digest_data, "Digest data of sha 224 mode and " \
                                                                  "expected digest ore not same"
                logger().info(f"Digest data of sha 224 mode : {final_digest_data} and"
                              f" Expected digest data of sha 224 mode :{expected_digest_data} are matched")

            if self.test_case == 215178:
                expected_digest_data = "a49b2446a02c645bf419f995b67091253a04a259"
                digest = self.wifi_dut.interfaces.wifi.compute_sha_digest(sha_type=Si91xSHA.SL_SI91x_SHA_1,
                                                                          msg=input_message)
                logger().info(f"digest is -> {digest}")
                split_data = digest.decode('utf-8').split(':')
                final_digest_data = split_data[-1].strip()
                output = len(final_digest_data) / 2
                length = int(output)
                logger().info(f"digest length for sha 1 mode is {length}")
                assert final_digest_data == expected_digest_data, "Digest data of sha 1mode and " \
                                                                  "expected digest ore not same"
                logger().info(f"Digest data of sha 1 mode : {final_digest_data} and"
                              f" Expected digest data of sha 1 mode :{expected_digest_data} are matched")

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case} thread: {str(e)} ****\n\n")
            raise e


@pytest.mark.end_state("wifi_dut")
@pytest.mark.config(
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
def test_wifi_sdk_sha_mode_256_digest_length_32_c215174(wifi_dut, sl_collections):
    """Verify sha output with sha mode 256 digest length 32"""
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, test_case=215174)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


def test_wifi_sdk_sha_mode_384_digest_length_48_c215175(wifi_dut, sl_collections):
    """Verify sha output with sha mode 384 digest length 48"""
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, test_case=215175)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


def test_wifi_sdk_sha_mode_512_digest_length_64_c215176(wifi_dut, sl_collections):
    """Verify sha output with sha mode 512 digest length 64"""
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, test_case=215176)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


def test_wifi_sdk_sha_mode_224_digest_length_28_c215177(wifi_dut, sl_collections):
    """Verify sha output with sha mode 224 digest length 28"""
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, test_case=215177)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


def test_wifi_sdk_sha_mode_1_digest_length_20_c215178(wifi_dut, sl_collections):
    """Verify sha output with sha mode 1 digest length 20"""
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, test_case=215178)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
