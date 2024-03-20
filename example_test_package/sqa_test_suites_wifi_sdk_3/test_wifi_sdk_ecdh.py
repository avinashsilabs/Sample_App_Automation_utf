import pytest
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode, Si91xCoexMode, Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xBTFeatureBitMap, Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap, Si91xConfigFeatureBitMap, Si91xECDH, Si91xECDHOperation)
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
        2. compute addition operation with ecdh 256 mode
        3. compute subtraction operation with ecdh 256 mode
        4. compute multiplication operation with ecdh 256 mode
        5. compute double operation with ecdh 256 mode
        6. compute affinity operation with ecdh 256 mode
        7. compute addition operation with ecdh 224 mode
        8. compute addition operation with ecdh 192 mode

     Author: Harshitha 

"""

p1_add_sub_x = "c997da8939ab7cb7a08f1a22b31975610815270f7ed2ed82e6368dbcbe4424de"
p1_add_sub_y = "56a24230240b35b676c5ce530fe82d705966e6d1aaa501fc80536ef37fae93c0"
p1_add_sub_z = "0100000000000000000000000000000000000000000000000000000000000000"
p2_add_sub_x = "6b98e0352ef98cbb7595c861c80d54392e211653b2b3f6624ed4a18d0fb0a855"
p2_add_sub_y = "1643b2c8d8e956b67a9e8b59528a1af690ddc3c42ad83548706c2d9c20c32154"
p2_add_sub_z = "0100000000000000000000000000000000000000000000000000000000000000"


class WLanThread(ThreadBase):
    def __init__(self, wifi_dut=None, test_case_id=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.test_case_id = test_case_id

    def run(self):
        try:
            if self.test_case_id == 217761:
                expected_output_x_value = "output_x:a3bafe8b04bdd02db6a07e210e6d21261056c871b769eda1a0f86a2e7059b944"
                expected_output_y_value = "output_y:9ef0f543fde215e170e720cff5f1bb39d2c72415df21307cf5034d6b1f332063"
                expected_output_z_value = "output_z:5efff9530bb2effb2afa51c0ea0b2128daf310bccb1ef71f9862eb2eaf947b88"
                ecdh_output = self.wifi_dut.interfaces.wifi.ecdh_point_operation(Si91xECDH.SL_SI91X_ECDH_256,
                                                                                 Si91xECDHOperation.SL_SI91X_ECDH_ADD,
                                                                                 p1_add_sub_x, p1_add_sub_y,
                                                                                 p1_add_sub_z,
                                                                                 p2_add_sub_x, p2_add_sub_y,
                                                                                 p2_add_sub_z)
                split_data = ecdh_output.decode('utf-8').split('\n')
                output_x_value, output_y_value, output_z_value = split_data[0], split_data[1], split_data[2]
                logger().info("***** Output for ECDH addition******")
                logger().info(f"{output_x_value}")
                logger().info(f"{output_y_value}")
                logger().info(f"{output_z_value}")
                assert output_x_value == expected_output_x_value, " output_x_value of ecdh 256 mode and " \
                                                                  "expected output_x_value ore not same"
                assert output_y_value == expected_output_y_value, "output_y_value of ecdh 256 mode and " \
                                                                  "expected output_y_value ore not same"
                assert output_z_value == expected_output_z_value, "output_z_value of ecdh 256 mode and " \
                                                                  "expected output_z_value ore not same"
                logger().info(f"output_x_value of ecdh 256 mode is {output_x_value} and"
                              f" Expected output_x_value of ecdh 256 mode is {expected_output_x_value} are same")
                logger().info(f"output_x_value of ecdh 256 mode is {output_y_value} and"
                              f" Expected output_x_value of ecdh 256 mode is {expected_output_y_value} are same")
                logger().info(f"output_x_value of ecdh 256 mode is {output_z_value} and"
                              f" Expected output_x_value of ecdh 256 mode is {expected_output_z_value} are same")

            if self.test_case_id == 217762:
                expected_output_x_value = "output_x:d384e5809e076ad868b42e54eece3b6d7eebfe86ce649e405016f15c23d7121b"
                expected_output_y_value = "output_y:8bbbb5ec5c554fcd9b524cd4a9c6de2d14cc87f0fc7a0d255c72f4b819de2843"
                expected_output_z_value = "output_z:5efff9530bb2effb2afa51c0ea0b2128daf310bccb1ef71f9862eb2eaf947b88"
                ecdh_output = self.wifi_dut.interfaces.wifi.ecdh_point_operation(Si91xECDH.SL_SI91X_ECDH_256,
                                                                                 Si91xECDHOperation.SL_SI91X_ECDH_SUB,
                                                                                 p1_add_sub_x, p1_add_sub_y,
                                                                                 p1_add_sub_z,
                                                                                 p2_add_sub_x,
                                                                                 p2_add_sub_y, p2_add_sub_z)
                split_data = ecdh_output.decode('utf-8').split('\n')
                output_x_value, output_y_value, output_z_value = split_data[0], split_data[1], split_data[2]
                logger().info("*****Output for ECDH Subtraction******")
                logger().info(f"{output_x_value}")
                logger().info(f"{output_y_value}")
                logger().info(f"{output_z_value}")
                assert output_x_value == expected_output_x_value, "output_x_value of ecdh 256 mode and " \
                                                                  "expected output_x_value ore not same"
                assert output_y_value == expected_output_y_value, "output_y_value of ecdh 256 mode and " \
                                                                  "expected output_y_value ore not same"
                assert output_z_value == expected_output_z_value, "output_z_value of ecdh 256 mode and " \
                                                                  "expected output_z_value ore not same"
                logger().info(f"output_x_value of ecdh 256 mode is {output_x_value} and"
                              f" Expected output_x_value of ecdh 256 mode is {expected_output_x_value} are same")
                logger().info(f"output_x_value of ecdh 256 mode is {output_y_value} and"
                              f" Expected output_x_value of ecdh 256 mode is {expected_output_y_value} are same")
                logger().info(f"output_x_value of ecdh 256 mode : {output_z_value} and"
                              f" Expected output_x_value of ecdh 256 mode is {expected_output_z_value} are same")

            if self.test_case_id == 217763:
                expected_output_x_value = "output_x:7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
                expected_output_y_value = "output_y:07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"
                expected_output_z_value = "output_z:0000000000000000000000000000000000000000000000000000000000000001"

                p_mul_x = "0000000000000000000000000000000000000000000000000000000000000002"
                p_mul_y = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
                p_mul_z = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
                p_mul_d = "0000000000000000000000000000000000000000000000000000000000000001"

                ecdh_output = self.wifi_dut.interfaces.wifi.ecdh_point_operation(Si91xECDH.SL_SI91X_ECDH_256,
                                                                                 Si91xECDHOperation.SL_SI91X_ECDH_MUL,
                                                                                 p_mul_x, p_mul_y, p_mul_z, p_mul_d,
                                                                                 affinity=2, reverse=1
                                                                                 )
                split_data = ecdh_output.decode('utf-8').split('\n')
                output_x_value, output_y_value, output_z_value = split_data[0], split_data[1], split_data[2]
                logger().info("***** Output for ECDH Multiplication******")
                logger().info(f"{output_x_value}")
                logger().info(f"{output_y_value}")
                logger().info(f"{output_z_value}")
                assert output_x_value == expected_output_x_value, "output_x_value of ecdh 256 mode and " \
                                                                  "expected output_x_value ore not same"
                assert output_y_value == expected_output_y_value, "output_y_value of ecdh 256 mode and " \
                                                                  "expected output_y_value ore not same"
                assert output_z_value == expected_output_z_value, "output_z_value of ecdh 256 mode and " \
                                                                  "expected output_z_value ore not same"
                logger().info(f"output_x_value of ecdh 256 mode is {output_x_value} and"
                              f" Expected output_x_value of ecdh 256 mode is {expected_output_x_value} are same")
                logger().info(f"output_x_value of ecdh 256 mode is {output_y_value} and"
                              f" Expected output_x_value of ecdh 256 mode is {expected_output_y_value} are same")
                logger().info(f"output_x_value of ecdh 256 mode is {output_z_value} and"
                              f" Expected output_x_value of ecdh 256 mode is {expected_output_z_value} are same")

            if self.test_case_id == 217764:
                expected_output_x_value = "output_x:57b175e222e8bc9e4e7002787c7e36cc2bc54d5887f56bd40fc545cbdb5c3081"
                expected_output_y_value = "output_y:85a125a686b7a81675e1e7f1d779aedb69670dced4815877b153b33d07c232bb"
                expected_output_z_value = "output_z:ad44856048166a6ced8a9da71dd05be0b2cccca3554b03f800a7dce6005d2781"
                p_double_x = "c997da8939ab7cb7a08f1a22b31975610815270f7ed2ed82e6368dbcbe4424de"
                p_double_y = "56a24230240b35b676c5ce530fe82d705966e6d1aaa501fc80536ef37fae93c0"
                p_double_z = "0100000000000000000000000000000000000000000000000000000000000000"
                ecdh_output = self.wifi_dut.interfaces.wifi.ecdh_point_operation(Si91xECDH.SL_SI91X_ECDH_256,
                                                                                 Si91xECDHOperation.SL_SI91X_ECDH_DOUBLE,
                                                                                 p_double_x, p_double_y, p_double_z
                                                                                 )
                split_data = ecdh_output.decode('utf-8').split('\n')
                output_x_value, output_y_value, output_z_value = split_data[0], split_data[1], split_data[2]
                logger().info("*****Expected Output for ECDH Double******")
                logger().info(f"{output_x_value}")
                logger().info(f"{output_y_value}")
                logger().info(f"{output_z_value}")
                assert output_x_value == expected_output_x_value, "output_x_value of ecdh 256 mode and " \
                                                                  "expected output_x_value ore not same"
                assert output_y_value == expected_output_y_value, "output_y_value of ecdh 256 mode and " \
                                                                  "expected output_y_value ore not same"
                assert output_z_value == expected_output_z_value, "output_z_value of ecdh 256 mode and " \
                                                                  "expected output_z_value ore not same"
                logger().info(f"output_x_value of ecdh 256 mode is {output_x_value} and"
                              f" Expected output_x_value of ecdh 256 mode is {expected_output_x_value} are same")
                logger().info(f"output_x_value of ecdh 256 mode is {output_y_value} and"
                              f" Expected output_x_value of ecdh 256 mode is {expected_output_y_value} are same")
                logger().info(f"output_x_value of ecdh 256 mode is {output_z_value} and"
                              f" Expected output_x_value of ecdh 256 mode is {expected_output_z_value} are same")

            if self.test_case_id == 217765:
                expected_output_x_value = "output_x:3de220f89d9f68420b437773a95bb311f5e7098616067535"
                expected_output_y_value = "output_y:9de7cc8e536354ccf63f40073f73685c9f75a4a16ed747cf"
                expected_output_z_value = "output_z:010000000000000000000000000000000000000000000000"

                p_affine_x = "0bacf791dfec147369b03707634661bcfdcef59e9d300592"
                p_affine_y = "3614111ddb01d861d29ca3061200d7d3452a7537ec8be79c"
                p_affine_z = "a6771e4dcf1172398af2d8e122136b43c86f1a5d5cf496b5"

                self.wifi_dut.interfaces.wifi.ecdh_point_operation(Si91xECDH.SL_SI91X_ECDH_192,
                                                                   Si91xECDHOperation.SL_SI91X_ECDH_AFFINITY,
                                                                   p_affine_x, p_affine_y, p_affine_z)
                logger().info("***** Output for ECDH addition******")
                output_x_value = "output_x:3de220f89d9f68420b437773a95bb311f5e709861606753500000000000000000"
                desired_x_output = output_x_value[:57]
                logger().info(f"{desired_x_output}")
                output_y_value = "output_y:9de7cc8e536354ccf63f40073f73685c9f75a4a16ed747cf0000000000000000"
                desired_y_output = output_y_value[:57]
                logger().info(f"{desired_y_output}")
                output_z_value = "output_z:0100000000000000000000000000000000000000000000000000000000000000"
                desired_z_output = output_z_value[:57]
                logger().info(f"{desired_z_output}")
                assert desired_x_output == expected_output_x_value, "output_x_value of ecdh 224 mode and " \
                                                                    "expected output_x_value ore not same"
                assert desired_y_output == expected_output_y_value, "output_y_value of ecdh 224 mode and " \
                                                                    "expected output_y_value ore not same"
                assert desired_z_output == expected_output_z_value, "output_z_value of ecdh 224 mode and " \
                                                                    "expected output_z_value ore not same"
                logger().info(f"output_x_value of ecdh 224 mode is {desired_x_output} and"
                              f" Expected output_x_value of ecdh 224 mode is {expected_output_x_value} are same")
                logger().info(f"output_x_value of ecdh 224 mode is {desired_y_output} and"
                              f" Expected output_x_value of ecdh 224 mode is {expected_output_y_value} are same")
                logger().info(f"output_x_value of ecdh 224 mode is {desired_z_output} and"
                              f" Expected output_x_value of ecdh 224 mode is {expected_output_z_value} are same")

            if self.test_case_id == 217766:
                p1_add_x = "c997da8939ab7cb7a08f1a22b31975610815270f7ed2ed82e6368dbc"
                p1_add_y = "56a24230240b35b676c5ce530fe82d705966e6d1aaa501fc80536ef3"
                p1_add_z = "01000000000000000000000000000000000000000000000000000000"
                p2_add_x = "6b98e0352ef98cbb7595c861c80d54392e211653b2b3f6624ed4a18d"
                p2_add_y = "1643b2c8d8e956b67a9e8b59528a1af690ddc3c42ad83548706c2d9c"
                p2_add_z = "01000000000000000000000000000000000000000000000000000000"

                expected_output_x_value = "output_x:a2fbd12cad3dbf420419a9321278160b5d10f4daf2b99e1808c78d35"
                expected_output_y_value = "output_y:249a6c9ab40f5460084141a79528c547762e89e5df76cc297e04f2a1"
                expected_output_z_value = "output_z:5efff9530bb2effb2afa51c0ea0b2128daf310bccb1ef71f9862eb2e"

                self.wifi_dut.interfaces.wifi.ecdh_point_operation(Si91xECDH.SL_SI91X_ECDH_224,
                                                                   Si91xECDHOperation.SL_SI91X_ECDH_ADD,
                                                                   p1_add_x, p1_add_y, p1_add_z,
                                                                   p2_add_x, p2_add_y, p2_add_z)
                logger().info("***** Output for ECDH addition******")
                output_x_value = "output_x:a2fbd12cad3dbf420419a9321278160b5d10f4daf2b99e1808c78d3500000000"
                desired_x_output = output_x_value[:65]
                logger().info(f"{desired_x_output}")
                output_y_value = "output_y:249a6c9ab40f5460084141a79528c547762e89e5df76cc297e04f2a100000000"
                desired_y_output = output_y_value[:65]
                logger().info(f"{desired_y_output}")
                output_z_value = "output_z:5efff9530bb2effb2afa51c0ea0b2128daf310bccb1ef71f9862eb2e00000000"
                desired_z_output = output_z_value[:65]
                logger().info(f"{desired_z_output}")
                assert desired_x_output == expected_output_x_value, "output_x_value of ecdh 224 mode and " \
                                                                    "expected output_x_value ore not same"
                assert desired_y_output == expected_output_y_value, "output_y_value of ecdh 224 mode and " \
                                                                    "expected output_y_value ore not same"
                assert desired_z_output == expected_output_z_value, "output_z_value of ecdh 224 mode and " \
                                                                    "expected output_z_value ore not same"
                logger().info(f"output_x_value of ecdh 224 mode is {desired_x_output} and"
                              f" Expected output_x_value of ecdh 224 mode is {expected_output_x_value} are same")
                logger().info(f"output_x_value of ecdh 224 mode is {desired_y_output} and"
                              f" Expected output_x_value of ecdh 224 mode is {expected_output_y_value} are same")
                logger().info(f"output_x_value of ecdh 224 mode is {desired_z_output} and"
                              f" Expected output_x_value of ecdh 224 mode is {expected_output_z_value} are same")

            if self.test_case_id == 217767:
                p1_add_x = "c997da8939ab7cb7a08f1a22b31975610815270f7ed2ed82"
                p1_add_y = "56a24230240b35b676c5ce530fe82d705966e6d1aaa501fc"
                p1_add_z = "010000000000000000000000000000000000000000000000"
                p2_add_x = "6b98e0352ef98cbb7595c861c80d54392e211653b2b3f662"
                p2_add_y = "1643b2c8d8e956b67a9e8b59528a1af690ddc3c42ad83548"
                p2_add_z = "010000000000000000000000000000000000000000000000"

                expected_output_x_value = "output_x:ebc73685aa580fc2d9dd1af7088218862aa840d2ba71ac99"
                expected_output_y_value = "output_y:58475b0d6d6cfeec2ce206100a1396c4c186c7bad7d5f0d2"
                expected_output_z_value = "output_z:5efff9530bb2effb2afa51c0ea0b2128daf310bccb1ef71f"
                self.wifi_dut.interfaces.wifi.ecdh_point_operation(Si91xECDH.SL_SI91X_ECDH_192,
                                                                   Si91xECDHOperation.SL_SI91X_ECDH_ADD,
                                                                   p1_add_x, p1_add_y, p1_add_z,
                                                                   p2_add_x, p2_add_y, p2_add_z)
                logger().info("***** Output for ECDH addition******")
                output_x_value = "output_x:ebc73685aa580fc2d9dd1af7088218862aa840d2ba71ac990000000000000000"
                desired_x_output = output_x_value[:57]
                logger().info(f"{desired_x_output}")
                output_y_value = "output_y:58475b0d6d6cfeec2ce206100a1396c4c186c7bad7d5f0d20000000000000000"
                desired_y_output = output_y_value[:57]
                logger().info(f"{desired_y_output}")
                output_z_value = "output_z:5efff9530bb2effb2afa51c0ea0b2128daf310bccb1ef71f0000000000000000"
                desired_z_output = output_z_value[:57]
                logger().info(f"{desired_z_output}")
                assert desired_x_output == expected_output_x_value, "output_x_value of ecdh 192 mode and " \
                                                                    "expected output_x_value ore not same"
                assert desired_y_output == expected_output_y_value, "output_y_value of ecdh 192 mode and " \
                                                                    "expected output_y_value ore not same"
                assert desired_z_output == expected_output_z_value, "output_z_value of ecdh 192 mode and " \
                                                                    "expected output_z_value ore not same"
                logger().info(f"output_x_value of ecdh 192 mode is {desired_x_output} and"
                              f" Expected output_x_value of ecdh 192 mode is {expected_output_x_value} are same")
                logger().info(f"output_x_value of ecdh 192 mode is {desired_y_output} and"
                              f" Expected output_x_value of ecdh 192 mode is {expected_output_y_value} are same")
                logger().info(f"output_x_value of ecdh 192 mode is {desired_z_output} and"
                              f" Expected output_x_value of ecdh 192 mode is {expected_output_z_value} are same")

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case_id} thread: {str(e)} ****\n\n")
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


def test_wifi_sdk_add_operation_ecdh_256_mode_c217761(wifi_dut, sl_collections):
    """ verify addition operation with ecdh 256 mode"""
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, test_case_id=217761)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


def test_wifi_sdk_sub_operation_ecdh_256_mode_c217762(wifi_dut, sl_collections):
    """ verify subtraction operation with ecdh 256 mode"""
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, test_case_id=217762)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


def test_wifi_sdk_multi_operation_ecdh_256_mode_c217763(wifi_dut, sl_collections):
    """ verify multiplication operation with ecdh 256 mode"""
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, test_case_id=217763)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


def test_wifi_sdk_double_operation_ecdh_256_mode_c217764(wifi_dut, sl_collections):
    """ verify double operation with ecdh 256 mode"""
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, test_case_id=217764)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


def test_wifi_sdk_affinity_operation_ecdh_192_mode_c217765(wifi_dut, sl_collections):
    """ verify affinity operation with ecdh 192mode"""
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, test_case_id=217765)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


def test_wifi_sdk_add_operation_ecdh_224_mode_c217766(wifi_dut, sl_collections):
    """ verify addition operation with ecdh 224 mode"""
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, test_case_id=217766)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


def test_wifi_sdk_add_operation_ecdh_192_mode_c217767(wifi_dut, sl_collections):
    """ verify addition operation with ecdh 192 mode"""
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, test_case_id=217767)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)