import time
import pytest
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xRegion, Si91xRegionCode, Si91xModuleType, Si91xCustomFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xExtTCPIPFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xOperatingMode, Si91xPowerSaveModes, \
    Si91xPowerSaveProcedureTypes
from utf_wiseconnect_3.tests.sl_status import SLStatus

def logger():
    return get_logger(__name__)


""" Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Enable the wlan and bt power save mode in dut after the connection
        3. Initiate the Scan from DUT
        4. Verify the scan results

    setup requirement:
        1. DUT(SiWG917 _ACX (BRD4343A)
        2. Si-MB4002A
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. NUC

    Author: Shaik Abdul Azeez
"""


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "region": 1,
        "region_code": "ignore",
        "security": "WPA2",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
        "channel": 11,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_ver_aput_channel_13_c661455(wifi_dut, sl_collections):
    """Verify APUT when channel 13 is configured"""
    try:
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0", static_gateway="192.168.100.76")

        wifi_dut.interfaces.wifi.start_ap(ssid="silabs_ap", security="wpa2", channel=13, psk="Automation@123", dtim_beacon_count=1,
                                          beacon_interval=100, expected_status=SLStatus.SL_STATUS_SI91X_INVALID_CHANNEL)
        logger().info("\nObserved the expected error code: 0x1000A (SL_STATUS_SI91X_INVALID_CHANNEL)\n")
        time.sleep(20)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "region": 1,
        "region_code": "ignore",
        "security": "WPA2",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
        "channel": "11",
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "silabs_ap",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_ver_aput_channel_11_c661456(wifi_dut, wifi_client, sl_collections):
    """Verify APUT behavior when channel 11 is configured"""
    try:
        # Configure DUT with static IP
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0", static_gateway="192.168.100.76")

        # Start Access Point
        wifi_dut.interfaces.wifi.start_ap(ssid="silabs_ap", security="wpa2", channel=11,
                                          psk="Automation@123", dtim_beacon_count=1, beacon_interval=100)
        time.sleep(20)

        # Get and log DUT IP
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode("utf-8")
        logger().info(f"DUT IP: {dut_ip}")

        # Get and log Raspberry Pi MAC address
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"Raspberry Pi MAC Address: {rasp_mac_address}")

        # Raspberry Pi Client connects to DUT AP
        logger().info("Raspberry Pi Client connecting to DUT AP...")
        wifi_client.interfaces.wifi.join(ssid="silabs_ap", security="WPA2",
                                         passphrase="Automation@123", country="US", scan_ssid=1)
        # Get and log client IP
        client_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Client IP: {client_ip}")
        time.sleep(30)

        # Perform ping test
        logger().info("Initiating WLAN ping from Raspberry Pi Client...")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(f"sudo ping -c 10 {dut_ip}")
        assert rc == 0, "Raspberry Pi client failed to ping DUT"
        logger().info(f"Ping Results:\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")

        # Get and log DUT MAC address
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT MAC Address: {dut_mac_address}")

        # Disconnect client
        logger().info("Raspberry Pi Client disconnecting from DUT AP...")
        wifi_client.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        # Stop Access Point
        wifi_dut.interfaces.wifi.stop_ap()
