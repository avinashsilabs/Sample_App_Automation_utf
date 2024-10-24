import pytest
import time
import random
import string
from random import randint
import re
from datetime import datetime
from utf.interfaces.shell.ssh_shell import SSHShell
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xOperatingMode,
    DeviceConstants,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
)
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from random import randint
from utf.utils.thread_base import ThreadBase

from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from threading import Thread

"""This function runs below test steps for DUT
    Step1: 1. Configuration of DUT in 2G mode
    Step2 : Do Scan the AP
    Step3: Connect to the AP
    Step4 :Initiate the different powersave modes and check the connectivity 
    Step7 : Issue init,scan and connect to the AP

    setup requirement:
        1. DUT(917-SDK)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

    Author: CG team
"""


def logger():
    return get_logger(__name__)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_power_mode_switching_before_assoc_C19500(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                  sniffer_filter):
    """
    Power Save Mode switching before association
    """
    try:
        capture_filename = "test_power_mode_switching_before_assoc_c19500"
        channel = wifi_access_point.interfaces.wifi.channel
        logger().info(f"Configuring the sniffer with channel {channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info("Starting capture")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        time.sleep(5)
        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            time.sleep(5)
            logger().info(f"Iterating for {iter_count}: Current iteration is {i}")
            logger().info("Enabling power Save")
            wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")

            time.sleep(5)
            logger().info("Disabling power save ")
            wifi_dut.interfaces.wifi.set_performance_profile(mode="high_performance")
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

            logger().info("enable the scan in dut on channel 0...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            time.sleep(20)
            assert (len(scan_results) >= 1), "Scan Failed"
            logger().info(scan_results)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT mac address is {sa_addr}")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=sa_addr, filter_name="probe_request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe request broadcast packet'
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.
        Feature32KHzBypassClockOnUULP_GPIO_3
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_powersave_disable_functionality_powersave1_C19501(wifi_access_point, wifi_dut, wifi_sniffer, rs_helper,
                                                           sl_collections):
    """
    Power save disable functionality when module is in power save
    """
    try:

        validation = True
        capture_filename = "test_C19501_max_psp_enabled"
        channel = wifi_access_point.interfaces.wifi.channel

        logger().info(f"Configuring the sniffer with channel {channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info("Starting capture")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False, retry_count=3,
                                                     associated=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        logger().info(f"DUT MAC: {dut_mac_address}")
        time.sleep(30)
        logger().info(f"***** Enabling Max PSP in DUT ******")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

        logger().info(f'DUT ip {device_ip}')
        logger().info("pinging to dut.....")

        ping_status = sl_collections.ping_with_custom_size(device_ip, ping_counts=60, byte_size=300)
        assert ping_status, "DUT is not responding to ping request after powersave"
        logger().info("ping to DUT is successful....")
        time.sleep(30)

        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter1 = f"(wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address}) && (wlan.da == {ap_bssid}))"
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Qos Null with PM1'

        capture_filename2 = "test_C19501_max_psp_disabled"
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info("Starting capture")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename2}.pcap")
        time.sleep(5)

        logger().info("Disabling wlan power save")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="high_performance")

        time.sleep(60)
        wifi_sniffer.interfaces.capture.stop_capture()
        validation = True
        logger().info("CHECKING MAX PSP DISABLED - SO SHOULD NOT GET NUL PACKETS")
        packet_filter2 = f"(wlan.fc.pwrmgt == 0) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address}) && (wlan.da == {ap_bssid}))"
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], "Unable to find Qos Null with PM 0"

        wifi_dut.interfaces.wifi.leave()

        logger().info(f"CASE 2: CHECKING CASE2 ENHANCED MAX PSP")
        capture_filename = "test_C19501_enhanced_max_psp_enabled"

        channel = wifi_access_point.interfaces.wifi.channel
        logger().info(f"Configuring the sniffer with channel {channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info("Starting capture")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        logger().info("Configuring ENHANCED MAX PSP")
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False, retry_count=3,
                                                     associated=False)

        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        time.sleep(30)

        logger().info(f"***** Enabling Enhanced Max PSP in DUT ******")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save")
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

        logger().info(f'DUT ip {device_ip}')
        logger().info("pinging to dut.....")

        ping_status = sl_collections.ping_with_custom_size(device_ip, ping_counts=30, byte_size=300)
        assert ping_status, "DUT is not responding to ping request after powersave"
        logger().info("ping to DUT is successful....")
        logger().info("Stopping sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = f"(wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address}) && (wlan.da == {ap_bssid}))"
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Qos Null with PM1'

        capture_filename2 = "test_C19501_enhance_max_psp_disabled"
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info("Starting capture")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename2}.pcap")
        time.sleep(5)

        logger().info("Disabling power save ")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="high_performance")
        time.sleep(60)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("CHECKING ENHANCDED MAX PSP DISABLED - SO SHOULD NOT GET NUL PACKETS")

        validation = True
        packet_filter2 = f"(wlan.fc.pwrmgt == 0) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address}) && (wlan.da == {ap_bssid}))"
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], "Unable to find Qos Null with PM 0"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["multicast_leave", "disassociated", "clear_certs"])
def test_send_multicast_broadcast_data_sdk_C19507(multicast_client, net_perf_client, protocol,
                                                  wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, utf_constants,
                                                  sl_collections, sniffer_filter):
    """
    Sending of broadcast and multicast data with power save enabled
    """
    try:
        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            capture_filename = f"test_Send_Multicast_data_C19507_sdk_iteration_{i}"
            channel = wifi_access_point.interfaces.wifi.channel

            logger().info(f"Configuring the sniffer with channel {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            logger().info("Starting capture")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f'AP BSSID = {ap_bssid}')
            wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                     beacon_missed_count=40, first_time_retry_enable=0)

            result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=True, ping_count=10,
                                                         associated=False, retry_count=3)
            device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
            logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

            logger().info(f"***** Start get IP address ******")
            host_ip = wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"***** host ip is {host_ip}")
            logger().info(f"***** Device ip is {device_ip}")

            timeout = 60

            logger().info(f"***** Running broadcast data")
            ip_str = device_ip.split(".")
            ip_str[3] = "255"
            broadcast_ip = ".".join(ip_str)
            logger().info(f"Broadcast ip is {broadcast_ip}")

            logger().info(f"SENDING MULTICAST DATA")
            ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()

            logger().info(f"DUT joining to the multicast group {multicast_ip}")
            wifi_dut.interfaces.wifi.sl_net_join_multicast_address()

            net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=multicast_ip, time_out=timeout,
                                                            protocol=protocol, time_to_leave="32", bandwidth="60M",
                                                            host_role="C", bind_address=host_ip)
            logger().info(f"Host IP: {host_ip}, Dut IP: {device_ip}, Protocol: {protocol}")
            logger().info(f"***** starting iperf ******")
            net_perf_client.interfaces.net_perf.start()
            logger().info(f"***** start listening  ******")
            wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                           local_port=net_perf_client.interfaces.net_perf.client_port,
                                           local_ip=multicast_ip, remote_ip=host_ip,
                                           remote_port=net_perf_client.interfaces.net_perf.client_port,
                                           size=1470, ttl=30, throughput_type=4, qos=0, async_socket=1)

            wifi_dut.interfaces.wifi.sl_net_leave_multicast_address()

            logger().info(f"SENDING BROADCAST DATA")
            # sl_collections.run_traffic(wifi_dut=wifi_dut, net_perf_client=net_perf_client, protocol=protocol, device_ip=device_ip, host_ip=host_ip, timeout=60, traffic_type="TX")
            sl_collections.run_traffic(wifi_dut=wifi_dut, net_perf_client=net_perf_client, protocol=protocol,
                                       device_ip=broadcast_ip, host_ip=host_ip, timeout=60, traffic_type="TX")

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Initiating disconnect from DUT")
            # Wlan Disconnect
            wifi_dut.interfaces.wifi.leave()
            time.sleep(10)

            logger().info("validate NULL data frame with PM bit set to '1'")
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                            da_addr={ap_bssid},
                                                                                            filter_name='power_mgmt_bit')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
                'Unable to find power management bit in QOS null frames in sniffer capture'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_powersave_mode_2_enterprise_sdk_C19509(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                radius_server, sl_collections, request, utf_constants,
                                                net_perf_client, wifi_client, protocol):
    """
    Power mode 2 data transfer in Enterprise security mode
    """
    try:
        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            testcase = "test_powersave_mode_2_Enterprise_C19509"
            logger().info("configuring the Sniffer with the channel")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

            logger().info("start capturing with Sniffer by giving the test case name as filename")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP bssid {ap_bssid}")

            dut_addr = sl_collections.join_to_eap_network(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                                          eap_type="tls", ping_after_power_save=True, power_save=False)
            device_ip = dut_addr['device_ip']
            dut_mac_address = dut_addr['dut_mac_address']
            logger().info(f"device_ip, device_mac : {dut_addr['device_ip']}, {dut_addr['dut_mac_address']}")

            host_ip = wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"Remote device ip :{host_ip}")

            logger().info("Enabling power save Enhanced max psp")
            wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            time.sleep(10)

            # Enables the bt power save in DUT
            logger().info("Setting DUT in bt power save...")
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            time.sleep(30)

            logger().info(f"Running UDP-Rx Traffic")
            sl_collections.run_traffic(wifi_dut=wifi_dut, net_perf_client=net_perf_client, protocol=IperfConstants.UDP,
                                       device_ip=device_ip, host_ip=host_ip, timeout=60, traffic_type="RX")
            time.sleep(60)

            logger().info(f"Running TCP -Rx traffic")
            sl_collections.run_traffic(wifi_dut=wifi_dut, net_perf_client=net_perf_client, protocol=protocol,
                                       device_ip=device_ip, host_ip=host_ip, timeout=30, traffic_type="RX")
            time.sleep(30)

            logger().info("Initiating disconnect from DUT")
            wifi_dut.interfaces.wifi.leave()

            logger().info("stopping capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("validate NULL data frame with PM bit set to '1'")
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                            da_addr={ap_bssid},
                                                                                            filter_name='power_mgmt_bit')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
                'Unable to find power management bit in QOS null frames in sniffer capture'

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
