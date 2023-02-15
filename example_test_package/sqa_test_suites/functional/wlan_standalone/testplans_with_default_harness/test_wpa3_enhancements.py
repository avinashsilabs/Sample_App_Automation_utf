from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utils.iperf.iperf_utils import print_dict, logger
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116PowerSaveModes, \
    RS9116TCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116CustomFeatureBitMap, RS9116PowerSaveProcedureTypes
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect.devices.rs911x import RS9116JoinFeatureBitMap

"""This function runs below test steps for DUT-RS9116
        1. Configuration of DUT in 2G : BGN
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        6. Enable the power save mode in DUT
        7. Stop the sniffer  
        8. Analyzing all sniffer capture packets for WPA3 Security

    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP - ASUS 1800-AX53U)
        5. Sniffer(NUC device)

    Author: Swathi.Pathuri
"""

def logger():
    return get_logger(__name__)


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_conn_STA_AP_in_H2E_mode_C113907(rs_helper, utf_constants, wifi_sniffer, net_perf_client, wifi_access_point,
                                         wifi_dut, wifi_client):
    validation = True
    file_name = "test_conn_STA_AP_in_H2E_mode_C113907"

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
    time.sleep(5)
    logger().info("enable rejoin")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    logger().info(f"***** preparing wifi_dut ******")

    wifi_dut.interfaces.wifi.join(
        ssid=wifi_access_point.interfaces.wifi.ssid,
        security="WPA3Transition",
        passphrase=wifi_access_point.interfaces.wifi.passphrase,
        channel=0,
        join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable)

    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                   power_save=True, associated=True)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    packet_filter3 = f'wlan.rsnx.sae_hash_to_element == 1 and wlan.fc.type_subtype==0 and' \
                     f'  wlan.sa == {dut_mac_address}'

    logger().info("Sniffer Validation for Assoc req with H2E")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'], \
        "sniffer validation failed"


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_thpt_STA_AP_in_H2E_mode_C113911(rs_helper, utf_constants, wifi_sniffer, net_perf_client,
                                                             wifi_access_point, wifi_dut, wifi_client, protocol):
    validation = True
    file_name = "test_thpt_STA_AP_in_H2E_mode_C113911"

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
    time.sleep(5)
    logger().info("enable rejoin")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    logger().info(f"***** preparing wifi_dut ******")

    wifi_dut.interfaces.wifi.join(
        ssid=wifi_access_point.interfaces.wifi.ssid,
        security="WPA3Transition",
        passphrase=wifi_access_point.interfaces.wifi.passphrase,
        channel=0,
        join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable)

    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                   power_save=True, associated=True)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    timeout = 60
    protocol = IperfConstants.UDP

    rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    packet_filter3 = f'wlan.rsnx.sae_hash_to_element == 1 and wlan.fc.type_subtype==0 and  wlan.sa == {dut_mac_address}'

    logger().info("Sniffer Validation for Assoc req with H2E")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'], \
        "sniffer validation failed"


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2',
                                               "protected_management_frame": "Capable"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_conn_STA_AP_in_Transition_mode_C113912(rs_helper, utf_constants, wifi_sniffer, net_perf_client,
                                                wifi_access_point, wifi_dut, wifi_client, protocol):
    validation = True
    file_name = "test_conn_STA_AP_in_Transition_mode_C113912"

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
    time.sleep(2)

    logger().info("enable rejoin")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    logger().info(f"***** Joining to the AP ******")
    wifi_dut.interfaces.wifi.join(
        ssid=wifi_access_point.interfaces.wifi.ssid,
        security="WPA3Transition",
        passphrase=wifi_access_point.interfaces.wifi.passphrase,
        channel=0,
        join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable)

    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                   power_save=True, associated=True)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "protected_management_frame": "Capable"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity
                    | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_data_transfer_STA_in_Transition_mode_C113913(rs_helper, utf_constants, wifi_sniffer, net_perf_client,
                                                      wifi_access_point, wifi_dut, wifi_client, protocol):
    validation = True
    file_name = "test_data_transfer_STA_in_Transition_mode_C113913"

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
    time.sleep(2)

    logger().info("enable rejoin")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    logger().info(f"***** preparing wifi_dut ******")

    wifi_dut.interfaces.wifi.join(
        ssid=wifi_access_point.interfaces.wifi.ssid,
        security="WPA3Transition",
        passphrase=wifi_access_point.interfaces.wifi.passphrase,
        channel=0,
        join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable)

    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                   power_save=True, associated=True)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    timeout = 60
    protocol = IperfConstants.UDP

    rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="RX")

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3',
                                               "protected_management_frame": "Capable"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_DUT_behaviour_rejoin_H2E_C113909(rs_helper, utf_constants, wifi_sniffer, net_perf_client,
                                      wifi_access_point, wifi_dut, wifi_client, protocol):
    validation = True
    file_name = "test_DUT_behaviour_rejoin_H2E_C113909"

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
    time.sleep(5)
    logger().info("enable rejoin")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    logger().info(f"***** preparing wifi_dut ******")

    wifi_dut.interfaces.wifi.join(
        ssid=wifi_access_point.interfaces.wifi.ssid,
        security="WPA3Transition",
        passphrase=wifi_access_point.interfaces.wifi.passphrase,
        channel=0,
        join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable)

    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                   power_save=True, associated=True)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    wifi_access_point.interfaces.wifi.stop_ap()

    wifi_access_point.interfaces.wifi.start_ap()

    time.sleep(20)
    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, utf_constants.get("ping_count"))
    assert status, "DUT not responding for ping request......"

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(5)

    logger().info("validate Assoc req with H2E")
    packet_filter3 = f'wlan.rsnx.sae_hash_to_element==1 && wlan.fc.type_subtype==0 && wlan.sa=={dut_mac_address}'

    logger().info("Sniffer Validation for Assoc req with H2E")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'],\
        "sniffer validation failed"



@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, indexing (starts with 0) applies as per order defined in harness.
        0: {
             'ssid': 'OPEN',
             'security': 'Open',
             'channel': 1,
        },
        1: {
             'ssid': 'WPA3-SSID',
             'security': 'WPA3',
             'passphrase': '123123123',
             'channel': 1,
             'protected_management_frame': "Capable"
        }
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_behaviour_of_DUT_when_AP_without_H2E_C113910(rs_helper, utf_constants, wifi_sniffer, net_perf_client,
                                                      wifi_access_points, wifi_dut, wifi_client, protocol):
    validation = True
    file_name = "test_behaviour_of_DUT_when_AP_without_H2E_C113910"

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[1].interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
    time.sleep(2)

    logger().info("enable rejoin")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    logger().info(f"***** Joining to the AP ******")
    wifi_dut.interfaces.wifi.join(
        ssid=wifi_access_points[1].interfaces.wifi.ssid,
        security="WPA3Transition",
        passphrase=wifi_access_points[1].interfaces.wifi.passphrase,
        channel=0,
        join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable)

    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_points[1],
                                                                   power_save=True, associated=True)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    packet_filter3 = f'(wlan.fixed.sae_message_type == 1) || (wlan.fixed.sae_message_type == 2)' \
                     f' && wlan.addr == {dut_mac_address}'

    packet_filter4 = f'!(wlan.fc.type_subtype == 0x0008) && (wlan.tag.number == 45 ) || ' \
                     f'(wlan.fc.type_subtype == 0x0000) || eapol || (wlan.fixed.sae_message_type == 1) || ' \
                     f'(wlan.fixed.sae_message_type == 2) && wlan.addr == {dut_mac_address}'

    logger().info("Sniffer Validation for Authentication packets of COMMIT & CONFIRM")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']
    logger().info("Sniffer Validation for Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)['packet_count']





@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, indexing (starts with 0) applies as per order defined in harness.
        0: {
             'ssid': 'OPEN',
             'security': 'Open',
             'channel': 1,
        },
        1: {
             'ssid': 'WPA3-SSID',
             'security': 'WPA3',
             'passphrase': '123123123',
             'channel': 1,
             'protected_management_frame': "Capable"
        }
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_DUT_reconnection_hunting_pecking_C113908(rs_helper, utf_constants, wifi_sniffer, net_perf_client,
                                                      wifi_access_points, wifi_dut, wifi_client, protocol):
    validation = True
    file_name = "test_DUT_reconnection_hunting_pecking_C113908"

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[1].interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
    time.sleep(2)

    logger().info("enable rejoin")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    for count in range(0, utf_constants.get("iter_count")):

        logger().info(f"***** Joining to the AP ******")
        wifi_dut.interfaces.wifi.join(
            ssid=wifi_access_points[1].interfaces.wifi.ssid,
            security="WPA3Transition",
            passphrase=wifi_access_points[1].interfaces.wifi.passphrase,
            channel=0,
            join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable)

        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_points[1],
                                                                       power_save=True, associated=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        logger().info("Dut going to leave the AP")
        wifi_dut.interfaces.wifi.leave()

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    packet_filter3 = f'(wlan.fixed.sae_message_type == 1) || (wlan.fixed.sae_message_type == 2)' \
                     f' && wlan.addr == {dut_mac_address}'

    packet_filter4 = f'!(wlan.fc.type_subtype == 0x0008) && (wlan.tag.number == 45 ) || ' \
                     f'(wlan.fc.type_subtype == 0x0000) || eapol || (wlan.fixed.sae_message_type == 1) || ' \
                     f'(wlan.fixed.sae_message_type == 2) && wlan.addr == {dut_mac_address}'

    logger().info("Sniffer Validation for Authentication packets of COMMIT & CONFIRM")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']
    logger().info("Sniffer Validation for Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)['packet_count']


@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, indexing (starts with 0) applies as per order defined in harness.
        0: {
             'ssid': 'WPA3-TR',
             'security': 'WPA3',
             'passphrase': '123123123',
             'channel': 1,
             'protected_management_frame': "Capable"
        },
        1: {
             'ssid': 'WPA3-TR',
             'security': 'WPA3',
             'passphrase': '123123123',
             'channel': 1,
             'protected_management_frame': "Capable"
        }
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_DUT_rejoin_AP1_H2E_AP2_hunting_pecking_C113916(rs_helper, utf_constants, wifi_sniffer, net_perf_client,
                                                      wifi_access_points, wifi_dut, wifi_client, protocol):
    validation = True
    file_name = "test_DUT_rejoin_AP1_H2E_AP2_hunting_pecking_C113916"

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[0].interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
    time.sleep(2)

    logger().info("enable rejoin")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    logger().info(f"***** Joining to the AP ******")
    wifi_dut.interfaces.wifi.join(
        ssid=wifi_access_points[0].interfaces.wifi.ssid,
        security="WPA3Transition",
        passphrase=wifi_access_points[0].interfaces.wifi.passphrase,
        channel=0,
        join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable)

    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_points[1],
                                                                   power_save=True, associated=True)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("validate Assoc req with H2E")
    packet_filter1 = f'wlan.rsnx.sae_hash_to_element==1 && wlan.fc.type_subtype==0 && wlan.sa=={dut_mac_address}'

    logger().info("Sniffer Validation for Assoc req with H2E")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        "sniffer validation failed"

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[0].interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
    time.sleep(5)
    logger().info("Turning OFF AP1")
    wifi_access_points[0].interfaces.wifi.stop_ap()

    time.sleep(50)

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("validate rejoin process to AP2")
    packet_filter3 = f'wlan.fc.type_subtype==1 && wlan.sa=={wifi_access_points[1].interfaces.wifi.bssid}'

    logger().info("Sniffer Validation for Assoc resp from AP2 with hunting and pecking")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'], \
        "sniffer validation failed"



