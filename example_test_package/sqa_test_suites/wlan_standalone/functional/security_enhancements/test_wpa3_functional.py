from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict, logger
from retry import retry
from utf.interfaces.cli import CLITransport, CLITransportException
from utf.interfaces.wifi import WlanError
import sys
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116PowerSaveModes, \
    RS9116TCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116CustomFeatureBitMap, RS9116PowerSaveProcedureTypes
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from typing import Dict
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
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC device)

    Author: Benazeer K
"""


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


def logger():
    return get_logger(__name__)






@retry(Exception, delay=15, tries=3)
def ping_to_dut(dut_ip, ping_count=10):
    status = ping(dut_ip, ping_count)
    assert status, "Failed to ping to DUT"
    return status


@retry(Exception, delay=5, tries=5)
def ping_to_host(wifi_client, device_ip):
    status = wifi_client.interfaces.wifi.ping(server_ip=device_ip)
    assert status < 1, "Failed to ping to host"
    return status


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_scan_c34503_04_05_07(wifi_sniffer, wifi_dut, wifi_access_point,utf_constants):
    logger().info(f"********this test_case to validate DNS_SERVER WITH DHCP********")
    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_scan_c34503_04_05_07')
    time.sleep(2)
    ping_count = utf_constants.get("ping_count")

    scan_dict = [{"ssid": None, "channel": 0}, {"ssid": None, "channel": wifi_access_point.interfaces.wifi.channel},
                 {"ssid": wifi_access_point.interfaces.wifi.ssid, "channel": wifi_access_point.interfaces.wifi.channel}]

    for i in range(len(scan_dict)):
        assert wifi_dut.interfaces.wifi.scan(ssid=scan_dict[i]['ssid'], channel=scan_dict[i]['channel'])
        time.sleep(3)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                         | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired)
    time.sleep(1)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    result = wifi_dut.interfaces.wifi.version()
    logger().info(f" DUT_Version: {result}")

    packet_filter3 = f'(wlan.fixed.sae_message_type == 1) || (wlan.fixed.sae_message_type == 2)' \
                     f' && wlan.addr == {dut_mac_address}'

    packet_filter4 = f'!(wlan.fc.type_subtype == 0x0008) && (wlan.tag.number == 45 ) || ' \
                     f'(wlan.fc.type_subtype == 0x0000) || eapol || (wlan.fixed.sae_message_type == 1) || ' \
                     f'(wlan.fixed.sae_message_type == 2) && wlan.addr == {dut_mac_address}'

    logger().info(f"*****Enabling Enhanced MAX PSP******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )
    time.sleep(2)
    logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(10)
    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    logger().info("Sniffer Validation for Authentication packets of COMMIT & CONFIRM")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']
    logger().info("Sniffer Validation for Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)['packet_count']


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
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
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_tcp_data_tx_with_wpa3_c34512(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client,
                                      protocol):
    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_tcp_data_tx_with_wpa3_c34512')
    time.sleep(2)

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                         | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"*****Enabling Enhanced MAX PSP******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )

    logger().info(f"***** Start get IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 1, "fail to ping host"
    logger().info("ping successful to host")

    time.sleep(2)

    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol: {protocol}")

    print('\n\n ********** Calling IPERF TX, TCP traffic for all Qos services ********************\n\n')

    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    logger().info(f"***** starting iperf ******")
    net_perf_client.interfaces.net_perf.start()

    logger().info(f"***** open socket and send traffic  ******")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    logger().info(f"***** get and print throughput ******")
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp, "failed to get throughtput..."
    __print_throughput(tp)
    time.sleep(5)

    packet_filter3 = f'!(wlan.fc.type_subtype == 0x0008) && (wlan.tag.number == 45 ) || ' \
                     f'(wlan.fc.type_subtype == 0x0000) || eapol || (wlan.fixed.sae_message_type == 1) || ' \
                     f'(wlan.fixed.sae_message_type == 2) && wlan.addr == {dut_mac_address}'

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Sniffer Validation for Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_udp_data_tx_with_wpa3_c34514(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client,
                                      protocol):
    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_udp_data_tx_with_wpa3_c34514')
    time.sleep(2)

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                         | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"*****Enabling Enhanced MAX PSP******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )

    logger().info(f"***** Start get IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 1, "fail to ping host"
    logger().info("ping successful to host")

    time.sleep(2)

    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol: {protocol}")

    print('\n\n ********** Calling IPERF TX, TCP traffic for all Qos services ********************\n\n')

    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    logger().info(f"***** starting iperf ******")
    net_perf_client.interfaces.net_perf.start()

    logger().info(f"***** open socket and send traffic  ******")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    logger().info(f"***** get and print throughput ******")
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp, "failed to get throughtput..."
    __print_throughput(tp)
    time.sleep(5)

    packet_filter3 = f'!(wlan.fc.type_subtype == 0x0008) && (wlan.tag.number == 45 ) || ' \
                     f'(wlan.fc.type_subtype == 0x0000) || eapol || (wlan.fixed.sae_message_type == 1) || ' \
                     f'(wlan.fixed.sae_message_type == 2) && wlan.addr == {dut_mac_address}'

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Sniffer Validation for Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
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
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_tcp_data_rx_with_wpa3_c34513(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client,
                                      protocol):
    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_tcp_data_rx_with_wpa3_c34513')
    time.sleep(2)

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                         | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"*****Enabling Enhanced MAX PSP******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )

    logger().info(f"***** Start get IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 1, "fail to ping host"
    logger().info("ping successful to host")

    time.sleep(2)

    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol: {protocol}")

    print('\n\n ********** Calling IPERF RX ********************\n\n')

    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    logger().info(f"***** open socket and start listening ******")
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        logger().info(f"***** start iperf  ******")
        net_perf_client.interfaces.net_perf.start()

        logger().info(f"***** capture device output  ******")
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

    logger().info(f"***** get and print throughput   ******")
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    time.sleep(5)
    assert tp, "failed to get throughtput..."
    __print_throughput(tp)
    time.sleep(5)

    packet_filter3 = f'!(wlan.fc.type_subtype == 0x0008) && (wlan.tag.number == 45 ) || ' \
                     f'(wlan.fc.type_subtype == 0x0000) || eapol || (wlan.fixed.sae_message_type == 1) || ' \
                     f'(wlan.fixed.sae_message_type == 2) && wlan.addr == {dut_mac_address}'

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()
    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Sniffer Validation for Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_udp_data_rx_with_wpa3_c34515(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client,
                                      protocol):
    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_udp_data_rx_with_wpa3_c34515')
    time.sleep(2)

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                         | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"*****Enabling Enhanced MAX PSP******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )

    logger().info(f"***** Start get IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 1, "fail to ping host"
    logger().info("ping successful to host")

    time.sleep(2)

    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol: {protocol}")

    print('\n\n ********** Calling IPERF RX ********************\n\n')

    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    logger().info(f"***** open socket and start listening ******")
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        logger().info(f"***** start iperf  ******")
        net_perf_client.interfaces.net_perf.start()

        logger().info(f"***** capture device output  ******")
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

    logger().info(f"***** get and print throughput   ******")
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp, "failed to get throughtput..."
    __print_throughput(tp)
    time.sleep(5)

    packet_filter3 = f'!(wlan.fc.type_subtype == 0x0008) && (wlan.tag.number == 45 ) || ' \
                     f'(wlan.fc.type_subtype == 0x0000) || eapol || (wlan.fixed.sae_message_type == 1) || ' \
                     f'(wlan.fixed.sae_message_type == 2) && wlan.addr == {dut_mac_address}'

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()
    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Sniffer Validation for Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']



@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.IEEE802_11W,
        "band": 1,
    }
)
@pytest.mark.wifi_5g
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"channel": 36, "security": 'WPA3'})
def test_tcp_data_tx_with_wpa3_5g_c34516(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client,
                                         protocol):
    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_tcp_data_tx_with_wpa3_5g_c34516')
    time.sleep(2)

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                         | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"*****Enabling Enhanced MAX PSP******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )

    logger().info(f"***** Start get IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    status = ping_to_host(wifi_client, device_ip)
    assert status < 1, f"ping failed to host"
    logger().info(f" ping to host successful")

    time.sleep(2)

    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol: {protocol}")

    print('\n\n ********** Calling IPERF TX, TCP traffic for all Qos services ********************\n\n')

    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    logger().info(f"***** starting iperf ******")
    net_perf_client.interfaces.net_perf.start()

    logger().info(f"***** open socket and send traffic  ******")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    logger().info(f"***** get and print throughput ******")
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp, "failed to get throughtput..."
    __print_throughput(tp)
    time.sleep(5)

    packet_filter3 = f'!(wlan.fc.type_subtype == 0x0008) && (wlan.tag.number == 45 ) || ' \
                     f'(wlan.fc.type_subtype == 0x0000) || eapol || (wlan.fixed.sae_message_type == 1) || ' \
                     f'(wlan.fixed.sae_message_type == 2) && wlan.addr == {dut_mac_address}'

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()
    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Sniffer Validation for Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config('wifi_access_point', wifi={"channel": 40, "security": 'WPA3'})
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.IEEE802_11W,
        "band": 1,
    }
)
@pytest.mark.wifi_5g
def test_udp_data_tx_with_wpa3_5g_c34518(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client,
                                         protocol):
    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_udp_data_tx_with_wpa3_5g_c34518')
    time.sleep(2)

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                         | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"*****Enabling Enhanced MAX PSP******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )

    logger().info(f"***** Start get IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    status = ping_to_host(wifi_client, device_ip)
    assert status < 1, f"ping failed to host"
    logger().info(f" ping to host successful")

    time.sleep(2)

    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol: {protocol}")

    print('\n\n ********** Calling IPERF TX, TCP traffic for all Qos services ********************\n\n')

    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    logger().info(f"***** starting iperf ******")
    net_perf_client.interfaces.net_perf.start()

    logger().info(f"***** open socket and send traffic  ******")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    logger().info(f"***** get and print throughput ******")
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp, "failed to get throughtput..."
    __print_throughput(tp)
    time.sleep(5)

    packet_filter3 = f'!(wlan.fc.type_subtype == 0x0008) && (wlan.tag.number == 45 ) || ' \
                     f'(wlan.fc.type_subtype == 0x0000) || eapol || (wlan.fixed.sae_message_type == 1) || ' \
                     f'(wlan.fixed.sae_message_type == 2) && wlan.addr == {dut_mac_address}'

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()
    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Sniffer Validation for Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"channel": 48, "security": 'WPA3'})
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.IEEE802_11W,
        "band": 1,
    }
)
@pytest.mark.wifi_5g
def test_tcp_data_rx_with_wpa3_5g_c34517(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client,
                                         protocol):
    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_tcp_data_rx_with_wpa3_5g_c34517')
    time.sleep(2)

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                         | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"*****Enabling Enhanced MAX PSP******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )

    logger().info(f"***** Start get IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    status = ping_to_host(wifi_client, device_ip)
    assert status < 1, f"ping failed to host"
    logger().info(f" ping to host successful")

    time.sleep(2)

    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol: {protocol}")

    print('\n\n ********** Calling IPERF RX ********************\n\n')

    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    logger().info(f"***** open socket and start listening ******")
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        logger().info(f"***** start iperf  ******")
        net_perf_client.interfaces.net_perf.start()

        logger().info(f"***** capture device output  ******")
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

    logger().info(f"***** get and print throughput   ******")
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    time.sleep(5)
    assert tp, "failed to get throughtput..."
    __print_throughput(tp)
    time.sleep(5)

    packet_filter3 = f'!(wlan.fc.type_subtype == 0x0008) && (wlan.tag.number == 45 ) || ' \
                     f'(wlan.fc.type_subtype == 0x0000) || eapol || (wlan.fixed.sae_message_type == 1) || ' \
                     f'(wlan.fixed.sae_message_type == 2) && wlan.addr == {dut_mac_address}'

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()
    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Sniffer Validation for Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config('wifi_access_point', wifi={"channel": 149, "security": 'WPA3'})
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.IEEE802_11W,
        "band": 1,

    }
)
@pytest.mark.wifi_5g
def test_udp_data_rx_with_wpa3_5g_c34519(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client,
                                         protocol):
    validation = True

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_udp_data_rx_with_wpa3_5g_c34519')
    time.sleep(2)

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                         | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"*****Enabling Enhanced MAX PSP******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )

    logger().info(f"***** Start get IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    status = ping_to_host(wifi_client, device_ip)
    assert status < 1, f"ping failed to host"
    logger().info(f" ping to host successful")
    time.sleep(2)

    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol: {protocol}")

    print('\n\n ********** Calling IPERF RX ********************\n\n')

    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    logger().info(f"***** open socket and start listening ******")
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        logger().info(f"***** start iperf  ******")
        net_perf_client.interfaces.net_perf.start()

        logger().info(f"***** capture device output  ******")
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

    logger().info(f"***** get and print throughput   ******")
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp, "failed to get throughtput..."
    __print_throughput(tp)
    time.sleep(5)

    packet_filter3 = f'!(wlan.fc.type_subtype == 0x0008) && (wlan.tag.number == 45 ) || ' \
                     f'(wlan.fc.type_subtype == 0x0000) || eapol || (wlan.fixed.sae_message_type == 1) || ' \
                     f'(wlan.fixed.sae_message_type == 2) && wlan.addr == {dut_mac_address}'

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()
    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Sniffer Validation for Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count']


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"channel": 149, "security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.IEEE802_11W,
        "band": 1,
    }
)
def test_conn_deconn_reconn_wpa3_C34508(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client, utf_constants):
    validation = True
    iter_count = 2
    ping_count = utf_constants.get("ping_count")
    for i in range(0, iter_count):
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_conn_deconn_reconn_wpa3_C34508')
        time.sleep(2)

        logger().info(f"***** preparing wifi_dut ******")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                         join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                             | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired)
        ip_config = wifi_dut.interfaces.wifi.start_ip()
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")

        logger().info(f"*****Enabling Enhanced MAX PSP******")
        wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                            power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
            power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
        )
        time.sleep(2)
        logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(5)

        packet_filter4 = f'!(wlan.fc.type_subtype == 0x0008) && (wlan.tag.number == 45 ) || ' \
                         f'(wlan.fc.type_subtype == 0x0000) || eapol || (wlan.fixed.sae_message_type == 1) || ' \
                         f'(wlan.fixed.sae_message_type == 2) && wlan.addr == {mac_address}'

        time.sleep(10)
        logger().info("DUT is going to leave the third party AP")
        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
        logger().info("Sniffer is going to stop")
        wifi_sniffer.interfaces.capture.stop_capture()

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)['packet_count'], \
            'Unable to find Broadcast Probe request packet'

        time.sleep(10)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.IEEE802_11W,

    }
)

def test_bgscan_specific_chal_wpa3_C34511(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client, utf_constants):
    testcase = "wpa3_BG_scan_C34511"
    rejoin_max = 10
    scan_interval = 6
    beacon_missedcount = 40
    ping_count = utf_constants.get("ping_count")
    first_time_retry = 0
    timeout = 10
    validation = True
    channel_list = [1, 6, 8]
    true_result_list = []
    false_result_list = []
    Probe_captured_channel_list = []
    Probe_not_captured_channel_list = []
    channel_bitmap_2_4 = 0
    scan_expected_time = 0
    for count in channel_list:
        channel_bitmap_2_4 += 1 << (count - 1)
        scan_expected_time += 100

    channel_bitmap_5 = 0
    scan_feature_extend = 0
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='main_capture')
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                    beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                    timeout=timeout)
    logger().info(f"***** Enabling BG scan parameters ******")
    wifi_dut.interfaces.wifi.set_bgscan(1, 0, 1, 4, 2, 15, 20, 0)

    time.sleep(2)

    # enables the scan in DUT with the given channel bitmap value
    logger().info("Initiating selective channel scan in DUT...")
    scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                   scan_bitmap_2_4=channel_bitmap_2_4,
                                                                       scan_bitmap_5=channel_bitmap_5,
                                                                       scan_feature=scan_feature_extend)
    time.sleep(5)
    logger().info(scan_results)
    assert len(scan_results) >= 1, "scan results not found"

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                         | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired, channel=0)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    logger().info(f"*****Enabling Enhanced MAX PSP******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )
    wifi_sniffer.interfaces.capture.stop_capture()
    packet_filter1 = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"
    time.sleep(2)
    for channel in channel_list:
        logger().info(f"configuring the Sniffer with the channel : {channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_sel_ch_{channel}")
        time.sleep(3)
        logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(10)
        logger().info("*********##### Sniffer is going to stop")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(f"Validate broadcast Probe req in {channel}")
        output = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count']
        if bool(output) is False:
            false_result_list.append(bool(output))
            Probe_not_captured_channel_list.append(channel)

        else:
            true_result_list.append(bool(output))
            Probe_captured_channel_list.append(channel)

        logger().info(f"True list = {true_result_list}")
        logger().info(f"false list = {false_result_list}")

    assert Probe_not_captured_channel_list == [], logger().info(
        f"******* unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list} ")

    logger().info(f"******* Probe requests are captured in all the channels:{Probe_captured_channel_list} ")

    logger().info(f"DUT is going to leave the AP")
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.IEEE802_11W,
        "band": 0,

    }
)

def test_bgscan_in_all_channel_wpa3_C34510(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants):
    testcase = "test_bgscan_in_all_channel_wpa3_C34510"
    rejoin_max = 10
    scan_interval = 6
    ping_count = utf_constants.get("ping_count")
    beacon_missedcount = 40
    first_time_retry = 0
    timeout = 10
    validation = True
    channel_list = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    true_result_list = []
    false_result_list = []
    Probe_captured_channel_list = []
    Probe_not_captured_channel_list = []
    channel_bitmap_2_4 = 0
    scan_expected_time = 0
    for count in channel_list:
        channel_bitmap_2_4 += 1 << (count - 1)
        scan_expected_time += 100

    channel_bitmap_5 = 0
    scan_feature_extend = 0
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='main_capture')
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                    beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                    timeout=timeout)
    logger().info(f"***** Enabling BG scan parameters ******")
    wifi_dut.interfaces.wifi.set_bgscan(1, 0, 1, 4, 2, 15, 20, 0)

    time.sleep(2)

    # enables the scan in DUT with the given channel bitmap value
    logger().info("Initiating selective channel scan in DUT...")
    scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                   scan_bitmap_2_4=channel_bitmap_2_4,
                                                                   scan_bitmap_5=channel_bitmap_5,
                                                                   scan_feature=scan_feature_extend)
    time.sleep(5)
    logger().info(scan_results)
    assert len(scan_results) >= 1, "scan results not found"

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                         | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired, channel=0)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    logger().info(f"*****Enabling Enhanced MAX PSP******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )
    wifi_sniffer.interfaces.capture.stop_capture()
    packet_filter1 = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"
    time.sleep(2)
    for channel in channel_list:
        logger().info(f"configuring the Sniffer with the channel : {channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{testcase}_sel_ch_{channel}")
        time.sleep(3)
        logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(10)
        logger().info("*********##### Sniffer is going to stop")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(f"Validate broadcast Probe req in channel :{channel}")
        output = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count']
        if bool(output) is False:
            false_result_list.append(bool(output))
            Probe_not_captured_channel_list.append(channel)

        else:
            true_result_list.append(bool(output))
            Probe_captured_channel_list.append(channel)

        logger().info(f"True list = {true_result_list}")
        logger().info(f"false list = {false_result_list}")

    assert Probe_not_captured_channel_list == [], logger().info(
        f"******* unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list} ")

    logger().info(f"******* Probe requests are captured in all the channels:{Probe_captured_channel_list} ")

    logger().info(f"DUT is going to leave the AP")
    wifi_dut.interfaces.wifi.leave()

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_rejoin_with_wpa3_security_c34509(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants):
    validation = True
    ping_count = utf_constants.get("ping_count")

    ''' Verify Rejoin Functionality in WPA3 Security'''
    state = switch.interfaces.pdu_switch.get_state()
    logger().info("pdu switch state : " + str(state))
    if state == 'true':
        logger().info('PDU is ready for use')
    else:
        logger().info(f'\n\n Please check the AP & PDU current state')
        assert False
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(10)
    # Setting sniffer capture file name
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_with_wpa3_security_c34509')
    logger().info(f"Enabling the rejoin parameters")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
    logger().info(f"DUT is going to join third party Access Point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                         | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired)

    dut_ip = None
    for count in range(1, 4):
        try:
            ip_config = wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(ip_config,
                              wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {ip_config}"
            dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            break
        except:
            logger().info(f"Get IP address through dhcp process is failed. retry count -> {count}")
            time.sleep(10)
    assert dut_ip, "ip setting in DUT has failed"
    logger().info(f'DUT ip {dut_ip}')

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    time.sleep(2)
    logger().info(f"*****Enabling Enhanced MAX PSP******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )
    time.sleep(2)
    # Initiate ping from third party wifi-client to DUT
    status = ping(dut_ip, ping_count)
    assert status == 1
    time.sleep(5)

    packet_filter4 = f'!(wlan.fc.type_subtype == 0x0008) && (wlan.tag.number == 45 ) || ' \
                     f'(wlan.fc.type_subtype == 0x0000) || eapol || (wlan.fixed.sae_message_type == 1) || ' \
                     f'(wlan.fixed.sae_message_type == 2) && wlan.addr == {mac_address}'

    logger().info("Checking for association packet before turning off the AP")
    wifi_sniffer.interfaces.capture.stop_capture()

    result = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)['packet_count'], \
             'Unable to find Broadcast Probe request packet'
    if result:
        logger().info(f'Sniffer validation pass')
    else:
        assert result

    logger().info('#### Turn off Access point and turn on the sniffer to capture the re association after rejoin####')
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file='test_rejoin_with_wpa3_security_after_ap_turn_off_c34509')
    if state == 'true':
        switch.interfaces.pdu_switch.turn_off()
    time.sleep(30)

    logger().info('##### Turn on Access point #####')
    state = switch.interfaces.pdu_switch.get_state()
    logger().info(f"checking status: {state}")
    if state == 'false':
        switch.interfaces.pdu_switch.turn_on()
        logger().info(f"PDU was off, trying to turn on using PDU, Please wait for 60 seconds to check DUT is rejoined to that AP or not ........")
        time.sleep(60)

    try:
        wifi_sniffer.interfaces.capture.stop_capture()
        result = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)['packet_count'], \
                 'Unable to find Broadcast Probe request packet'
        if result:
            logger().info(f'Sniffer validation pass')
        else:
            assert result
        if wifi_dut.interfaces.wifi.associated is True:
            logger().info(f"Initiating ping to DUT ip {dut_ip} after successful rejoin")

            for count in range(5):
                try:
                    logger().info("pinging to dut after power-save.....")
                    status = ping_to_dut(dut_ip, ping_count)
                    logger().info("ping to DUT is successful....")
                    break
                except:
                    logger().info(f"ping to dut is failed...retry count->{count + 1}")
                    time.sleep(15)
            assert status, "DUT not responding for ping request......"
            if status == 1:
                logger().info('#### Ping successful ####')
            else:
                logger().info('#### Ping unsuccessful ####')
    except (AssertionError, IndexError, CLITransportException):
        assert False, 'Find exception'
    finally:
        if state == 'true':
            logger().info('\n\n Access point is available')
        else:
            logger().info('\n\n Turn on the Access Point')
            switch.interfaces.pdu_switch.turn_on()
            logger().info('\n\n Turning on the Access Point, Please wait for 30 seconds ......')
            time.sleep(30)
