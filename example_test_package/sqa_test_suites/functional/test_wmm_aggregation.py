from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict, logger
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116PowerSaveModes, RS9116CustomFeatureBitMap, SocketOptions, RS9116PowerSaveProcedureTypes, \
    RS9116ExtTCPIPFeatureBitMap
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping

ping_count = 10
"""This function runs below test steps for DUT-RS9116
        1. Configuration of DUT in 2G : BGN
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        6. Enable the power save mode in DUT
        7. Stop the sniffer
        8. Validating Add-ba request from AP/DUT
        9. Validating Add-ba response from AP/DUT 

    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC device)

    Author: Shaik Abdul Azeez
"""


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


def logger():
    return get_logger(__name__)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": RS9116CustomFeatureBitMap.Default},
)
def test_udp_tx_by_enabling_aggregation_c19031(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut,
                                               remote_socket, wifi_client,
                                               protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_udp_tx_by_enabling_aggregation_c19031')
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
    time.sleep(5)

    logger().info("scan for the ap's.....")
    wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"***** Start getting the remote PC IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"remote ip is : {host_ip}")
    logger().info(f"*****Initiating Power_save Mode2 in DUT******")
    logger().info("Enabling wifi power save")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"

    logger().info("Enabling bt power save")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info(f"Initiating ping to DUT ip {device_ip} after power save")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(2)

    logger().info(f"********** Calling IPERF TX, UDP traffic DUT configured as Client **************")
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol:{protocol}")

    logger().info(f"***** starting iperf ******")
    net_perf_client.interfaces.net_perf.start()

    logger().info(f"***** open socket and send traffic ******")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )

    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp is not None, "Throughput not found"
    __print_throughput(tp)
    logger().info("data transfer is successful")

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()
    packet_filter1 = f'(wlan.fc.type_subtype ==0x000d) && (wlan.fixed.action_code == 0x00) && (wlan.sa == {wifi_access_point.interfaces.wifi.bssid}) && (wlan.da == {dut_mac_address})'
    packet_filter2 = f'(wlan.fc.type_subtype ==0x000d) && (wlan.fixed.action_code == 0x01) && (wlan.da == {wifi_access_point.interfaces.wifi.bssid}) && (wlan.sa == {dut_mac_address})'
    packet_filter3 = f'(wlan.fc.type_subtype ==0x000d) && (wlan.fixed.action_code == 0x00) && (wlan.da == {wifi_access_point.interfaces.wifi.bssid}) && (wlan.sa == {dut_mac_address})'
    packet_filter4 = f'(wlan.fc.type_subtype ==0x000d) && (wlan.fixed.action_code == 0x01) && (wlan.sa == {wifi_access_point.interfaces.wifi.bssid}) && (wlan.da == {dut_mac_address})'
    packet_filter5 = f'(wlan.addr =={dut_mac_address} && (wlan.fc.type_subtype == 0x0028 || wlan.fc.type_subtype == 0x0019))'

    logger().info(f"***** Validating packets for Action frame to check Add-ba request from AP  ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        'Unable to find Add-ba request from AP side'

    logger().info(f"***** Validating packets for Action frame to check Add-ba response from DUT ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
        'Unable to find Add-ba response from DUT side'

    logger().info(f"***** Validating packets for Action frame to check Add-ba request from DUT ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'], \
        'Unable to find Add-ba request from DUT side'

    logger().info(f"***** Validating packets for Action frame to check Add-ba response from AP ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)['packet_count'], \
        'Unable to find Add-ba response from AP side'

    logger().info(f"***** Validating Block ACK packets  ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)['packet_count'], \
        'Unable to find Block ACK packets'


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.Default},
)
def test_udp_rx_by_enabling_aggregation_c19032(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut,
                                               remote_socket, wifi_client,
                                               protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_udp_rx_by_enabling_aggregation_c19032')
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
    time.sleep(2)

    logger().info("scan for the ap's.....")
    wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"***** Start getting the remote PC IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"remote ip is : {host_ip}")
    logger().info(f"*****Initiating Power_save Mode2 in DUT******")
    logger().info("Enabling wifi power save")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"

    logger().info("Enabling bt power save")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"
    logger().info(f"Initiating ping to DUT ip {device_ip} after power save")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(2)

    logger().info(f"********** Calling IPERF RX, UDP traffic DUT configured as Server **************")
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol:{protocol}")

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

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    packet_filter1 = f'(wlan.fc.type_subtype ==0x000d) && (wlan.fixed.action_code == 0x00) && (wlan.sa == {wifi_access_point.interfaces.wifi.bssid}) && (wlan.da == {dut_mac_address})'
    packet_filter2 = f'(wlan.fc.type_subtype ==0x000d) && (wlan.fixed.action_code == 0x01) && (wlan.da == {wifi_access_point.interfaces.wifi.bssid}) && (wlan.sa == {dut_mac_address})'
    packet_filter3 = f'(wlan.fc.type_subtype ==0x000d) && (wlan.fixed.action_code == 0x00) && (wlan.da == {wifi_access_point.interfaces.wifi.bssid}) && (wlan.sa == {dut_mac_address})'
    packet_filter4 = f'(wlan.fc.type_subtype ==0x000d) && (wlan.fixed.action_code == 0x01) && (wlan.sa == {wifi_access_point.interfaces.wifi.bssid}) && (wlan.da == {dut_mac_address})'
    packet_filter5 = f'(wlan.addr =={dut_mac_address} && (wlan.fc.type_subtype == 0x0028 || wlan.fc.type_subtype == 0x0019))'

    logger().info(f"***** Validating packets for Action frame to check Add-ba request from AP  ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        'Unable to find Add-ba request from AP side'

    logger().info(f"***** Validating packets for Action frame to check Add-ba response from DUT ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
        'Unable to find Add-ba response from DUT side'

    logger().info(f"***** Validating packets for Action frame to check Add-ba request from DUT ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'], \
        'Unable to find Add-ba request from DUT side'

    logger().info(f"***** Validating packets for Action frame to check Add-ba response from AP ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)['packet_count'], \
        'Unable to find Add-ba response from AP side'

    logger().info(f"***** Validating Block ACK packets  ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)['packet_count'], \
        'Unable to find Block ACK packets'


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'open'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.Default},
)
def test_udp_tx_aggregation_open_mode_with_power_save_c19033(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut,
                                                             remote_socket, wifi_client,
                                                             protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_udp_tx_by_enabling_aggregation_c19033')
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
    time.sleep(2)

    logger().info("scan for the ap's.....")
    wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"***** Start getting the remote PC IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"remote ip is : {host_ip}")

    logger().info(f"*****Initiating Power_save Mode2 in DUT******")
    logger().info("Enabling wifi power save")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"

    logger().info("Enabling bt power save")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info(f"Initiating ping to DUT ip {device_ip} after power save")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(2)

    print('\n\n ********** Calling IPERF TX, UDP traffic DUT configured as Client ********************\n\n')

    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol:{protocol}")

    logger().info(f"***** starting iperf ******")
    net_perf_client.interfaces.net_perf.start()

    logger().info(f"***** open socket and send traffic ******")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )

    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp is not None, "Throughput not found"
    __print_throughput(tp)
    logger().info("data transfer is successful")

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    logger().info("Dut going to leave the AP")
    wifi_dut.interfaces.wifi.leave()

    packet_filter1 = f'(wlan.fc.type_subtype ==0x000d) && (wlan.fixed.action_code == 0x00) && (wlan.sa == {wifi_access_point.interfaces.wifi.bssid}) && (wlan.da == {dut_mac_address})'
    packet_filter2 = f'(wlan.fc.type_subtype ==0x000d) && (wlan.fixed.action_code == 0x01) && (wlan.da == {wifi_access_point.interfaces.wifi.bssid}) && (wlan.sa == {dut_mac_address})'
    packet_filter3 = f'(wlan.fc.type_subtype ==0x000d) && (wlan.fixed.action_code == 0x00) && (wlan.da == {wifi_access_point.interfaces.wifi.bssid}) && (wlan.sa == {dut_mac_address})'
    packet_filter4 = f'(wlan.fc.type_subtype ==0x000d) && (wlan.fixed.action_code == 0x01) && (wlan.sa == {wifi_access_point.interfaces.wifi.bssid}) && (wlan.da == {dut_mac_address})'
    packet_filter5 = f'(wlan.addr =={dut_mac_address} && (wlan.fc.type_subtype == 0x0028 || wlan.fc.type_subtype == 0x0019))'

    logger().info(f"***** Validating packets for Action frame to check Add-ba request from AP  ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        'Unable to find Add-ba request from AP side'

    logger().info(f"***** Validating packets for Action frame to check Add-ba response from DUT ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
        'Unable to find Add-ba response from DUT side'

    logger().info(f"***** Validating packets for Action frame to check Add-ba request from DUT ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'], \
        'Unable to find Add-ba request from DUT side'

    logger().info(f"***** Validating packets for Action frame to check Add-ba response from AP ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)['packet_count'], \
        'Unable to find Add-ba response from AP side'

    logger().info(f"***** Validating Block ACK packets  ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)['packet_count'], \
        'Unable to find Block ACK packets'


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'open'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.Default},
)
def test_udp_rx_aggregation_open_mode_with_power_save_c19034(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut,
                                                             remote_socket, wifi_client,
                                                             protocol):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file='test_udp_rx_aggregation_open_mode_with_power_save_c19034')
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
    time.sleep(2)

    logger().info("scan for the ap's.....")
    wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"***** preparing wifi_dut ******")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    logger().info(f"***** Start getting the remote PC IP address ******")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"remote ip is : {host_ip}")

    logger().info("Enabling wifi power save")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"

    logger().info("Enabling bt power save")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info(f"Initiating ping to DUT ip {device_ip} after power save")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    time.sleep(2)

    logger().info(f"********** Calling IPERF RX, UDP traffic DUT configured as Server **************")
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    logger().info(f"Host IP: {host_ip}")
    logger().info(f"Dut IP: {device_ip}")
    logger().info(f"Protocol:{protocol}")

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

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    packet_filter1 = f'(wlan.fc.type_subtype ==0x000d) && (wlan.fixed.action_code == 0x00) && (wlan.sa == {wifi_access_point.interfaces.wifi.bssid}) && (wlan.da == {dut_mac_address})'
    packet_filter2 = f'(wlan.fc.type_subtype ==0x000d) && (wlan.fixed.action_code == 0x01) && (wlan.da == {wifi_access_point.interfaces.wifi.bssid}) && (wlan.sa == {dut_mac_address})'
    packet_filter3 = f'(wlan.fc.type_subtype ==0x000d) && (wlan.fixed.action_code == 0x00) && (wlan.da == {wifi_access_point.interfaces.wifi.bssid}) && (wlan.sa == {dut_mac_address})'
    packet_filter4 = f'(wlan.fc.type_subtype ==0x000d) && (wlan.fixed.action_code == 0x01) && (wlan.sa == {wifi_access_point.interfaces.wifi.bssid}) && (wlan.da == {dut_mac_address})'
    packet_filter5 = f'(wlan.addr =={dut_mac_address} && (wlan.fc.type_subtype == 0x0028 || wlan.fc.type_subtype == 0x0019))'

    logger().info(f"***** Validating packets for Action frame to check Add-ba request from AP  ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        'Unable to find Add-ba request from AP side'

    logger().info(f"***** Validating packets for Action frame to check Add-ba response from DUT ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
        'Unable to find Add-ba response from DUT side'

    logger().info(f"***** Validating packets for Action frame to check Add-ba request from DUT ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'], \
        'Unable to find Add-ba request from DUT side'

    logger().info(f"***** Validating packets for Action frame to check Add-ba response from AP ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)['packet_count'], \
        'Unable to find Add-ba response from AP side'

    logger().info(f"***** Validating Block ACK packets  ******")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)['packet_count'], \
        'Unable to find Block ACK packets'