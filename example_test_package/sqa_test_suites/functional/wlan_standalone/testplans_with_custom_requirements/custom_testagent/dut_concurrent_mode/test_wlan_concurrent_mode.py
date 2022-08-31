from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
import pytest
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict
from utf_wiseconnect.devices.rs911x import RS9116OperatingMode, RS9116CoexMode, RS9116Band, RS9116FeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116CustomFeatureBitMap, RS9116ExtCustomFeatureBitMap, \
    RS9116ExtTCPIPFeatureBitMap, RS9116AsyncEventType, SocketParams, RS9116ConfigFeatureBitMap, RS9116PowerSaveModes, \
    RS9116PowerSaveProcedureTypes, DeviceConstants
import time
from typing import Dict
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from datetime import datetime
import uuid




"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)(Note:ap_mac will work only with ASUS ap)
    Test Steps:
        1. Configure the DUT in concurrent mode
        2. create DUT as access point and join DUT to 3rd party access point
        3. Initiate ping from the dut and vice versa
        4.Disconnect dut and connect again
        
    Note:1.EFR reset is used  as DUT reset is not working
        2.execute_number fixture used to run test case multiple times
    Author: Aravind 
"""

def logger():
    return get_logger(__name__)
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.Ping,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C19314", "passphrase": "12345678", "channel": 8
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP_C19314", "passphrase": "12345678", "channel": 8, "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.parametrize('execute_number', range(2))
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_device_as_sta_and_ap_c_19314(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
                                      execute_number):
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    ping_iterations = 10
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_device_as_sta_and_ap_c_19314')
    time.sleep(3)

    # preparing wifi_dut as access point - AP Mode

    logger().info("Bringing up DUT in AP mode")
    wifi_dut.interfaces.wifi.start_ap(ssid="RS9116_AP_C19314", security="WPA2", passphrase="12345678", channel=8)
    logger().info("joining 3rd party client to DUT ap")
    wifi_client.interfaces.wifi.join()
    logger().info("fetching gateway ip of ap")
    device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info("fetching ip address of 3rd party sta")
    wifi_client_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info("dut ap mode ip: " + device_ip_dut_as_ap)
    logger().info("wifi_client ip: " + wifi_client_ip)
    status = ping(wifi_client_ip, ping_iterations)
    assert status == 1, "failed to ping to client"

    # preparing wifi_dut as STA - STA Mode
    logger().info("joining to 3rd party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    time.sleep(5)
    logger().info("fetching ip address through DHCP")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    access_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(server_ip=access_point_ip)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'ap mac is {ap_mac}')
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    packet_filter5 = f'((wlan.addr == {dut_mac_address}) and' \
                     f' (!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)))'
    logger().info("DUT Station Mode")
    logger().info("dut station mode ip: " + device_ip_dut_as_client)
    logger().info("access point ip: " + str(access_point_ip))

    logger().info("Disconnecting 3rd party station from RS9116 AP")
    wifi_client.interfaces.wifi.leave()

    logger().info("reconnecting 3rd party station from RS9116 AP")
    wifi_client.interfaces.wifi.join()

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    logger().info("passing passphrase and ssid to decrypt dhcp packets")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    logger().info("DHCP decryption is in progress")
    status = wifi_sniffer.interfaces.capture.get_dhcp_list(dut_mac_address, decryption_key, ["dhcp"])
    logger().info(f'DHCP packet from DUT found: {status}')
    assert status, "DHCP packets not found"

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'
    logger().info("doing EFR reset instead of device reset till reset issue is fixed")
    wifi_dut.interfaces.wifi.reset_soft()


# #####c19315##########

@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.Ping,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C19315", "passphrase": "12345678", "channel": 8
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP_C19315", "passphrase": "12345678", "channel": 8, "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_device_as_sta_and_ap_c_19315(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer):
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    ping_iterations = 10
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_device_as_sta_and_ap_c_19315')
    time.sleep(3)

    # preparing wifi_dut as access point - AP Mode
 
    logger().info("Bringing up DUT in AP mode")
    wifi_dut.interfaces.wifi.start_ap(ssid="RS9116_AP_C19315", security="WPA2", passphrase="12345678", channel=8)
    logger().info("joining 3rd party client to DUT ap")
    wifi_client.interfaces.wifi.join()
    logger().info("fetching gateway ip of ap")
    device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info("fetching ip address of 3rd party sta")
    wifi_client_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info("dut ap mode ip: " + device_ip_dut_as_ap)
    logger().info("wifi_client ip: " + wifi_client_ip)
    status = ping(wifi_client_ip, ping_iterations)
    assert status == 1, "failed to ping to client"

    # preparing wifi_dut as STA - STA Mode
    logger().info("joining to 3rd party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    time.sleep(5)
    logger().info("fetching ip address through DHCP")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    access_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(server_ip=access_point_ip)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'ap mac is {ap_mac}')
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    packet_filter1 = f'((wlan.addr == {dut_mac_address}) and' \
                     f' (!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)))'
    logger().info("DUT Station Mode")
    logger().info("dut station mode ip: " + device_ip_dut_as_client)
    logger().info("access point ip: " + str(access_point_ip))

    logger().info("Disconnecting DUT station from 3rd party AP")
    wifi_dut.interfaces.wifi.leave()

    logger().info("reconnecting DUT station from 3rd party AP")
    wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                  security=wifi_access_point.interfaces.wifi.security,
                                  passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                  channel=wifi_access_point.interfaces.wifi.channel)

    time.sleep(5)
    logger().info("fetching ip address through DHCP")
    wifi_dut.interfaces.wifi.start_ip()

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    logger().info("passing passphrase and ssid to decrypt dhcp packets")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    status = wifi_sniffer.interfaces.capture.get_dhcp_list(dut_mac_address, decryption_key, ["dhcp"])
    logger().info(f'DHCP packet from DUT found: {status}')
    assert status, "DHCP packets not found"

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'
    logger().info("doing EFR reset instead of device reset till reset issue is fixed")
    wifi_dut.interfaces.wifi.reset_soft()

######c19324##########

@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server
                          | RS9116TCPIPFeatureBitMap.Ping | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C19324", "passphrase": "12345678", "channel": 8
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP_C19324", "passphrase": "12345678", "channel": 8, "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_device_as_sta_and_ap_c_19324(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer):
    ping_iterations = 10
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_device_as_sta_and_ap_c_19324')
    time.sleep(3)

    # preparing wifi_dut as access point - AP Mode


    logger().info("Bringing up DUT in AP mode")
    wifi_dut.interfaces.wifi.start_ap(ssid="RS9116_AP_C19324", security="WPA2", passphrase="12345678", channel=8)
    logger().info("joining 3rd party client to DUT ap")
    wifi_client.interfaces.wifi.join()

    logger().info("fetching gateway ip of ap")
    device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip


    logger().info("fetching ip address of 3rd party sta")
    wifi_client_ip = wifi_client.interfaces.wifi.get_ip_address()

    logger().info("dut ap mode ip: " + device_ip_dut_as_ap)
    logger().info("wifi_client ip: " + wifi_client_ip)
    status = ping(wifi_client_ip, ping_iterations)
    assert status == 1, "failed to ping to client"

    # preparing wifi_dut as STA - STA Mode
    logger().info("joining to 3rd party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    time.sleep(5)

    logger().info("fetching ip address through DHCP")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    access_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(access_point_ip)

    logger().info("fetching DUT mac address")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info("fetching 3rd party  mac address")
    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'ap mac is {ap_mac}')
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    packet_filter1 = f'((wlan.addr == {dut_mac_address}) and' \
                     f' (!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)))'

    logger().info("DUT Station Mode")
    logger().info("dut station mode ip: " + device_ip_dut_as_client)
    logger().info("access point ip: " + str(access_point_ip))
    logger().info("Disconnecting DUT station from 3rd party AP")

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    logger().info("passing passphrase and ssid to decrypt dhcp packets")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    status = wifi_sniffer.interfaces.capture.get_dhcp_list(dut_mac_address, decryption_key, ["dhcp"])
    logger().info(f'DHCP packet from DUT found: {status}')
    assert status, "DHCP packets not found"

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'
    logger().info("connect and disconnect for multiple times")
    for count in range(1, 3):
        wifi_dut.interfaces.wifi.leave()

        logger().info("reconnecting DUT station from 3rd party AP")
        time.sleep(10)
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        time.sleep(5)
        for i in range(3):
            try:
                logger().info("fetching ip address through DHCP")
                wifi_dut.interfaces.wifi.start_ip()
            except:
                logger().info(f"Get IP address through dhcp process is failed. retry count -> {i+1}")
                time.sleep(5)

        logger().info(f'connected and disconnected for {count} times')

    logger().info("doing EFR reset instead of device reset till reset issue is fixed")
    wifi_dut.interfaces.wifi.reset_soft()

##########19313###########
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.Ping,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C19313", "passphrase": "12345678", "channel": 8
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP_C19313", "passphrase": "12345678", "channel": 8, "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize('execute_number', range(2))
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_device_as_sta_and_ap_c_19313(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
                                      protocol, net_perf_client, execute_number):
    ping_iterations = 10
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_device_as_sta_and_ap_c_19313')
    time.sleep(3)

    # preparing wifi_dut as STA - STA Mode
    logger().info("joining to 3rd party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    time.sleep(5)

    logger().info("fetching ip address through DHCP")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    access_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(server_ip=access_point_ip)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC: {dut_mac_address}")
    packet_filter5 = f'((wlan.addr == {dut_mac_address}) and' \
                     f' (!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)))'

    # packet_filter3 = f'dhcp.hw.mac_addr == {dut_mac_address}'
    logger().info("DUT Station Mode")
    logger().info("dut station mode ip: " + device_ip_dut_as_client)
    logger().info("access point ip: " + str(access_point_ip))

    # preparing wifi_dut as access point - AP Mode

    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'ap mac is {ap_mac}')
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    logger().info("Bringing up DUT in AP mode")
    wifi_dut.interfaces.wifi.start_ap(ssid="RS9116_AP_C19313", security="WPA2", passphrase="12345678", channel=8)
    logger().info("joining 3rd party client to DUT ap")
    time.sleep(5)
    wifi_client.interfaces.wifi.join()
    logger().info("fetching gateway ip of ap")
    device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info("fetching p address of 3rd party sta")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info("dut ap mode ip: " + device_ip_dut_as_ap)
    logger().info("wifi_client ip: " + host_ip)
    status = ping(host_ip, ping_iterations)
    assert status == 1, "failed to ping to client"
    logger().info("setting eth0 interface on raspi ")
    wifi_client.interfaces.wifi.interface = "eth0"
    logger().info("fetching eth0 interface ip of raspi wifi connected to 3rd party ap over ethernet")
    raspi_ap_ip = wifi_client.interfaces.wifi.get_ip_address(network_interface="eth0")
    logger().info(f"raspi_ap_ip:{raspi_ap_ip}")

    # starting iperf server at raspi client
    logger().info("configured iperf server")
    net_perf_client.interfaces.net_perf.init_server(host_ip=raspi_ap_ip, device_ip=device_ip_dut_as_client,
                                                    protocol=protocol)
    logger().info("started iperf server")
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic from dut
    logger().info("sending data from client dut")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        raspi_ap_ip,
        device_ip_dut_as_client,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    logger().info("passing passphrase and ssid to decrypt dhcp packets")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    status = wifi_sniffer.interfaces.capture.get_dhcp_list(dut_mac_address, decryption_key, ["dhcp"])
    logger().info(f'DHCP packet from DUT found: {status}')
    assert status, "DHCP packets not found"

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'
    logger().info("doing EFR reset instead of device reset till reset issue is fixed")
    wifi_dut.interfaces.wifi.reset_soft()

# ######19322-5Ghz########

# @pytest.mark.skip()
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.Ping,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.FiveGHz,
        "security": "WPA2", "ssid": "RS9116_5Ghz_C19322", "passphrase": "1234567890", "channel": 149,
        # changed to channel 149 because raspi is not supporting channel 161
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 149,
    }

)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_5Ghz_C19322", "passphrase": "1234567890", "channel": 149,
          "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize('execute_number', range(1))
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_device_as_sta_and_ap_c_19322(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
                                      protocol, net_perf_client, execute_number):
    ping_iterations = 10
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_device_as_sta_and_ap_c_19322')
    time.sleep(3)

    # preparing wifi_dut as STA - STA Mode
    logger().info("joining to 3rd party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    time.sleep(5)

    logger().info("fetching ip address through DHCP")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    access_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(server_ip=access_point_ip)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC: {dut_mac_address}")
    packet_filter5 = f'((wlan.addr == {dut_mac_address}) and' \
                     f' (!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)))'

    # packet_filter3 = f'dhcp.hw.mac_addr == {dut_mac_address}'
    logger().info("DUT Station Mode")
    logger().info("dut station mode ip: " + device_ip_dut_as_client)
    logger().info("access point ip: " + str(access_point_ip))

    # preparing wifi_dut as access point - AP Mode

    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'ap mac is {ap_mac}')
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    logger().info("Bringing up DUT in AP mode")
    wifi_dut.interfaces.wifi.start_ap(ssid="RS9116_5Ghz_C19322", security="WPA2", passphrase="1234567890", channel=149)
    time.sleep(15)
    logger().info("joining 3rd party client to DUT ap")
    wifi_client.interfaces.wifi.join()
    logger().info("fetching gateway ip of ap")
    device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info("fetching p address of 3rd party sta")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    logger().info("dut ap mode ip: " + device_ip_dut_as_ap)
    logger().info("wifi_client ip: " + host_ip)
    status = ping(host_ip, ping_iterations)
    assert status == 1, "failed to ping to client"

    wifi_client.interfaces.wifi.interface = "eth0"

    raspi_ap_ip = wifi_client.interfaces.wifi.get_ip_address(network_interface="eth0")
    logger().info(f"raspi_ap_ip:{raspi_ap_ip}")

    # starting iperf server at raspi client
    logger().info("configured iperf server")
    net_perf_client.interfaces.net_perf.init_server(host_ip=raspi_ap_ip, device_ip=device_ip_dut_as_client,
                                                    protocol=protocol)
    logger().info("started iperf server")
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic from dut
    logger().info("sending data from client dut")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        raspi_ap_ip,
        device_ip_dut_as_client,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'
    logger().info("doing EFR reset instead of device reset till reset issue is fixed")
    wifi_dut.interfaces.wifi.reset_soft()



# ##############19312###############

@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 8})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.Ping,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C19312", "passphrase": "12345678", "channel": 8
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP_C19312", "passphrase": "12345678", "channel": 8, "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize('execute_number', range(2))
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_device_as_sta_and_ap_c_19312(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
                                      protocol, net_perf_client, execute_number):
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    ping_iterations = 10
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_device_as_sta_and_ap_c_19312')
    time.sleep(3)

    # preparing wifi_dut as STA - STA Mode
    logger().info("joining to 3rd party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("fetching ip address through DHCP")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    access_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(server_ip=access_point_ip)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC: {dut_mac_address}")
    packet_filter5 = f'((wlan.addr == {dut_mac_address}) and' \
                     f' (!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)))'

    logger().info("DUT Station Mode")
    logger().info("dut station mode ip: " + device_ip_dut_as_client)
    logger().info("access point ip: " + str(access_point_ip))

    # preparing wifi_dut as access point - AP Mode

    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'ap mac is {ap_mac}')
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    logger().info("Bringing up DUT in AP mode")
    wifi_dut.interfaces.wifi.start_ap(ssid="RS9116_AP_C19312", security="WPA2", passphrase="12345678", channel=8)
    logger().info("joining 3rd party client to DUT ap")
    time.sleep(10)
    wifi_client.interfaces.wifi.join()
    logger().info("fetching gateway ip of ap")
    device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info("fetching p address of 3rd party sta")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    logger().info("dut ap mode ip: " + device_ip_dut_as_ap)
    logger().info("wifi_client ip: " + host_ip)
    status = ping(host_ip, ping_iterations)
    assert status == 1, "failed to ping to client"

    # starting iperf server at raspi client
    logger().info("configured iperf server")
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip_dut_as_ap,
                                                    protocol=protocol)
    logger().info("started iperf server")
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic from dut
    logger().info("sending data from client dut")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip_dut_as_ap,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    logger().info("passing passphrase and ssid to decrypt dhcp packets")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    status = wifi_sniffer.interfaces.capture.get_dhcp_list(dut_mac_address, decryption_key, ["dhcp"])
    logger().info(f'DHCP packet from DUT found: {status}')
    assert status, "DHCP packets not found"

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'
    logger().info("doing EFR reset instead of device reset till reset issue is fixed")
    wifi_dut.interfaces.wifi.reset_soft()


# ###################19319#########################
# ##Connectivity of concurrent mode in WPA2 security#######
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 8})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.Ping,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP_C19319", "passphrase": "12345678", "channel": 8
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP_C19319", "passphrase": "12345678", "channel": 8, "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_device_as_sta_and_ap_c_19319(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer):
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_dut.interfaces.wifi.associated = False
    ping_iterations = 10
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_device_as_sta_and_ap_c_19319')
    time.sleep(3)

    # preparing wifi_dut as STA - STA Mode
    logger().info("joining to 3rd party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    time.sleep(5)
    logger().info("fetching ip address through DHCP")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    access_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(server_ip=access_point_ip)
    logger().info("DUT Station Mode")
    logger().info("dut station mode ip: " + device_ip_dut_as_client)
    logger().info("access point ip: " + str(access_point_ip))

    # preparing wifi_dut as access point - AP Mode
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'ap mac is {ap_mac}')
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    logger().info("Bringing up DUT in AP mode")
    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'ap mac is {ap_mac}')
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    logger().info("Bringing up DUT in AP mode")
    wifi_dut.interfaces.wifi.start_ap(ssid="RS9116_AP_C19319", security="WPA2", passphrase="12345678", channel=8)
    logger().info("joining 3rd party client to DUT ap")
    time.sleep(5)
    wifi_client.interfaces.wifi.join()
    logger().info("fetching gateway ip of ap")
    device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info("fetching p address of 3rd party sta")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info("dut ap mode ip: " + device_ip_dut_as_ap)
    logger().info("wifi_client ip: " + host_ip)
    status = ping(host_ip, ping_iterations)
    assert status == 1, "failed to ping to client"

    packet_filter5 = f'((wlan.addr == {dut_mac_address}) and' \
                     f' (!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)))'

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    logger().info("passing passphrase and ssid to decrypt dhcp packets")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    status = wifi_sniffer.interfaces.capture.get_dhcp_list(dut_mac_address, decryption_key, ["dhcp"])
    logger().info(f'DHCP packet from DUT found: {status}')
    assert status, "DHCP packets not found"

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'
    logger().info("doing EFR reset instead of device reset till reset issue is fixed")
    wifi_dut.interfaces.wifi.reset_soft()


# ##############19318###############

@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.Ping,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.TwoPointFourGHz,
        "security": 'WPA2', "ssid": "RS9116_AP_C19318", "channel": 8, "passphrase": "12345678"
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP_C19318", "channel": 8, "passphrase": "12345678", "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize('execute_number', range(2))
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_device_as_sta_and_ap_c_19318(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
                                      protocol, net_perf_client, execute_number):
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    ping_iterations = 10
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_device_as_sta_and_ap_c_19318')
    time.sleep(3)

    # preparing wifi_dut as access point - AP Mode
    logger().info("Bringing up DUT in AP mode")
    wifi_dut.interfaces.wifi.start_ap(ssid="RS9116_AP_C19318", security="WPA2", passphrase="12345678", channel=8)
    logger().info("joining 3rd party client to DUT ap")
    time.sleep(5)
    wifi_client.interfaces.wifi.join()

    logger().info("fetching gateway ip of ap")
    device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info("fetching p address of 3rd party sta")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info("dut ap mode ip: " + device_ip_dut_as_ap)
    logger().info("wifi_client ip: " + host_ip)
    status = ping(host_ip, ping_iterations)
    assert status == 1, "failed to ping to client"

    # preparing wifi_dut as STA - STA Mode
    logger().info("joining to 3rd party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    time.sleep(5)

    logger().info("fetching ip address through DHCP")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    access_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(server_ip=access_point_ip)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'ap mac is {ap_mac}')
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    packet_filter5 = f'((wlan.addr == {dut_mac_address}) and' \
                     f' (!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)))'
    logger().info("DUT Station Mode")
    logger().info("dut station mode ip: " + device_ip_dut_as_client)
    logger().info("access point ip: " + str(access_point_ip))

    # starting iperf server at raspi client with  DUT as AP
    logger().info("configured iperf server")
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip_dut_as_ap,
                                                    protocol=protocol)
    logger().info("started iperf server")
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic from dut to raspi station
    logger().info("sending data from client dut")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip_dut_as_ap,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    logger().info("passing passphrase and ssid to decrypt dhcp packets")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    status = wifi_sniffer.interfaces.capture.get_dhcp_list(dut_mac_address, decryption_key, ["dhcp"])
    logger().info(f'DHCP packet from DUT found: {status}')
    assert status, "DHCP packets not found"

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'
    logger().info("doing EFR reset instead of device reset till reset issue is fixed")
    wifi_dut.interfaces.wifi.reset_soft()



# ##########19320#########
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.Ping,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.TwoPointFourGHz,
        "security": 'WPA2', "ssid": "RS9116_AP_C19320", "channel": 8, "passphrase": "12345678"
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurrent_AP',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP_C19320", "channel": 8, "passphrase": "12345678", "interface": "wlan0"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize('execute_number', range(1))
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_device_as_sta_and_ap_c_19320(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
                                      protocol, net_perf_client, execute_number):
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    ping_iterations = 10
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_device_as_sta_and_ap_c_19320')
    time.sleep(3)

    # preparing wifi_dut as access point - AP Mode

    logger().info("Bringing up DUT in AP mode")
    wifi_dut.interfaces.wifi.start_ap(ssid="RS9116_AP_C19320", security="WPA2", passphrase="12345678", channel=8)
    logger().info("joining 3rd party client to DUT ap")
    time.sleep(10)
    wifi_client.interfaces.wifi.join()

    logger().info("fetching gateway ip of ap")
    device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info("fetching p address of 3rd party sta")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info("dut ap mode ip: " + device_ip_dut_as_ap)
    logger().info("wifi_client ip: " + host_ip)
    status = ping(host_ip, ping_iterations)
    assert status == 1, "failed to ping to client"

    # preparing wifi_dut as STA - STA Mode
    logger().info("joining to 3rd party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("fetching ip address through DHCP")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    access_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(server_ip=access_point_ip)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'ap mac is {ap_mac}')
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    packet_filter5 = f'((wlan.addr == {dut_mac_address}) and' \
                     f' (!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)))'
    logger().info("DUT Station Mode")
    logger().info("dut station mode ip: " + device_ip_dut_as_client)
    logger().info("access point ip: " + str(access_point_ip))

    # starting iperf server at raspi client with  DUT as AP
    logger().info("configured iperf server")
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip_dut_as_ap,
                                                    protocol=protocol)
    logger().info("started iperf server")
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic from dut to raspi station
    logger().info("sending data from dut ap")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip_dut_as_ap,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    logger().info("data transfer successful to 3rd party station from dut ap"
                  )
    logger().info("setting eth0 interface on raspi ")
    wifi_client.interfaces.wifi.interface = "eth0"
    logger().info("fetching eth0 interface ip of raspi wifi connected to 3rd party ap over ethernet")
    raspi_ap_ip = wifi_client.interfaces.wifi.get_ip_address(network_interface="eth0")
    logger().info(f"raspi_ap_ip:{raspi_ap_ip}")

    # starting iperf server at raspi client
    logger().info("configured iperf server")
    net_perf_client.interfaces.net_perf.init_server(host_ip=raspi_ap_ip, device_ip=device_ip_dut_as_client,
                                                    protocol=protocol)
    logger().info("started iperf server")
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic from dut
    logger().info("sending data from dut sta")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        raspi_ap_ip,
        device_ip_dut_as_client,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    logger().info("passing passphrase and ssid to decrypt dhcp packets")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    status = wifi_sniffer.interfaces.capture.get_dhcp_list(dut_mac_address, decryption_key, ["dhcp"])
    logger().info(f'DHCP packet from DUT found: {status}')
    assert status, "DHCP packets not found"

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'
    logger().info("doing EFR reset instead of device reset till reset issue is fixed")
    wifi_dut.interfaces.wifi.reset_soft()
#################################################################################

@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.Ping,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.Default,
        "security": 'WPA2', "ssid": "RASPI_AP", "channel": 8, "passphrase": "12345678"
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'DUT_AP',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 8,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RASPI_AP", "channel": 8, "passphrase": "12345678"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.skip()
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.config('wifi_access_point',
                    wifi={"dhcp_start": "192.168.50.12", "dhcp_end": "192.168.50.20", "dhcp_lease": "180"})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize('execute_number', range(1))
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_device_as_sta_and_ap_c_19316(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
                                      protocol, net_perf_client, execute_number):
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_device_as_sta_and_ap_c_19316')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    # preparing wifi_dut as access point - AP Mode
    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'ap mac is {ap_mac}')
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    logger().info("Bringing up DUT in AP mode")
    wifi_dut.interfaces.wifi.start_ap()
    logger().info("joining 3rd party client to DUT ap")
    time.sleep(20)
    wifi_client.interfaces.wifi.join(ssid="RASPI_AP")
    logger().info("fetching gateway ip of ap")
    device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info("fetching p address of 3rd party sta")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info("dut ap mode ip: " + device_ip_dut_as_ap)
    logger().info("wifi client ip: " + str(host_ip))

    # preparing wifi_dut as STA - STA Mode
    logger().info("joining to 3rd party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("fetching ip address through DHCP")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    access_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(server_ip=access_point_ip)
    packet_filter5 = f'((wlan.addr == {dut_mac_address}) and' \
                     f' (!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)))'
    logger().info("DUT Station Mode")
    logger().info("dut station mode ip: " + device_ip_dut_as_client)
    logger().info("access point ip: " + str(access_point_ip))
    wifi_access_point.interfaces.wifi.enable_dhcp_ap(
        dhcp_start="192.168.50.50",
        dhcp_end="192.168.50.60",
        dhcp_lease=120)
    time.sleep(120)


    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    logger().info("passing passphrase and ssid to decrypt dhcp packets")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    status = wifi_sniffer.interfaces.capture.get_dhcp_list(dut_mac_address, decryption_key, ["dhcp"])
    logger().info(f'DHCP packet from DUT found: {status}')
    assert status, "DHCP packets not found"

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'
    logger().info("doing EFR reset instead of device reset till reset issue is fixed")
    wifi_dut.interfaces.wifi.reset_soft()


# ###############C19321########################

def get_igmp_list(wifi_sniffer, dut_mac_address, decryption_key: str, print_layers: list, capture_filename, mode=0) -> \
        Dict[str, int]:
    igmp_capture_list = []
    current_time = time.time()
    updated_capture_file = 'filter_' + capture_filename + '_' + str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    file_name = f'./reports/{updated_capture_file}.pcap'
    local_capture_file = file_name
    wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
    packet_filter1 = f'(wlan.addr == {dut_mac_address})'
    wifi_sniffer.interfaces.capture.shell(
        f"tshark -nr {wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter1}' -T fields -e "
        f"frame.number -w "
        f"{wlan_filter_file}")
    with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
        sftp.get(wlan_filter_file, local_capture_file)
    for packet in wifi_sniffer.interfaces.capture.iter_packets(
            decrypt_packets=True,
            encryption_type="WPA-PWD",
            decryption_key=decryption_key,
            capture_file_filter=local_capture_file
    ):
        for layer in packet.layers:
            layer_name = layer.layer_name.lower()
            if layer_name == "wlan":
                mac_layer = str(layer)
                for count in mac_layer.split("\n"):
                    if "Transmitter address" in count:
                        ta_address = count.split(": ")[1].strip()
            if layer_name in print_layers:
                if ta_address == dut_mac_address:
                    igmp_layer = str(layer)
                    logger().info(f"As per sniffer capture IGMP packets sent by DUT..{ta_address}  ->  {igmp_layer}")
                    igmp_capture_list.append(tuple([igmp_layer, packet.sniff_timestamp]))
    return igmp_capture_list


def join_get_ip(wifi_access_point, utf_constants, wifi_dut):
    ping_count = utf_constants.get("ping_count")
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f"DUT firmware version: {result}")
    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger().info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None)
            scan_fail = 0
            break
        except:
            logger().info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger().info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                    scan_interval=6,
                                    beacon_missedcount=40,
                                    first_time_retry=0)
    for count in range(1, 3):
        try:
            join_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger().info("Joining to the Wifi Access Point")
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            join_fail = 0
            break
        except:
            logger().info(f"Joining to the Wifi Access point is failed. retry count -> {count}")
            time.sleep(1)
    if join_fail:
        logger().info(f"Joining to the AP has failed")
        assert join_fail == 0, "Joining to the AP is failed"
    for count in range(1, 3):
        ip_fail = 1
        try:
            # DUT gets ipaddress through DHCP process after start_ip API is executed
            logger().info("DUT gets ipaddress through DHCP ")
            ip_address = wifi_dut.interfaces.wifi.start_ip(timeout=60)
            ip_fail = 0
            break
        except:
            logger().info(f"Get IP address through dhcp process is failed. retry count -> {count}")
            time.sleep(1)
    if ip_fail:
        logger().info(f"DUT unable to get IP address")
        assert ip_fail == 0, "ip setting in DUT has failed"
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger().info(f"Initiating ping to DUT ip {device_ip} after power save")
    ping(device_ip, ping_count)
    return mac_address, device_ip


# pytestmark = [
#     pytest.mark.config(
#         "wifi_dut",
#         wifi=
#         {
#             "oper_mode": RS9116OperatingMode.ConcurrentMode,
#             "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#             "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#             "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
#             "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
#             "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
#             "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
#             "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
#             "set_send_feature_frame": True,
#             "band": RS9116Band.Default,
#         }
#     )
# ]



@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["multicast_leave", "close_sockets", "wifi_powersave_disable", "bt_powersave_disable",
                             "disassociated"])
def test_sta_ap_multicast_data_c19321(wifi_sniffer, wifi_access_point, utf_constants, wifi_client, wifi_dut,
                                      multicast_client):
    capture_file = 'test_device_as_sta_and_ap_C19321'
    ping_count = utf_constants.get("ping_count")
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    logger().info(f"preparing wifi_dut as STA - STA Mode")
    dut_mac_address, device_ip = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut)
    logger().info("Bringing up DUT in AP mode")
    wifi_dut.interfaces.wifi.start_ap()
    logger().info("joining 3rd party client to DUT ap")
    wifi_client.interfaces.wifi.join()
    logger().info("fetching gateway ip of ap")
    device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info("fetching p address of 3rd party sta")
    wifi_client_ip = wifi_client.interfaces.wifi.get_ip_address()
    status = ping(device_ip_dut_as_ap, ping_count)
    assert status == 1, f"unable to ping to the dut"
    logger().info("dut ap mode ip: " + device_ip_dut_as_ap)
    logger().info("wifi client ip: " + str(wifi_client_ip))
    ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()
    logger().info(f"multicast_ip : {multicast_ip}")
    wifi_dut.interfaces.wifi.join_multicast_group(ip_version, multicast_ip)
    socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
    assert socket_id == 0, f"socket id received is wrong, expected is 0"
    logger().info(f"socket id received is {socket_id} which is expected")
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)
    logger().info(f"Starting server remotely at {multicast_ip} and port number {server_port}")
    multicast_client.interfaces.multicast.start_server()
    logger().info(
        f"Send {no_of_pkts} of packets with buffer length {buffer_length} from remote device to socket address->{multicast_ip}:{device_port}")
    multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
    multicast_client.interfaces.multicast.socket_close()
    time.sleep(30)
    result = wifi_dut.interfaces.wifi.close_socket(socket_id)
    assert b"success" in result, "unable to close opened socket in the dut"
    logger().info("Successfully closed opened socket in the DUT")
    result = wifi_dut.interfaces.wifi.get_socket_rx_stats(socket_id)
    bytes_received = int(result.split(b":")[1])
    bytes_sent = (no_of_pkts * buffer_length)
    packet_loss = (((bytes_sent - bytes_received) / bytes_sent) * 100)
    logger().info(f"Packet loss {packet_loss}")
    assert packet_loss < 20, "Packet loss is not in tolerance level"
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    wifi_dut.interfaces.wifi.leave_multicast_group(multicast_ip=multicast_ip)
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    igmp_list = get_igmp_list(wifi_sniffer, dut_mac_address, decryption_key, ["igmp"], capture_file)
    assert len(igmp_list) > 0, "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger().info(f"PS-POLL packets are captured in the sniffer")
    logger().info("device reset")
    wifi_dut.interfaces.wifi.reset()








