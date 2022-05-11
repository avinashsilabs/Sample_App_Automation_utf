from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
import pytest
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict
from utf_wiseconnect.devices.rs911x import RS9116OperatingMode, RS9116CoexMode, RS9116Band, RS9116FeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116CustomFeatureBitMap, RS9116ExtCustomFeatureBitMap,\
    RS9116ExtTCPIPFeatureBitMap,RS9116AsyncEventType
import time
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping


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
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 8
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
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 8}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.parametrize('execute_number', range(1))
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_device_as_sta_and_ap_c_19314(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
                                        execute_number):
    validation = True
    ping_iterations = 10
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_device_as_sta_and_ap_c_19314')
    # preparing wifi_dut as access point - AP Mode
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'ap mac is {ap_mac}')
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    logger().info("Bringing up DUT in AP mode")
    wifi_dut.interfaces.wifi.start_ap()
    logger().info("joining 3rd party client to DUT ap")
    wifi_client.interfaces.wifi.join()
    logger().info("fetching gateway ip of ap")
    device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info("fetching p address of 3rd party sta")
    wifi_client_ip = wifi_client.interfaces.wifi.get_ip_address()
    status = ping(wifi_client_ip, ping_iterations)
    assert status == 1
    logger().info("dut ap mode ip: " + device_ip_dut_as_ap)
    logger().info("wifi client ip: " + str(wifi_client_ip))

    # preparing wifi_dut as STA - STA Mode
    logger().info("joining to 3rd party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info("fetching ip address through DHCP")
    ip_config = wifi_dut.interfaces.wifi.start_ip(vap_id=1)
    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    acces_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(server_ip=acces_point_ip)
    packet_filter5 = f'((wlan.addr == {dut_mac_address}) and' \
                     f' (!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)))'
    logger().info("DUT Station Mode")
    logger().info("dut station mode ip: " + device_ip_dut_as_client)
    logger().info("access point ip: " + str(acces_point_ip))

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
    assert status == True,"DUT mac not found in DHCP packet"

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'
    logger().info("doing EFR reset instead of device reset till reset issue is fixed")
    wifi_dut.interfaces.wifi.reset_soft()


######c19315##########

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
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 8
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
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 8}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_device_as_sta_and_ap_c_19315(firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer):
    validation = True
    ping_iterations = 10
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_device_as_sta_and_ap_c_19315')
    # preparing wifi_dut as access point - AP Mode
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'ap mac is {ap_mac}')
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    logger().info("Bringing up DUT in AP mode")
    wifi_dut.interfaces.wifi.start_ap()
    logger().info("joining 3rd party client to DUT ap")
    wifi_client.interfaces.wifi.join()
    logger().info("fetching gateway ip of ap")
    device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info("fetching p address of 3rd party sta")
    wifi_client_ip = wifi_client.interfaces.wifi.get_ip_address()
    status = ping(wifi_client_ip, ping_iterations)
    assert status == 1
    logger().info("dut ap mode ip: " + device_ip_dut_as_ap)
    logger().info("wifi client ip: " + str(wifi_client_ip))

    # preparing wifi_dut as STA - STA Mode
    logger().info("joining to 3rd party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info("fetching ip address through DHCP")
    ip_config = wifi_dut.interfaces.wifi.start_ip(vap_id=1)
    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    acces_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(server_ip=acces_point_ip)
    packet_filter1 = f'((wlan.addr == {dut_mac_address}) and' \
                     f' (!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)))'
    logger().info("DUT Station Mode")
    logger().info("dut station mode ip: " + device_ip_dut_as_client)
    logger().info("access point ip: " + str(acces_point_ip))

    logger().info("Disconnecting DUT station from 3rd party AP")
    wifi_dut.interfaces.wifi.leave()

    logger().info("reconnecting DUT station from 3rd party AP")
    wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                  security=wifi_access_point.interfaces.wifi.security,
                                  passphrase=wifi_access_point.interfaces.wifi.passphrase)

    logger().info("fetching ip address through DHCP")
    wifi_dut.interfaces.wifi.start_ip(vap_id=1)

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    logger().info("passing passphrase and ssid to decrypt dhcp packets")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    status = wifi_sniffer.interfaces.capture.get_dhcp_list(dut_mac_address, decryption_key, ["dhcp"])
    logger().info(f'DHCP packet from DUT found: {status}')
    assert status == True,"DUT mac not found in DHCP packet"

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
        "band": RS9116Band.Default,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 8
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
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 8}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_device_as_sta_and_ap_c_19324(firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer):
    validation = True
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_device_as_sta_and_ap_c_19324')
    # preparing wifi_dut as access point - AP Mode
    logger().info("fetching DUT mac address")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    logger().info("fetching 3rd party  mac address")
    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'ap mac is {ap_mac}')
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info("Bringing up DUT in AP mode")
    wifi_dut.interfaces.wifi.start_ap()

    time.sleep(10)
    logger().info("joining 3rd party client to DUT ap")
    wifi_client.interfaces.wifi.join()

    logger().info("fetching gateway ip of ap")
    device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip
    assert (
            wifi_client.interfaces.wifi.ping(
                server_ip=wifi_client.interfaces.wifi.client_gateway_ip
            )
            < 0.1
    )

    logger().info("fetching ip address of 3rd party sta")
    wifi_client_ip = wifi_client.interfaces.wifi.get_ip_address()
    time.sleep(5)
    logger().info("dut ap mode ip: " + device_ip_dut_as_ap)
    logger().info("wifi client ip: " + str(wifi_client_ip))

     # preparing wifi_dut as STA - STA Mode
    logger().info("joining to 3rd party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("fetching ip address through DHCP")
    ip_config = wifi_dut.interfaces.wifi.start_ip(vap_id=1)

    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    acces_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(acces_point_ip)

    packet_filter1 = f'((wlan.addr == {dut_mac_address}) and' \
                     f' (!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)))'

    logger().info("DUT Station Mode")
    logger().info("dut station mode ip: " + device_ip_dut_as_client)
    logger().info("access point ip: " + str(acces_point_ip))
    logger().info("Disconnecting DUT station from 3rd party AP")

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    logger().info("passing passphrase and ssid to decrypt dhcp packets")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    status = wifi_sniffer.interfaces.capture.get_dhcp_list(dut_mac_address, decryption_key, ["dhcp"])
    logger().info(f'DHCP packet from DUT found: {status}')
    assert status == True,"DUT mac not found in DHCP packet"

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'
    logger().info("connect and disconnect for multiple times")
    for count in range(1, 3):
        wifi_dut.interfaces.wifi.leave()

        logger().info("reconnecting DUT station from 3rd party AP")
        time.sleep(10)
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,security=wifi_access_point.interfaces.wifi.security,\
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase)

        logger().info("fetching ip address through DHCP")
        wifi_dut.interfaces.wifi.start_ip(vap_id=1)

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
        "band": RS9116Band.Default,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 8
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
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 8}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize('execute_number', range(2))
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])

def test_device_as_sta_and_ap_c_19313(firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
                                            protocol, net_perf_client, execute_number):
    validation = True
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_device_as_sta_and_ap_c_19313')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    # preparing wifi_dut as STA - STA Mode
    logger().info("joining to 3rd party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("fetching ip address through DHCP")
    ip_config = wifi_dut.interfaces.wifi.start_ip(vap_id=1)
    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    acces_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(server_ip=acces_point_ip)
    packet_filter5 = f'((wlan.addr == {dut_mac_address}) and' \
                     f' (!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)))'

    # packet_filter3 = f'dhcp.hw.mac_addr == {dut_mac_address}'
    logger().info("DUT Station Mode")
    logger().info("dut station mode ip: " + device_ip_dut_as_client)
    logger().info("access point ip: " + str(acces_point_ip))


    # preparing wifi_dut as access point - AP Mode

    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'ap mac is {ap_mac}')
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    logger().info("Bringing up DUT in AP mode")
    wifi_dut.interfaces.wifi.start_ap()
    logger().info("joining 3rd party client to DUT ap")
    time.sleep(5)
    wifi_client.interfaces.wifi.join()
    logger().info("fetching gateway ip of ap")
    device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info("fetching p address of 3rd party sta")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info("dut ap mode ip: " + device_ip_dut_as_ap)
    logger().info("wifi client ip: " + str(host_ip))

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
    assert status == True,"DUT mac not found in DHCP packet"

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'
    logger().info("doing EFR reset instead of device reset till reset issue is fixed")
    wifi_dut.interfaces.wifi.reset_soft()

#######19322-5Ghz########

@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "features": RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.Ping,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.FiveGHz,
        "security": "WPA2", "ssid": "RS9116_5Ghz", "passphrase": "12345678", "channel": 149,
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
    wifi={"security": "WPA2", "ssid": "RS9116_5Ghz", "passphrase": "12345678", "channel": 149}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize('execute_number', range(1))
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_device_as_sta_and_ap_c_19322(firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
                                            protocol, net_perf_client, execute_number):
    validation = True
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_device_as_sta_and_ap_c_19322')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    # preparing wifi_dut as STA - STA Mode
    logger().info("joining to 3rd party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("fetching ip address through DHCP")
    ip_config = wifi_dut.interfaces.wifi.start_ip(vap_id=1)
    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    acces_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(server_ip=acces_point_ip)
    packet_filter5 = f'((wlan.addr == {dut_mac_address}) and' \
                     f' (!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)))'

    # packet_filter3 = f'dhcp.hw.mac_addr == {dut_mac_address}'
    logger().info("DUT Station Mode")
    logger().info("dut station mode ip: " + device_ip_dut_as_client)
    logger().info("access point ip: " + str(acces_point_ip))


    # preparing wifi_dut as access point - AP Mode

    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'ap mac is {ap_mac}')
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    logger().info("Bringing up DUT in AP mode")
    wifi_dut.interfaces.wifi.start_ap()
    time.sleep(10)
    logger().info("joining 3rd party client to DUT ap")
    wifi_client.interfaces.wifi.join(ssid=wifi_client.interfaces.wifi.ssid,
                                  security=wifi_client.interfaces.wifi.security,
                                  passphrase=wifi_client.interfaces.wifi.passphrase)
    logger().info("fetching gateway ip of ap")
    device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info("fetching p address of 3rd party sta")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    logger().info("dut ap mode ip: " + device_ip_dut_as_ap)
    logger().info("wifi client ip: " + str(host_ip))

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

###############19312###############


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
        "band": RS9116Band.Default,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 8
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
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 8}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize('execute_number', range(2))
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_device_as_sta_and_ap_c_19312(firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
                                            protocol, net_perf_client, execute_number):
    validation = True
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_device_as_sta_and_ap_c_19312')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    # preparing wifi_dut as STA - STA Mode
    logger().info("joining to 3rd party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("fetching ip address through DHCP")
    ip_config = wifi_dut.interfaces.wifi.start_ip(vap_id=1)
    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    acces_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(server_ip=acces_point_ip)

    packet_filter5 = f'((wlan.addr == {dut_mac_address}) and' \
                     f' (!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)))'

    logger().info("DUT Station Mode")
    logger().info("dut station mode ip: " + device_ip_dut_as_client)
    logger().info("access point ip: " + str(acces_point_ip))

    # preparing wifi_dut as access point - AP Mode

    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'ap mac is {ap_mac}')
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    logger().info("Bringing up DUT in AP mode")
    wifi_dut.interfaces.wifi.start_ap()
    logger().info("joining 3rd party client to DUT ap")
    time.sleep(5)
    wifi_client.interfaces.wifi.join()
    logger().info("fetching gateway ip of ap")
    device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info("fetching p address of 3rd party sta")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    logger().info("dut ap mode ip: " + device_ip_dut_as_ap)
    logger().info("wifi client ip: " + str(host_ip))


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
    assert status == True,"DUT mac not found in DHCP packet"

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'
    logger().info("doing EFR reset instead of device reset till reset issue is fixed")
    wifi_dut.interfaces.wifi.reset_soft()



####################19319#########################
###Connectivity of concurrent mode in WPA2 security#######
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
        "band": RS9116Band.Default,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 8
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
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 8}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_device_as_sta_and_ap_c_19319(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer):
    validation = True
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_device_as_sta_and_ap_c_19319')

    # preparing wifi_dut as STA - STA Mode
    logger().info("joining to 3rd party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info("fetching ip address through DHCP")
    ip_config = wifi_dut.interfaces.wifi.start_ip(vap_id=1)
    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    acces_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(server_ip=acces_point_ip)
    logger().info("DUT Station Mode")
    logger().info("dut station mode ip: " + device_ip_dut_as_client)
    logger().info("access point ip: " + str(acces_point_ip))

    # preparing wifi_dut as access point - AP Mode
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'ap mac is {ap_mac}')
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    logger().info("Bringing up DUT in AP mode")
    wifi_dut.interfaces.wifi.start_ap()
    logger().info("joining 3rd party client to DUT ap")
    wifi_client.interfaces.wifi.join()
    logger().info("fetching gateway ip of ap")
    device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info("fetching p address of 3rd party sta")
    wifi_client_ip = wifi_client.interfaces.wifi.get_ip_address()
    status = ping(device_ip_dut_as_ap, )
    assert status == 1
    logger().info("dut ap mode ip: " + device_ip_dut_as_ap)
    logger().info("wifi client ip: " + str(wifi_client_ip))
    packet_filter5 = f'((wlan.addr == {dut_mac_address}) and' \
                     f' (!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)))'

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    logger().info("passing passphrase and ssid to decrypt dhcp packets")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    status = wifi_sniffer.interfaces.capture.get_dhcp_list(dut_mac_address, decryption_key, ["dhcp"])
    logger().info(f'DHCP packet from DUT found: {status}')
    assert status == True,"DUT mac not found in DHCP packet"

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'
    logger().info("doing EFR reset instead of device reset till reset issue is fixed")
    wifi_dut.interfaces.wifi.reset_soft()


###############19312###############


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
        "security": 'WPA2', "ssid": "ABCD", "channel": 8,"passphrase": "12345678"
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
    wifi={"security": "WPA2", "ssid": "ABCD", "channel": 8, "passphrase": "12345678"}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize('execute_number', range(1))
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_device_as_sta_and_ap_c_19318(firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
                                            protocol, net_perf_client, execute_number):
    validation = True
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_device_as_sta_and_ap_c_19318')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    # preparing wifi_dut as access point - AP Mode
    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'ap mac is {ap_mac}')
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    logger().info("Bringing up DUT in AP mode")
    wifi_dut.interfaces.wifi.start_ap()
    logger().info("joining 3rd party client to DUT ap")
    time.sleep(20)
    wifi_client.interfaces.wifi.join(ssid="ABCD")
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
    ip_config = wifi_dut.interfaces.wifi.start_ip(vap_id=1)
    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    acces_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(server_ip=acces_point_ip)
    packet_filter5 = f'((wlan.addr == {dut_mac_address}) and' \
                     f' (!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)))'
    logger().info("DUT Station Mode")
    logger().info("dut station mode ip: " + device_ip_dut_as_client)
    logger().info("access point ip: " + str(acces_point_ip))

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
    assert status == True,"DUT mac not found in DHCP packet"

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'
    logger().info("doing EFR reset instead of device reset till reset issue is fixed")
    wifi_dut.interfaces.wifi.reset_soft()

###########19320#########


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
        "security": 'WPA2', "ssid": "RASPI_AP", "channel": 8,"passphrase": "12345678"
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
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize('execute_number', range(1))
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_device_as_sta_and_ap_c_19320(firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
                                            protocol, net_perf_client, execute_number):
    validation = True
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_device_as_sta_and_ap_c_19320')
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
    ip_config = wifi_dut.interfaces.wifi.start_ip(vap_id=1)
    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    acces_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(server_ip=acces_point_ip)
    packet_filter5 = f'((wlan.addr == {dut_mac_address}) and' \
                     f' (!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)))'
    logger().info("DUT Station Mode")
    logger().info("dut station mode ip: " + device_ip_dut_as_client)
    logger().info("access point ip: " + str(acces_point_ip))

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
    assert status == True,"DUT mac not found in DHCP packet"

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'
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
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid | RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.Default,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 8
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
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 8}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])

def test_device_as_sta_and_ap_c_19317(firmware_loader, wifi_access_point, wifi_dut, wifi_client, wifi_sniffer, protocol):
    validation = True
    wifi_dut.interfaces.wifi.associated = False
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_device_as_sta_and_ap_c_19317')
    logger().info("enabling rejoin params in DUT")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=20, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
    time.sleep(5)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    # preparing wifi_dut as STA - STA Mode
    logger().info("joining to 3rd party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("fetching ip address through DHCP")
    ip_config = wifi_dut.interfaces.wifi.start_ip(vap_id=1)
    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    acces_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(server_ip=acces_point_ip)
    packet_filter5 = f'((wlan.addr == {dut_mac_address}) and' \
                     f' (!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)))'

    # packet_filter3 = f'dhcp.hw.mac_addr == {dut_mac_address}'
    logger().info("DUT Station Mode")
    logger().info("dut station mode ip: " + device_ip_dut_as_client)
    logger().info("access point ip: " + str(acces_point_ip))

    # preparing wifi_dut as access point - AP Mode

    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'ap mac is {ap_mac}')
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    logger().info("Bringing up DUT in AP mode")
    wifi_dut.interfaces.wifi.start_ap()
    logger().info("joining 3rd party client to DUT ap")
    time.sleep(5)
    wifi_client.interfaces.wifi.join()
    logger().info("fetching gateway ip of ap")
    device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info("fetching p address of 3rd party sta")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info("dut ap mode ip: " + device_ip_dut_as_ap)
    logger().info("wifi client ip: " + str(host_ip))
    logger().info("****** AP radio is going in disable mode ******")
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(120)
    while 1:
        """validate rejoin retry failure"""
        events = wifi_dut.interfaces.wifi.get_async_events()
        rejoin_error_events = [event for event in events if
                               event.event_type == RS9116AsyncEventType.RejoinError]
        if len(rejoin_error_events):
            logger().info(f'RE-JOIN ERROR = {rejoin_error_events}')
            break
        else:
            logger().info(f'RE-JOIN ERROR not observed')
            assert False

    wifi_access_point.interfaces.wifi.start_ap()

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

    logger().info("passing passphrase and ssid to decrypt dhcp packets")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    status = wifi_sniffer.interfaces.capture.get_dhcp_list(dut_mac_address, decryption_key, ["dhcp"])
    logger().info(f'DHCP packet from DUT found: {status}')
    assert status == True,"DUT mac not found in DHCP packet"

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'
    logger().info("doing EFR reset instead of device reset till reset issue is fixed")
    wifi_dut.interfaces.wifi.reset_soft()
