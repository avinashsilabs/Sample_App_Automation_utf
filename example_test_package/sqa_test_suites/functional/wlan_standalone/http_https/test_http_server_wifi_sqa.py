# Test author: Vinod.G
# Test suite: HTTP server test suite
import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, DeviceConstants, \
    RS9116AsyncEventType, SocketOptions, RS9116PowerSaveProcedureTypes, RS9116CustomFeatureBitMap
import time
from typing import Dict
from utf.utils.iperf.iperf_utils import ping
from datetime import datetime
from random import randint
import uuid

"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G : BGN by enabling HTTP server feature in the DUT
        2. Association of Third party AP's
        3. Get the valid IP address
        4. HTTP get request from the Raspberry-pi to DUT 
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""


def get_tcp_pkt_list(wifi_sniffer, dut_mac_address, logger, decryption_key: str, print_layers: list, capture_filename,
                     ) -> Dict[str, int]:
    tcp_capture_list = []
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
                tcp_layer = str(layer)
                logger.info(f"As per sniffer capture TCP packets exchanged b/w DUT and destination -> {tcp_layer}")
                tcp_capture_list.append(tuple([tcp_layer, ta_address, packet.sniff_timestamp]))
    return tcp_capture_list


def join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger):
    ping_count = 10
    result = wifi_dut.interfaces.wifi.version()
    logger.info(f"DUT firmware version: {result}")
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )
    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None)
            scan_fail = 0
            break
        except:
            logger.info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger.info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")

    logger.info("Start the sniffer")
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap"
    )

    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                    scan_interval=6,
                                    beacon_missedcount=40,
                                    first_time_retry=0)
    for count in range(1, 3):
        try:
            join_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Joining to the Wifi Access Point")
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            join_fail = 0
            break
        except:
            logger.info(f"Joining to the Wifi Access point is failed. retry count -> {count}")
            time.sleep(1)
    if join_fail:
        logger.info(f"Joining to the AP has failed")
        assert join_fail == 0, "Joining to the AP is failed"
    for count in range(1, 3):
        ip_fail = 1
        try:
            # DUT gets ipaddress through DHCP process after start_ip API is executed
            logger.info("DUT gets ipaddress through DHCP ")
            ip_address = wifi_dut.interfaces.wifi.start_ip(timeout=60)
            ip_fail = 0
            break
        except:
            logger.info(f"Get IP address through dhcp process is failed. retry count -> {count}")
            time.sleep(1)
    if ip_fail:
        logger.info(f"DUT unable to get IP address")
        assert ip_fail == 0, "ip setting in DUT has failed"
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    ping(device_ip, ping_count)
    return mac_address


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("repeat", [10])
def test_wifi_http_server_TC19235(wifi_sniffer, wifi_dut, wifi_access_point, http_server, http_client, logger, repeat):
    current_time = time.time()
    capture_filename = "test_wifi_http_server_TC3595"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    index_path = "/"
    method = "GET"

    for count in range(0, repeat):
        logger.info(f"Sending http get request from third party client to DUT {count + 1} time")
        status, resp_content = http_client.interfaces.http.http_request(
            http_server.interfaces.http, method, index_path, server_ip=device_ip, timeout=20
        )
        logger.info(f"Length of DUTs  webpage {len(resp_content)} in iteration {count + 1}")
        logger.info(f"***************Contents of webpage on iteration {count + 1}------------->   {resp_content}\n\n\n"
                    f"*****")
        file_time_stamp = str(
            datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))

        webpage = "./reports/" + capture_filename + "webpage" + file_time_stamp + ".html"

        logger.info(f"webpage sent by DUT on iteration {count + 1} is {webpage}")
        with open(webpage, "w") as recv:
            recv.write(resp_content.decode())

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPSServer | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "server_cert": "server-cert.pem",
        "server_key": "server-key.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls_dut")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("repeat", [10])
def test_wifi_https_server_TC19236(wifi_sniffer, wifi_dut, wifi_access_point, http_server, http_client, logger, repeat):
    current_time = time.time()
    capture_filename = "test_wifi_https_server_TC19236"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    index_path = "/"
    method = "GET"

    for count in range(0, repeat):
        logger.info(f"Sending http get request from third party client to DUT {count + 1} time")
        status, resp_content = http_client.interfaces.http.http_request(
            http_server.interfaces.http, method, index_path, server_ip=device_ip, timeout=20
        )
        logger.info(f"Length of DUTs  webpage {len(resp_content)} in iteration {count + 1}")
        logger.info(f"***************Contents of webpage on iteration {count + 1}------------->   {resp_content}\n\n\n"
                    f"*****")
        file_time_stamp = str(
            datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))

        webpage = "./reports/" + capture_filename + "webpage" + file_time_stamp + ".html"

        logger.info(f"webpage sent by DUT on iteration {count + 1} is {webpage}")
        with open(webpage, "w") as recv:
            recv.write(resp_content.decode())

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPSServer | RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "server_cert": "server-cert.pem",
        "server_key": "server-key.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls_dut")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_enable1_http_https_server_TC19238(wifi_sniffer, wifi_dut, wifi_access_point, http_server, http_client,
                                                logger):
    current_time = time.time()
    capture_filename = "test_wifi_enable1_http_https_server_TC19238"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    index_path = "/"
    method = "GET"

    for count in range(0, 1):
        logger.info(f"Sending http get request from third party client to DUT {count + 1} time")
        status, resp_content = http_client.interfaces.http.http_request(
            http_server.interfaces.http, method, index_path, server_ip=device_ip, timeout=20
        )
        logger.info(f"Length of DUTs  webpage {len(resp_content)} in iteration {count + 1}")
        logger.info(f"***************Contents of webpage on iteration {count + 1}------------->   {resp_content}\n\n\n"
                    f"*****")
        file_time_stamp = str(
            datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))

        webpage = "./reports/" + capture_filename + "webpage" + file_time_stamp + ".html"

        logger.info(f"webpage sent by DUT on iteration {count + 1} is {webpage}")
        with open(webpage, "w") as recv:
            recv.write(resp_content.decode())

    logger.info(f"HTTPS server is activated when both http, https servers are enabled in the DUT which is expected")
    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPSServer | RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_enable2_http_https_server_TC19238(wifi_sniffer, wifi_dut, wifi_access_point, http_server, http_client,
                                                logger):
    capture_filename = "test_wifi_enable2_http_https_server_TC19238"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    index_path = "/"
    method = "GET"
    try:
        status, resp_content = http_client.interfaces.http.http_request(
            http_server.interfaces.http, method, index_path, server_ip=device_ip, timeout=20
        )
        assert status != 200, f"HTTP server is activated  in the DUT when both HTTP and HTTPS server features are " \
                              f"enabled which " \
                              f"is not expected "

    except:
        logger.info("HTTP server is not activated in the DUT when both HTTP and HTTPS server are enabled which is "
                    "expected")

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPSServer | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "server_cert": "server-cert.pem",
        "server_key": "server-key.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls_dut")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_https_server_erase_cert_TC19237(wifi_sniffer, wifi_dut, wifi_access_point, http_server, http_client,
                                              logger):
    capture_filename = "test_wifi_https_server_erase_cert_TC19237"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces.wifi.clear_certificate(6)
    wifi_dut.interfaces.wifi.clear_certificate(7)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    index_path = "/"
    method = "GET"
    try:
        status, resp_content = http_client.interfaces.http.http_request(
            http_server.interfaces.http, method, index_path, server_ip=device_ip, timeout=20
        )
        assert status != 200, f"SSL connection is successful even though certificates are not loaded in the DUT"
    except:
        logger.info("SSL connection failed when certificates are erased in the DUT which is expected")

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("timeout", [100])
def test_wifi_http_server_timeout_TC19239(remote_socket_factory, wifi_sniffer, wifi_dut, wifi_access_point, http_server,
                                          http_client, logger, timeout):
    bssid = wifi_access_point.interfaces.wifi.bssid
    bssid = bssid.strip()
    logger.info(f'AP BSSID = {bssid}')
    capture_filename = "test_wifi_http_server_timeout_TC19239"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    server_port = 80
    client_socket = remote_socket_factory.interfaces.socket.create_socket()
    logger.info(f"Connecting from remote device to DUT socket {(device_ip, server_port)}")
    local_port = randint(5001, 65535)
    client_socket.connect_client_tcp(device_ip, server_port, client_port=local_port)
    time.sleep(timeout + 10)

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    tcp_pkt_list = get_tcp_pkt_list(wifi_sniffer, dut_mac_address, logger, decryption_key, ["tcp"],
                                    capture_filename)
    if not len(tcp_pkt_list):
        logger.info(f"TCP packets are not captured or one of the 4-way handshake pkts are not captured in the "
                    f"sniffer file")

        assert 0, (f"TCP packets are not captured or one of the 4-way handshake pkts are not captured in the "
                   f"sniffer file")
    conn_syn_pkt = 0
    conn_fin_pkt = 0
    bssid = bssid.lower()
    for count in tcp_pkt_list:
        if (count[1] == bssid) and ("Syn: Set" in count[0]):
            connection_est_time = float(count[2])
            conn_syn_pkt = 1
        if (count[1] == dut_mac_address) and ("Fin: Set" in count[0]):
            connection_close_time = float(count[2])
            conn_fin_pkt = 1

    assert conn_syn_pkt == 1, f"TCP SYN-PKT is not received from remote http client or pkt is not captured in sniffer"
    assert conn_fin_pkt == 1, f"TCP FYN-ACK-PKT is not sent by DUT or the pkt is not captured in sniffer"

    timediff = connection_close_time - connection_est_time
    logger.info(f"DUT is closing the tcp connection after {timediff} seconds when http get request is not received")
    delta = timediff - timeout
    assert (delta <= 5) and (delta >= -5), f"DUT is not closing the connection within time. Expected is {timeout}, But " \
                                           f"observed {timediff} "
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_http_server_handle_multiple_clients_TC19240(remote_socket_factory, wifi_sniffer, wifi_dut,
                                                          wifi_access_point, http_server,
                                                          http_client, logger):
    current_time = time.time()
    capture_filename = "test_wifi_http_server_handle_multiple_clients_TC19240"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    index_path = "/"
    method = "GET"
    server_port = 80
    count = 0
    client_socket = remote_socket_factory.interfaces.socket.create_socket()
    logger.info(f"Connecting from remote device to DUT socket {(device_ip, server_port)}")
    local_port = randint(5001, 65535)
    client_socket.connect_client_tcp(device_ip, server_port, client_port=local_port)

    try:
        logger.info(f"Sending http get request from third party client to DUT {count + 1} time")
        status, resp_content = http_client.interfaces.http.http_request(
            http_server.interfaces.http, method, index_path, server_ip=device_ip, timeout=20
        )
        logger.info(f"Length of DUTs  webpage {len(resp_content)} in iteration {count + 1}")
        logger.info(f"***************Contents of webpage on iteration {count + 1}------------->   {resp_content}\n\n\n"
                    f"*****")
        file_time_stamp = str(
            datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))

        webpage = "./reports/" + capture_filename + "webpage" + file_time_stamp + ".html"

        logger.info(f"webpage sent by DUT on iteration {count + 1} is {webpage}")
        with open(webpage, "w") as recv:
            recv.write(resp_content.decode())
    except:
        logger.info("DUT is not responding to second http get request initiated by remote device when first "
                    "http-request at DUT is pending, which is expected behavior")
    time.sleep(100)
    count = count + 1
    logger.info(f"Sending http get request from third party client to DUT {count + 1} time")
    status, resp_content = http_client.interfaces.http.http_request(
        http_server.interfaces.http, method, index_path, server_ip=device_ip, timeout=20
    )
    logger.info(f"Length of DUTs  webpage {len(resp_content)} in iteration {count + 1}")
    logger.info(f"***************Contents of webpage on iteration {count + 1}------------->   {resp_content}\n\n\n"
                f"*****")
    file_time_stamp = str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))

    webpage = "./reports/" + capture_filename + "webpage" + file_time_stamp + ".html"

    logger.info(f"webpage sent by DUT on iteration {count + 1} is {webpage}")
    with open(webpage, "w") as recv:
        recv.write(resp_content.decode())
    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.leave()
