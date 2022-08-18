import pytest
import time
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116AsyncEventType, \
     RS9116ExtCustomFeatureBitMap, RS9116FeatureBitMap, RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap,  \
     RS9116CustomFeatureBitMap, RS9116CertificateType, RS9116ConfigFeatureBitMap, RS9116PowerSaveProcedureTypes
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth import BLEDeviceState
from utf.utils.iperf.iperf_utils import get_host_ip, ping

ping_count = 10

def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC)

    Author: Vishakha
"""

#Verify slave latency and connection stability when DUT as slave and initiate connection from remote device while STA associate to AP and do HTTP download
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index_long_lf.html"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_ble_slave_latency_C20122(http_server, wifi_sniffer, wifi_dut, wifi_access_point, ble_client, index_path, http_client):
    logger().info(f" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_sta_ble_slave_latency_C20122')
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    # Join Wi-Fi Access Point
    logger().info(f"connecting to access point.....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info(f"enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"enabling wifi power save mode in DUT......")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    logger().info(f"enabling bt power save mode in DUT......")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("fetching dut mac address....")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    # Initiate ping from third party wifi-client to DUT
    logger().info(f'DUT ip {device_ip}')
    logger().info(f"pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info(f"ping to DUT is successful....")

    #""" ******* SERVER CHECKS ******* """
    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat == True
    logger().info(f'http server state is {server_stat}')

    # This API gets the host ip for the http server
    logger().info(" fetching the host IP for http server")
    host_ip = get_host_ip()
    logger().info(f"host ip is {host_ip}")
    logger().info("pinging to server ip....")
    status = ping(host_ip, 10)
    assert status == 1, "unable to ping to server"

    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("fetching the data from server bt get method")
    status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http,index_path)
    status1, content1 = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

    assert status, "failed to fetch the http data"
    assert content, "failed to load the http data"

    logger().info(status)
    logger().info(content)
    assert content == content1, f"http send and receive content is not same"

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"Begin Scanning for BLE devices")
    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address, "Unable to get BLE client address"
    time.sleep(1)
    logger().info(f"Stop Scanning for BLE devices")
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(5)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,
                 bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}"):
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                               Connection_Handle="0x61 0x00",
                                                                               Connection_Interval_Min="0x06 0x00",
                                                                               Connection_Interval_Max="0x06 0x00",
                                                                               Max_Latency="0x05 0x00",
                                                                               Supervision_Timeout="0x90 0x01",
                                                                               Min_CE_Length="0x00 0x00",
                                                                               Max_CE_Length="0x00 0x00"
                                                                               )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")



#Verify slave latency and connection stability when DUT as slave and initiate connection from remote device while STA associate to AP and do HTTP download
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index_long_lf.html"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_ble_slave_latency_C20123(http_server, wifi_sniffer, wifi_dut, wifi_access_point, ble_client, index_path, http_client):
    logger().info(f" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_sta_ble_slave_latency_C20123')
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    # Join Wi-Fi Access Point
    logger().info(f"connecting to access point.....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info(f"enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"enabling wifi power save mode in DUT......")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    logger().info(f"enabling bt power save mode in DUT......")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("fetching dut mac address....")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    # Initiate ping from third party wifi-client to DUT
    logger().info(f'DUT ip {device_ip}')
    logger().info(f"pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info(f"ping to DUT is successful....")

    #""" ******* SERVER CHECKS ******* """
    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat == True
    logger().info(f'http server state is {server_stat}')

    # This API gets the host ip for the http server
    logger().info(" fetching the host IP for http server")
    host_ip = get_host_ip()
    logger().info(f"host ip is {host_ip}")
    logger().info("pinging to server ip....")
    status = ping(host_ip, 10)
    assert status == 1, "unable to ping to server"

    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("fetching the data from server bt get method")
    status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http,index_path)
    status1, content1 = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

    assert status, "failed to fetch the http data"
    assert content, "failed to load the http data"

    logger().info(status)
    logger().info(content)
    assert content == content1, f"http send and receive content is not same"

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"Begin Scanning for BLE devices")
    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address, "Unable to get BLE client address"
    time.sleep(1)
    logger().info(f"Stop Scanning for BLE devices")
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(5)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,
                 bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}"):
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                               Connection_Handle="0x61 0x00",
                                                                               Connection_Interval_Min="0x0C 0x00",
                                                                               Connection_Interval_Max="0x0C 0x00",
                                                                               Max_Latency="0x05 0x00",
                                                                               Supervision_Timeout="0x90 0x01",
                                                                               Min_CE_Length="0x00 0x00",
                                                                               Max_CE_Length="0x00 0x00"
                                                                               )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")




#Verify slave latency and connection stability when DUT as slave and initiate connection from remote device while STA associate to AP and do HTTP download
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index_long_lf.html"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_ble_slave_latency_C20124(http_server, wifi_sniffer, wifi_dut, wifi_access_point, ble_client, index_path, http_client):
    logger().info(f" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_sta_ble_slave_latency_C20124')
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    # Join Wi-Fi Access Point
    logger().info(f"connecting to access point.....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info(f"enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"enabling wifi power save mode in DUT......")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    logger().info(f"enabling bt power save mode in DUT......")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("fetching dut mac address....")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    # Initiate ping from third party wifi-client to DUT
    logger().info(f'DUT ip {device_ip}')
    logger().info(f"pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info(f"ping to DUT is successful....")

    #""" ******* SERVER CHECKS ******* """
    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat == True
    logger().info(f'http server state is {server_stat}')

    # This API gets the host ip for the http server
    logger().info(" fetching the host IP for http server")
    host_ip = get_host_ip()
    logger().info(f"host ip is {host_ip}")
    logger().info("pinging to server ip....")
    status = ping(host_ip, 10)
    assert status == 1, "unable to ping to server"

    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("fetching the data from server bt get method")
    status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http,index_path)
    status1, content1 = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

    assert status, "failed to fetch the http data"
    assert content, "failed to load the http data"

    logger().info(status)
    logger().info(content)
    assert content == content1, f"http send and receive content is not same"

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"Begin Scanning for BLE devices")
    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address, "Unable to get BLE client address"
    time.sleep(1)
    logger().info(f"Stop Scanning for BLE devices")
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(5)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,
                 bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}"):
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                               Connection_Handle="0x61 0x00",
                                                                               Connection_Interval_Min="0x80 0x0C",
                                                                               Connection_Interval_Max="0x80 0x0C",
                                                                               Max_Latency="0x02 0x00",
                                                                               Supervision_Timeout="0x80 0x0C",
                                                                               Min_CE_Length="0x00 0x00",
                                                                               Max_CE_Length="0x00 0x00"
                                                                               )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")



#Verify slave latency and connection stability when DUT as slave and initiate connection from remote device while STA associate to AP and do HTTP download
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index_long_lf.html"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_ble_slave_latency_C20125(http_server, wifi_sniffer, wifi_dut, wifi_access_point, ble_client, index_path, http_client):
    logger().info(f" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_sta_ble_slave_latency_C20125')
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    # Join Wi-Fi Access Point
    logger().info(f"connecting to access point.....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info(f"enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"enabling wifi power save mode in DUT......")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    logger().info(f"enabling bt power save mode in DUT......")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("fetching dut mac address....")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    # Initiate ping from third party wifi-client to DUT
    logger().info(f'DUT ip {device_ip}')
    logger().info(f"pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info(f"ping to DUT is successful....")

    #""" ******* SERVER CHECKS ******* """
    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat == True
    logger().info(f'http server state is {server_stat}')

    # This API gets the host ip for the http server
    logger().info(" fetching the host IP for http server")
    host_ip = get_host_ip()
    logger().info(f"host ip is {host_ip}")
    logger().info("pinging to server ip....")
    status = ping(host_ip, 10)
    assert status == 1, "unable to ping to server"

    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("fetching the data from server bt get method")
    status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http,index_path)
    status1, content1 = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

    assert status, "failed to fetch the http data"
    assert content, "failed to load the http data"

    logger().info(status)
    logger().info(content)
    assert content == content1, f"http send and receive content is not same"

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"Begin Scanning for BLE devices")
    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address, "Unable to get BLE client address"
    time.sleep(1)
    logger().info(f"Stop Scanning for BLE devices")
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(5)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,
                 bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}"):
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                               Connection_Handle="0x61 0x00",
                                                                               Connection_Interval_Min="0x06 0x00",
                                                                               Connection_Interval_Max="0x06 0x00",
                                                                               Max_Latency="0x00 0x00",
                                                                               Supervision_Timeout="0x90 0x01",
                                                                               Min_CE_Length="0x00 0x00",
                                                                               Max_CE_Length="0x00 0x00"
                                                                               )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")



#Verify slave latency and connection stability when DUT as slave and initiate connection from remote device while STA associate to AP and do HTTP download
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index_long_lf.html"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_ble_slave_latency_C20126(http_server, wifi_sniffer, wifi_dut, wifi_access_point, ble_client, index_path, http_client):
    logger().info(f" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_sta_ble_slave_latency_C20126')
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    # Join Wi-Fi Access Point
    logger().info(f"connecting to access point.....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info(f"enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"enabling wifi power save mode in DUT......")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    logger().info(f"enabling bt power save mode in DUT......")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("fetching dut mac address....")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    # Initiate ping from third party wifi-client to DUT
    logger().info(f'DUT ip {device_ip}')
    logger().info(f"pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info(f"ping to DUT is successful....")

    #""" ******* SERVER CHECKS ******* """
    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat == True
    logger().info(f'http server state is {server_stat}')

    # This API gets the host ip for the http server
    logger().info(" fetching the host IP for http server")
    host_ip = get_host_ip()
    logger().info(f"host ip is {host_ip}")
    logger().info("pinging to server ip....")
    status = ping(host_ip, 10)
    assert status == 1, "unable to ping to server"

    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("fetching the data from server bt get method")
    status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http,index_path)
    status1, content1 = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

    assert status, "failed to fetch the http data"
    assert content, "failed to load the http data"

    logger().info(status)
    logger().info(content)
    assert content == content1, f"http send and receive content is not same"

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info(f"Begin Scanning for BLE devices")
    logger().info("Executing lescan in raspi")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address, "Unable to get BLE client address"
    time.sleep(1)
    logger().info(f"Stop Scanning for BLE devices")
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating BLE connection")
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    logger().info("BLE Connection success")
    time.sleep(5)

    # setting data length on ble_client
    with BleLogs(start_collecting_logs=True,
                 bt_log_path=f"reports/test_ble_anchorpoints.log_{int(time.time())}"):
        logger().info("Updating ble connection with connection parameters")
        ble_client.interfaces.bluetooth.hci_tool_manager.ble_update_connection(dev_addr=ble_dut_address,
                                                                               Connection_Handle="0x61 0x00",
                                                                               Connection_Interval_Min="0x80 0x0C",
                                                                               Connection_Interval_Max="0x80 0x0C",
                                                                               Max_Latency="0x00 0x00",
                                                                               Supervision_Timeout="0x80 0x0C",
                                                                               Min_CE_Length="0x00 0x00",
                                                                               Max_CE_Length="0x00 0x00"
                                                                               )
    # BLE SNIFFER VALIDATION SUPPORT NEEDED WAITING FOR 5 MINS FOR CHECKING BLE CONNECTION STABILITY
    time.sleep(300)
    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")

    logger().info("Disconnect BLE connection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("BLE diconnect successful")
