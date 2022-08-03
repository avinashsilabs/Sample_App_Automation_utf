# Test author: Vinod.G
# Test suite: TCP/UDP test suite
import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, DeviceConstants, \
    RS9116AsyncEventType, SocketOptions, RS9116PowerSaveProcedureTypes, RS9116CustomFeatureBitMap
from utf.utils.subprocess_manager import SubprocessManager
from threading import Thread
import time
from random import randint
from utf.utils.iperf.iperf_utils import ping

"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Create a new TCP/IP socket 
        5. Bind the socket with DUT ip address
        6. Connect the client with server socket as specified port number.
        7. Send and receive the data over the socket. Verify the data integrity and packet loss checks.
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.FTPClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,

        }
    )
]


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


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# The test case checks tcp close functionality
def test_ftp_TC19004(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client, ftp_server, logger):
    capture_filename = "test_ftp_TC19004"
    join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info("Starting tcp server remotely at port number 5001")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger.info(f"host ip address is {host_ip}")
    wifi_dut.interfaces.wifi.connect_to_ftp_server(flags=4, server_ip=host_ip, username="ftpuser", password="ftpuser",
                                                   server_port=21)
    # wifi_dut.interfaces.wifi.set_ftp_mode()
    wifi_dut.interfaces.wifi.query_directory_list()
    time.sleep(10)
    events = wifi_dut.interfaces.wifi.get_async_events()
    for event in events:
        if event.event_type == RS9116AsyncEventType.FTP_DIR_READ:
            remote_terminate = event.event_data
        else:
            assert 1, f"dir read not received"
    wifi_dut.interfaces.wifi.create_directory("/ftp_test")
    wifi_dut.interfaces.wifi.set_directory("/ftp_test")
    wifi_dut.interfaces.wifi.ftp_file_create()
    wifi_dut.interfaces.wifi.ftp_file_write()
    wifi_dut.interfaces.wifi.ftp_file_rename()
    wifi_dut.interfaces.wifi.ftp_file_read()
    time.sleep(20)
    for event in events:
        if event.event_type == RS9116AsyncEventType.FTP_FILE_READ:
            remote_terminate = event.event_data
        else:
            assert 1, f"file read not received"
    wifi_dut.interfaces.wifi.create_directory("work")
    wifi_dut.interfaces.wifi.ftp_directory_delete()
    wifi_dut.interfaces.wifi.ftp_disconnect()
