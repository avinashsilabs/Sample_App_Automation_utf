import pytest
from test_wlan_max_psp_functionality import FilterPacket
from utf_wiseconnect.devices.rs911x import (RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap,
                                            RS9116CustomFeatureBitMap,
                                            RS9116ConfigFeatureBitMap,
                                            RS9116TCPIPFeatureBitMap,
                                            RS9116ExtCustomFeatureBitMap,
                                            RS9116ExtTCPIPFeatureBitMap,
                                            RS9116SecurityMode,
                                            RS9116OperatingMode,
                                            RS9116PowerSaveProcedureTypes,
                                            DeviceConstants,
                                            SocketType,
                                            SocketOptions, RS9116CertificateType,
                                            RS9116JoinFeatureBitMap,
                                            RS9116ULPModes
                                            )
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.iperf.iperf_utils import ping
from utf.utils.stopwatch import Stopwatch
import time
from random import randint
from threading import Thread
import threading
import string
import random
from utf.utils.time_measurer import TimeMeasurer
from utf.utils import mac_address_to_string
from utf.interfaces.switch import Switch
from utf.interfaces.wifi import WlanError

from test_wlan_powersave_ga_modified import tx_rx


def logger():
    return get_logger(__name__)

"""This function runs below test steps for DUT-RS9116
    Step1: 1. Configuration of DUT in 2G mode
    Step2 : Do Scan the AP
    Step3: Connect to the AP
    Step4 :Initiate the different powersave modes and check the connectivity 
    Step7 : Issue init,scan and connect to the AP
    Need to use separate .hex files for lp and ulp msb_based and gpio based cases.

    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC device)

    Author: swathi.pathuri
"""


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation
                    | RS9116FeatureBitMap.LPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.firmware_app("test_wlan_powersave_mode2_lp")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
def test_TCP_UDP_Tx_data_transfer_in_powersave_mode2_lp_C19488(firmware_loader, net_perf_client, wifi_sniffer,
                                                               wifi_access_point, wifi_dut,
                                                               wifi_client,
                                                               utf_constants, rs_helper):
    validation = True
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    capture_filename = "test_TCP_UDP_Tx_data_transfer_in_powersave_mode2_lp_C19488"
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")
    timeout = 100

    protocols = [IperfConstants.TCP, IperfConstants.UDP]
    for protocol in protocols:
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="TX")

    logger().info(f"Iperf data transfer completed successfully")

    logger().info("validate NULL data frame with PM bit set to 1")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.LPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.firmware_app("test_wlan_powersave_mode2_lp")
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
def test_TCP_UDP_Rx_data_transfer_in_powersave_mode2_lp_C19489(firmware_loader, net_perf_client, wifi_sniffer,
                                                               wifi_access_point, wifi_dut,
                                                               wifi_client,
                                                               rs_helper, utf_constants):
    validation = True
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    capture_filename = "test_TCP_UDP_Rx_data_transfer_in_powersave_mode2_lp_C19489"
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")
    timeout = 100
    protocols = [IperfConstants.TCP, IperfConstants.UDP]
    for protocol in protocols:
        rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="RX")
        time.sleep(5)

    logger().info(f"Iperf data transfer completed successfully")

    logger().info("validate NULL data frame with PM bit set to 1")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation
                    | RS9116FeatureBitMap.LPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
                              | RS9116ExtTCPIPFeatureBitMap.TCP_ACK_CORRECT,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.firmware_app("test_wlan_powersave_mode2_lp")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_sockets"])
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
@pytest.mark.parametrize("number_of_pkts", [500])
@pytest.mark.parametrize("test_run_time", [100])
@pytest.mark.skip("Getting FFD5 error while sending data")
def test_TCP_UDP_bidirectional_in_powersave_mode2_lp_TC19490(firmware_loader, wifi_sniffer, remote_socket, wifi_dut, wifi_access_point,
                                                             number_of_pkts, test_run_time,
                                                             rs_helper, utf_constants):

    validation = True
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')

    capture_filename = "test_TCP_UDP_bidirectional_in_powersave_mode2_lp_TC19490"
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    protocols = ["TCP", "UDP"]
    for protocol in protocols:
        data_size = 1460
        remote_socket.interfaces.socket.time_limit = 1800

        if protocol == "TCP":
            logger().info("Starting tcp server remotely at port number 5001")
            remote_socket.interfaces.socket.start_server()
            time.sleep(10)
            # DUT opens tcp client socket
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
            assert sock == 0, f"socket id received is wrong, expected is 0"
            logger().info(f"socket id received is {sock} which is expected")
            logger().info(
                f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                       SocketOptions.TCP_MAX_RETRY)
            local_port = randint(5001, 60000)
            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
            # tcp socket opened in DUT connects to the tcp server
            wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)
        else:
            logger().info("Starting udp socket remotely at port number 5001")
            remote_socket.interfaces.socket.start_server(socket_type=1)
            time.sleep(10)
            # Open UDP socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_udp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
            assert sock == 0, "socket id received is not matched. Expected is 0"
            logger().info(f"socket id received is {sock} which is expected")
            local_port = randint(5001, 60000)
            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        tx_rx_obj = tx_rx()
        if protocol == "TCP":
            th_start = Thread(target=tx_rx_obj.receive_data_socket,
                              args=(remote_socket, logger, number_of_pkts, data_size, 0), )
            th_start1 = Thread(target=tx_rx_obj.send_data, args=(remote_socket, logger, data_size, test_run_time, 0), )
        else:
            th_start = Thread(target=tx_rx_obj.receive_data_socket,
                              args=(remote_socket, logger, number_of_pkts, data_size, 1), )
            th_start1 = Thread(target=tx_rx_obj.send_data,
                               args=(remote_socket, logger, data_size, test_run_time, 1, device_ip, local_port), )

        th_start.start()
        th_start1.start()
        time.sleep(5)
        with TimeMeasurer() as t:
            if protocol == "TCP":
                bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts)
            else:
                server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
                server_port = remote_socket.interfaces.socket.server_port
                bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts,
                                                                     server_ip=server_ip, server_port=server_port)
        tx_time = t.duration
        logger().info(f"Number of bytes sent by dut {bytes_sent}")
        delta_time = 5
        time.sleep(test_run_time - tx_time + delta_time)
        th_start.join(5)
        th_start1.join(5)
        result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
        bytes_received = int(result.split(b":")[1])
        logger().info(f"bytes received on socket {sock} -> {bytes_received}")
        if protocol == "TCP":
            assert bytes_sent == tx_rx_obj.rcv_data, "Number of bytes sent by DUT and received on remote socket are not " \
                                                     "matched "
        else:
            packet_loss_tx = (((bytes_sent - tx_rx_obj.rcv_data) / bytes_sent) * 100)
            assert packet_loss_tx < 20, "Packet loss is not in tolerance level while DUT is sending data over UDP"

        packet_loss = (((tx_rx_obj.sent_data - bytes_received) / tx_rx_obj.sent_data) * 100)
        logger().info(f"Packet loss {packet_loss}")
        assert packet_loss < 20, "Packet loss is not in tolerance level while DUT receiving the data"

        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened tcp socket"
        remote_socket.interfaces.socket.stop()
        logger().info("Successfully closed opened socket in the DUT")
        time.sleep(5)
    logger().info("validate NULL data frame with PM bit set to '1'")
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    # Disconnect the AP
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit set to 1'




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.LPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
                              | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.firmware_app("test_wlan_powersave_mode2_lp")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '12345678',
                                               "dtim": 3, "beacon_interval": 100})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_Pwrmode_8_with_LP_C19502(firmware_loader, wifi_sniffer, wifi_dut, wifi_access_point,
                                   utf_constants, rs_helper):
    testcase = "test_Pwrmode_8_with_ULP_C19502"
    logger().info("configuring the Sniffer with the channel")
    capture_filename = testcase
    iter_count = utf_constants.get("iter_count")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    for i in range(0, iter_count):
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)

        time.sleep(120)

        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveDisabled)

        logger().info("Initiating scan from dut...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        assert (len(scan_results) >= 1), "Scan failed"
        logger().info(scan_results)
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation
        | RS9116FeatureBitMap.LPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.dut("rs9116")
@pytest.mark.wiseconnect_duts(["rs9116"])
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": "12345678"})
@pytest.mark.end_state("wifi_dut",
                      wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_power_mode_switching_after_assoc_lp_C19499(wifi_sniffer, wifi_access_point, wifi_dut, rs_helper, utf_constants):

        testcase = "test_power_mode_switching_after_assoc_lp_C19499"
        capture_filename = testcase
        validation = True
        iter_count = utf_constants.get("iter_count")
        ping_count = utf_constants.get("ping_count")
        time.sleep(5)

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {bssid}')

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                       power_save=False)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        logger().info("Disable wlan power save...")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveDisabled)

        logger().info("stopping the capture")
        # Stop Sniffer
        wifi_sniffer.interfaces.capture.stop_capture()

        # Validating the power management bit
        packet_filter1 = f' (wlan.fc.pwrmgt == 0) && ((wlan.fc.type_subtype == 0x0024)' \
                         f' && (wlan.sa == {dut_mac_address}) && (wlan.da == {bssid}))'

        # Validating the power management bit
        packet_filter2 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024)' \
                         f' && (wlan.sa == {dut_mac_address}) && (wlan.da == {bssid}))'

        for i in range(1, 4):

            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

            logger().info("start capturing with Sniffer by giving the test case name as filename")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
            time.sleep(5)

            logger().info("Setting DUT in wlan power save mode 1..")
            wifi_dut.interfaces.wifi.power_save(power_save_mode=f"{i}", ulp_mode=0)

            if i == 3:
                for j in range(0, 3):
                    try:
                        wifi_dut.interfaces.wifi.issue_ack()
                        break
                    except:
                        logger().info("Did not receive WKP msg ,Retrying for 3 times")
                        if j == 2:
                            raise

            time.sleep(30)

            logger().info("stopping the capture")
            # Stop Sniffer
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info(f"validating power save in sniffer with filter {packet_filter2}")

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                      packet_filter2)['packet_count'], \
                'Sniffer validation failed for NULL data frame with PM bit 1'

            logger().info("configuring the Sniffer with the channel")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

            logger().info("start capturing with Sniffer by giving the test case name as filename")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
            time.sleep(5)

            logger().info("Disable wlan power save...")
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveDisabled)
            time.sleep(30)

            logger().info("stopping the capture")
            # Stop Sniffer
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info(f"validating power save in sniffer with filter {packet_filter1}")

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                                      packet_filter1)['packet_count'], \
                'Sniffer validation failed for NULL data frame with PM bit 0'


