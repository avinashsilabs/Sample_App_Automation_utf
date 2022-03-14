import pytest
from utf_wiseconnect.devices.rs911x import (RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap,
                            RS9116CustomFeatureBitMap,
                            RS9116ConfigFeatureBitMap,
                            RS9116TCPIPFeatureBitMap,
                            RS9116ExtCustomFeatureBitMap,
                            RS9116ExtTCPIPFeatureBitMap,
                            RS9116SecurityMode,
                            RS9116OperatingMode, RS9116ULPModes
                            )
from utf.interfaces import wifi
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants,IperfTrafficType
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.iperf.iperf_utils import ping
import time

def logger():
    return get_logger(__name__)

""" Author: Sirisha Ayyagari
This test plan aims to connect the WIFI AP in different Powersave modes
setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
Step1: 1. Configuration of DUT in 2G mode
Step2 : Do Scan the AP
Step3: Connect to the AP
Step4 :Initiate the different powersave modes and check the connectivity 
Step7 : Issue init,scan and connect to the AP
Need to use separate .hex files for lp and ulp msb_based and gpio based until we get updated one from Vinod
"""

# @pytest.mark.config(
#         "wifi_dut",
#         wifi=
#         {
#             "oper_mode": 0,
#             "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#             "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#             "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#             "band": 0
#         }
#     )
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
# @pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# def test_connect_and_disconnect_when_module_is_in_power_save_mode_C3990(wifi_dut, wifi_access_point, wifi_sniffer):
#     validation = True
#     packet_filter2 = False
#     logger().info("********** configuring the sniffer with access point channel **********")
#     wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
#     logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
#     wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C3990')
#     logger().info(f"Fetches the DUT mac address")
#     dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
#     logger().info(f"Device mac address: {dut_mac_address}")
#     bssid = wifi_access_point.interfaces.wifi.bssid
#     logger().info(f'AP BSSID = {bssid}')
#     # Scan for the AP's
#     result= wifi_dut.interfaces.wifi.scan()
      assert result is not None, "No AP Found"
#     logger().info(f"*****Enable Enhanced Max Power save in DUT******")
#         # Initiating power save
#     wifi_dut.interfaces.wifi.power_save(2, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#             power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
#         )
#     time.sleep(30)
#     # Add disconnect
#     wifi_dut.interfaces.wifi.leave()
#     time.sleep(5)
#         # scan the AP
#     wifi_dut.interfaces.wifi.scan(ssid=None)
#         # Connect to the AP
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#
#     # validate NULL data frame with PM bit set to '1'
#     packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
#                          f'and (wlan.da == {bssid}))'
#     logger().info("Stop Sniffer finally")
#     wifi_sniffer.interfaces.capture.stop_capture()
#     logger().info('Validation for NULL packet with pm bit 1')
#
#
# @pytest.mark.config(
#          "wifi_dut",
#         wifi=
#          {
#              "oper_mode": 0,
#              "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#              "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#              "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#              "band": 0,
#              "beacon_interval": 1000
#          }
#      )
# @pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
# @pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
# def test_TCP_UDP_Rx_data_transfer_in_powersave_mode1_C3991(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
#     # scan the AP
#     wifi_dut.interfaces.wifi.scan()
#     # Connect to the AP
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#
#     # preparing wifi_dut
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     ip_config = wifi_dut.interfaces.wifi.start_ip()
#     device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
#     # Initiating power save1
#     wifi_dut.interfaces.wifi.power_save(1, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#         power_save_mode=RS9116PowerSaveModes.PowerSaveMode1
#     )
#
#     # preparing iperf
#     host_ip = wifi_client.interfaces.wifi.get_ip_address()
#     net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
#
#     # creating results object for sharing between host and dut
#     result = Result(net_perf_client.interfaces.net_perf.protocol)
#
#     # open socket and start listening
#     with wifi_dut.interfaces.wifi.start_socket_reader(
#             log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
#             result=result,
#             protocol=net_perf_client.interfaces.net_perf.protocol,
#             port=net_perf_client.interfaces.net_perf.client_port,
#             device_ip=device_ip,
#             data_len=net_perf_client.interfaces.net_perf.client_data_len,
#             time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
#
#         # start iperf
#         net_perf_client.interfaces.net_perf.start()
#         # capture device output
#         wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
#
#     # get and print throughput
#     tp = net_perf_client.interfaces.net_perf.process_output(result)
#     assert tp is not None
#
#
# @pytest.mark.config(
#         "wifi_dut",
#         wifi=
#          {
#              "oper_mode": 0,
#              "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#              "features": RS9116FeatureBitMap.LPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#              "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#              "band": 0,
#              "beacon_interval": 1000
#          }
#      )
# @pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
# @pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
# def test_TCP_UDP_Tx_data_transfer_in_powersave_mode2_C3993(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
#     # scan the AP
#     wifi_dut.interfaces.wifi.scan()
#     # Connect to the AP
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     # preparing wifi_dut
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     ip_config = wifi_dut.interfaces.wifi.start_ip()
#     device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
#     # Initiating power save2
#     wifi_dut.interfaces.wifi.power_save(2, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#         power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
#     )
#     # preparing iperf
#     host_ip = wifi_client.interfaces.wifi.get_ip_address()
#     net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
#     # creating results object for sharing between host and dut
#     result = Result(net_perf_client.interfaces.net_perf.protocol)
#     # open socket and start listening
#     with wifi_dut.interfaces.wifi.start_socket_reader(
#             log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
#             result=result,
#             protocol=net_perf_client.interfaces.net_perf.protocol,
#             port=net_perf_client.interfaces.net_perf.client_port,
#             device_ip=device_ip,
#             data_len=net_perf_client.interfaces.net_perf.client_data_len,
#             time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
#         # start iperf
#         net_perf_client.interfaces.net_perf.start()
#         # capture device output
#         wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
#     # get and print throughput
#     tp = net_perf_client.interfaces.net_perf.process_output(result)
#     assert tp is not None
#
#
#
# @pytest.mark.config(
#          "wifi_dut",
#         wifi=
#          {
#              "oper_mode": 0,
#              "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#              "features": RS9116FeatureBitMap.LPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#              "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#              "band": 0,
#              "beacon_interval": 1000
#          }
#      )
# @pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
# @pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
# def test_TCP_UDP_Rx_data_transfer_in_powersave_mode2_C3994(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
#     # scan the AP
#     wifi_dut.interfaces.wifi.scan()
#     # Connect to the AP
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     # preparing wifi_dut
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     ip_config = wifi_dut.interfaces.wifi.start_ip()
#     device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
#     # Initiating power save2
#     wifi_dut.interfaces.wifi.power_save(2, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#         power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
#     )
#     # preparing iperf
#     host_ip = wifi_client.interfaces.wifi.get_ip_address()
#     net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
#     # creating results object for sharing between host and dut
#     result = Result(net_perf_client.interfaces.net_perf.protocol)
#     # open socket and start listening
#     with wifi_dut.interfaces.wifi.start_socket_reader(
#             log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
#             result=result,
#             protocol=net_perf_client.interfaces.net_perf.protocol,
#             port=net_perf_client.interfaces.net_perf.client_port,
#             device_ip=device_ip,
#             data_len=net_perf_client.interfaces.net_perf.client_data_len,
#             time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
#         # start iperf
#         net_perf_client.interfaces.net_perf.start()
#         # capture device output
#         wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
#
#     # get and print throughput
#     tp = net_perf_client.interfaces.net_perf.process_output(result)
#     assert tp is not None
#
#
# @pytest.mark.config(
#          "wifi_dut",
#         wifi=
#          {
#              "oper_mode": 0,
#              "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#              "features": RS9116FeatureBitMap.LPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#              "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#              "band": 0,
#              "beacon_interval": 1000
#          }
#      )
# @pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
# @pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
# def test_TCP_UDP_Tx_data_transfer_in_powersave_mode3_C3996(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
#     # scan the AP
#     wifi_dut.interfaces.wifi.scan()
#     # Connect to the AP
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     # preparing wifi_dut
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     ip_config = wifi_dut.interfaces.wifi.start_ip()
#     device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
#     # Initiating power save3
#     wifi_dut.interfaces.wifi.power_save(3, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#         power_save_mode=RS9116PowerSaveModes.PowerSaveMode3
#     )
#     # preparing iperf
#     host_ip = wifi_client.interfaces.wifi.get_ip_address()
#     net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
#     # creating results object for sharing between host and dut
#     result = Result(net_perf_client.interfaces.net_perf.protocol)
#     # open socket and start listening
#     with wifi_dut.interfaces.wifi.start_socket_reader(
#             log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
#             result=result,
#             protocol=net_perf_client.interfaces.net_perf.protocol,
#             port=net_perf_client.interfaces.net_perf.client_port,
#             device_ip=device_ip,
#             data_len=net_perf_client.interfaces.net_perf.client_data_len,
#             time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
#         # start iperf
#         net_perf_client.interfaces.net_perf.start()
#         # capture device output
#         wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
#     # get and print throughput
#     tp = net_perf_client.interfaces.net_perf.process_output(result)
#     assert tp is not None
#
#
#
# @pytest.mark.config(
#          "wifi_dut",
#         wifi=
#          {
#              "oper_mode": 0,
#              "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#              "features": RS9116FeatureBitMap.LPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#              "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#              "band": 0,
#              "beacon_interval": 1000
#          }
#      )
# @pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
# @pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
# def test_TCP_UDP_Rx_data_transfer_in_powersave_mode3_C3997(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
#    #scan the AP
#     wifi_dut.interfaces.wifi.scan()
#     # Connect to the AP
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     # preparing wifi_dut
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     ip_config = wifi_dut.interfaces.wifi.start_ip()
#     device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
#     # Initiating power save3
#     wifi_dut.interfaces.wifi.power_save(3, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#         power_save_mode=RS9116PowerSaveModes.PowerSaveMode3
#     )
#     # preparing iperf
#     host_ip = wifi_client.interfaces.wifi.get_ip_address()
#     net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
#     # creating results object for sharing between host and dut
#     result = Result(net_perf_client.interfaces.net_perf.protocol)
#     # open socket and start listening
#     with wifi_dut.interfaces.wifi.start_socket_reader(
#             log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
#             result=result,
#             protocol=net_perf_client.interfaces.net_perf.protocol,
#             port=net_perf_client.interfaces.net_perf.client_port,
#             device_ip=device_ip,
#             data_len=net_perf_client.interfaces.net_perf.client_data_len,
#             time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
#         # start iperf
#         net_perf_client.interfaces.net_perf.start()
#         # capture device output
#         wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
#
#     # get and print throughput
#     tp = net_perf_client.interfaces.net_perf.process_output(result)
#     assert tp is not None
#
#
#
# @pytest.mark.config(
#          "wifi_dut",
#         wifi=
#          {
#              "oper_mode": 0,
#              "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#              "features": RS9116FeatureBitMap.LPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#              "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#              "band": 0,
#              "beacon_interval": 1000
#          }
#      )
# @pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
# @pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
# def test_TCP_UDP_Tx_data_transfer_in_powersave_mode3_C4000(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
#     # scan the AP
#     wifi_dut.interfaces.wifi.scan()
#     # Connect to the AP
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     # preparing wifi_dut
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     ip_config = wifi_dut.interfaces.wifi.start_ip()
#     device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
#     # Initiating power save3
#     wifi_dut.interfaces.wifi.power_save(3, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#         power_save_mode=RS9116PowerSaveModes.PowerSaveMode3
#     )
#     # preparing iperf
#     host_ip = wifi_client.interfaces.wifi.get_ip_address()
#     net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
#     # creating results object for sharing between host and dut
#     result = Result(net_perf_client.interfaces.net_perf.protocol)
#     # open socket and start listening
#     with wifi_dut.interfaces.wifi.start_socket_reader(
#             log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
#             result=result,
#             protocol=net_perf_client.interfaces.net_perf.protocol,
#             port=net_perf_client.interfaces.net_perf.client_port,
#             device_ip=device_ip,
#             data_len=net_perf_client.interfaces.net_perf.client_data_len,
#             time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
#         # start iperf
#         net_perf_client.interfaces.net_perf.start()
#         # capture device output
#         wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
#     # get and print throughput
#     tp = net_perf_client.interfaces.net_perf.process_output(result)
#     assert tp is not None
#
#
#
#
# pytest.mark.config(
#          "wifi_dut",
#         wifi=
#          {
#              "oper_mode": 0,
#              "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#              "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#              "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#              "band": 0,
#              "beacon_interval": 1000
#          }
#      )
# @pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
# @pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
# def test_TCP_UDP_Rx_data_transfer_in_powersave_mode3_C4001(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
#     # scan the AP
#     wifi_dut.interfaces.wifi.scan()
#     # Connect to the AP
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     # preparing wifi_dut
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     ip_config = wifi_dut.interfaces.wifi.start_ip()
#     device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
#     # Initiating power save3
#     wifi_dut.interfaces.wifi.power_save(3, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#         power_save_mode=RS9116PowerSaveModes.PowerSaveMode3
#     )
#     # preparing iperf
#     host_ip = wifi_client.interfaces.wifi.get_ip_address()
#     net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
#     # creating results object for sharing between host and dut
#     result = Result(net_perf_client.interfaces.net_perf.protocol)
#     # open socket and start listening
#     with wifi_dut.interfaces.wifi.start_socket_reader(
#             log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
#             result=result,
#             protocol=net_perf_client.interfaces.net_perf.protocol,
#             port=net_perf_client.interfaces.net_perf.client_port,
#             device_ip=device_ip,
#             data_len=net_perf_client.interfaces.net_perf.client_data_len,
#             time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
#         # start iperf
#         net_perf_client.interfaces.net_perf.start()
#         # capture device output
#         wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
#
#     # get and print throughput
#     tp = net_perf_client.interfaces.net_perf.process_output(result)
#     assert tp is not None
#
#
#
#
# @pytest.mark.config(
#         "wifi_dut",
#         wifi=
#         {
#             "oper_mode": 0,
#             "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#             "features": RS9116FeatureBitMap.LPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#             "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#             "band": 1
#
#         }
#     )
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
# @pytest.mark.start_state(wifi=['init'])
# @pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# def test_Power_save_mode_8_with_LP_mode_C4007(wifi_dut, wifi_access_point, wifi_sniffer):
#     validation = True
#     packet_filter2 = False
#     logger().info("********** configuring the sniffer with access point channel **********")
#     wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
#     logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
#     wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Powersave8_LP_C4007')
#     logger().info(f"Fetches the DUT mac address")
#     dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
#     logger().info(f"Device mac address: {dut_mac_address}")
#     bssid = wifi_access_point.interfaces.wifi.bssid
#     logger().info(f"*****Enable Powersave mode8 in LP mode in DUT******")
#         # Initiating power save
#     wifi_dut.interfaces.wifi.power_save(8, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#             power_save_mode=RS9116PowerSaveModes.PowerSaveMode8
#         )
#     time.sleep(120)
#          #scan the AP
#     wifi_dut.interfaces.wifi.scan()
#         #Initiate powersave mode8
#     wifi_dut.interfaces.wifi.power_save(8, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#         power_save_mode=RS9116PowerSaveModes.PowerSaveMode8
#     )
#     packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
#                          f'and (wlan.da == {bssid}))'
#     wifi_sniffer.interfaces.capture.stop_capture()
#     logger().info("Stop Sniffer finally")
#
#
# @pytest.mark.config(
#         "wifi_dut",
#         wifi=
#         {
#             "oper_mode": 0,
#             "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#             "features": RS9116FeatureBitMap.ULPGPIOHandshake| RS9116FeatureBitMap.Aggregation,
#             "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#             "band": 1
#         }
#     )
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
# @pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# def test_Power_save_mode_8_with_ULP_mode_C4009(wifi_sniffer, wifi_dut, wifi_access_point):
#         validation = True
#         packet_filter2 = False
#         logger().info("********** configuring the sniffer with access point channel **********")
#         wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
#         logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
#         wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Powersave8_ULP_C4009')
#         logger().info(f"Fetches the DUT mac address")
#         dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
#         logger().info(f"Device mac address: {dut_mac_address}")
#         bssid = wifi_access_point.interfaces.wifi.bssid
#         logger().info(f"*****Enable Powersave mode8 in ULP mode in DUT******")
#         # Initiating power save
#         wifi_dut.interfaces.wifi.power_save(8, 0)
#         wifi_dut.interfaces.wifi.bt_power_save(
#             power_save_mode=RS9116PowerSaveModes.PowerSaveMode8
#         )
#         time.sleep(120)
#          #scan the Ap
#         wifi_dut.interfaces.wifi.scan()
#         #Initiate powersave mode8
#         wifi_dut.interfaces.wifi.power_save(8, 0)
#         packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
#                          f'and (wlan.da == {bssid}))'
#         wifi_sniffer.interfaces.capture.stop_capture()
#         logger().info("Stop Sniffer finally")
#
# @pytest.mark.config(
#         "wifi_dut",
#         wifi=
#         {
#             "oper_mode": 0,
#             "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#             "features": RS9116FeatureBitMap.LPGPIOHandshake| RS9116FeatureBitMap.Aggregation,
#             "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#             #"custom_features": RS9116CustomFeatureBitMap.Default,
#             "band": 1
#         }
#     )
#
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
# @pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# def test_Power_save_mode_9_with_LP_mode_C4008(wifi_sniffer, wifi_dut, wifi_access_point):
#         validation = True
#         packet_filter2 = False
#         logger().info("********** configuring the sniffer with access point channel **********")
#         wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
#         logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
#         wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Powersave9_LP_C4007')
#         logger().info(f"Fetches the DUT mac address")
#         dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
#         logger().info(f"Device mac address: {dut_mac_address}")
#         bssid = wifi_access_point.interfaces.wifi.bssid
#          # init
#          wifi_dut.interfaces.wifi.init()
#          logger().info(f"*****Enable Powersave mode9 in LP mode in DUT******")
#          # Initiating power save
#          wifi_dut.interfaces.wifi.power_save(9, 0)
#          wifi_dut.interfaces.wifi.bt_power_save(
#              power_save_mode=RS9116PowerSaveModes.PowerSaveMode9
#          )
#          # Send ACK
#          wifi_dut.interfaces.wifi.send_ack(timeout=3)
#          # scan the AP
#          wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
#          time.sleep(10)
#          # init
#          wifi_dut.interfaces.wifi.init()
#          time.sleep(10)
#          # Initiating power save
#          wifi_dut.interfaces.wifi.power_save(9, 0)
#          # Send ACK
#          wifi_dut.interfaces.wifi.send_ack(timeout=10)
#          # scan the AP
#          wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
#          packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
#                          f'and (wlan.da == {bssid}))'
#          wifi_sniffer.interfaces.capture.stop_capture()
#          logger().info("Stop Sniffer finally")
#

# @pytest.mark.config(
#         "wifi_dut",
#         wifi=
#         {
#             "oper_mode": 0,
#             "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#             "features": RS9116FeatureBitMap.ULPGPIOHandshake| RS9116FeatureBitMap.Aggregation,
#             "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#             "band": 1
#         }
#     )
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
# @pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
#def test_power_save_mode_9_with_ULP_mode_C4010(wifi_sniffer, wifi_dut, wifi_access_point):
#         validation = True
#         packet_filter2 = False
#         logger().info("********** configuring the sniffer with access point channel **********")
#         wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
#         logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
#         wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Powersave9_ULP_C4007')
#         logger().info(f"Fetches the DUT mac address")
#         dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
#         logger().info(f"Device mac address: {dut_mac_address}")
#         bssid = wifi_access_point.interfaces.wifi.bssid
#          # init
#          wifi_dut.interfaces.wifi.init()
#          logger().info(f"*****Enable Powersave9 in ULP mode in  DUT******")
#          # Initiating power save
#          wifi_dut.interfaces.wifi.power_save(9, 0)
#          wifi_dut.interfaces.wifi.bt_power_save(
#              power_save_mode=RS9116PowerSaveModes.PowerSaveMode9
#          )
#          # Send ACK
#          wifi_dut.interfaces.wifi.send_ack(timeout=3)
#          # scan the Ap
#          wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
#
#          time.sleep(10)
#          # init
#          wifi_dut.interfaces.wifi.init()
#          time.sleep(10)
#          # Initiating power save
#          wifi_dut.interfaces.wifi.power_save(9, 0)
#          # Send ACK
#          wifi_dut.interfaces.wifi.send_ack(timeout=10)
#          # scan the Ap
#          wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
#          packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
#                          f'and (wlan.da == {bssid}))'
#          wifi_sniffer.interfaces.capture.stop_capture()
#          logger().info("Stop Sniffer finally")

#
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": 0,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#         "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
#         "band": 0
#     }
# )
#
# def test_powersave_mode_switching_before_association_case1_C4005(wifi_dut, wifi_access_point, wifi_sniffer):
#     validation = True
#     logger().info("********** configuring the sniffer with access point channel **********")
#     wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
#     logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
#     wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case1_C4005.txt')
#     logger().info(f"Fetches the DUT mac address")
#     dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
#     logger().info(f"Device mac address: {dut_mac_address}")
#     bssid = wifi_access_point.interfaces.wifi.bssid
#           #Initiating powersave mode8
#     wifi_dut.interfaces.wifi.power_save(8, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#             power_save_mode=RS9116PowerSaveModes.PowerSaveMode8
#
#     )
#         # Disable powersave mode
#     wifi_dut.interfaces.wifi.power_save(0, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#             power_save_mode=RS9116PowerSaveModes.PowerSaveDisabled
#
#     )
#         # scan the AP
#     wifi_dut.interfaces.wifi.scan()
#     wifi_sniffer.interfaces.capture.stop_capture()
#     # validate NULL data frame with PM bit set to '1'
#     packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
#                          f'and (wlan.da == {bssid}))'
#     assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
#     wifi_sniffer.interfaces.capture.stop_capture()
#     logger().info("Stop Sniffer finally")


# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": 0,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#         "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.ULPGPIOHandshake,
#         "band": 0
#     }
# )
# def test_powersave_mode_switching_before_association_case2_C4005(wifi_dut, wifi_access_point, wifi_sniffer):
#     validation = True
#     logger().info("********** configuring the sniffer with access point channel **********")
#     wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
#     logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
#     wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case2_C4005.txt')
#     logger().info(f"Fetches the DUT mac address")
#     dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
#     logger().info(f"Device mac address: {dut_mac_address}")
#     bssid = wifi_access_point.interfaces.wifi.bssid
#         #Initiating powersave mode9
#     wifi_dut.interfaces.wifi.power_save(9, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#             power_save_mode=RS9116PowerSaveModes.PowerSaveMode9
#
#     )
#     # Disable powersave mode
#     wifi_dut.interfaces.wifi.power_save(0, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#             power_save_mode=RS9116PowerSaveModes.PowerSaveDisabled
#
#     )
#     # scan the AP
#     wifi_dut.interfaces.wifi.scan()
#     wifi_sniffer.interfaces.capture.stop_capture()
#     # validate NULL data frame with PM bit set to '1'
#     packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
#                          f'and (wlan.da == {bssid}))'
#     assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
#     wifi_sniffer.interfaces.capture.stop_capture()
#     logger().info("Stop Sniffer finally")


# def __print_throughput(self, iperf_throughput: dict):
#     if iperf_throughput is not None:
#         print_dict("##     ", iperf_throughput)

# @pytest.mark.config(
#          "wifi_dut",
#         wifi=
#          {
#              "oper_mode": 0,
#              "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#              "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#              "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#              "band": 0,
#              "beacon_interval": 1000
#          }
#      )
# @pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
# @pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
# def test_TCP_UDP_Rx_data_transfer_in_powersave_mode1_C3991(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
#     # scan the AP
#     wifi_dut.interfaces.wifi.scan()
#     # Connect to the AP
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#
#     # preparing wifi_dut
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     ip_config = wifi_dut.interfaces.wifi.start_ip()
#     device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
#     # Initiating power save1
#     wifi_dut.interfaces.wifi.power_save(1, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#         power_save_mode=RS9116PowerSaveModes.PowerSaveMode1
#     )
#
#     # preparing iperf
#     host_ip = wifi_client.interfaces.wifi.get_ip_address()
#     net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
#
#     # creating results object for sharing between host and dut
#     result = Result(net_perf_client.interfaces.net_perf.protocol)
#
#     # open socket and start listening
#     with wifi_dut.interfaces.wifi.start_socket_reader(
#             log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
#             result=result,
#             protocol=net_perf_client.interfaces.net_perf.protocol,
#             port=net_perf_client.interfaces.net_perf.client_port,
#             device_ip=device_ip,
#             data_len=net_perf_client.interfaces.net_perf.client_data_len,
#             time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
#
#         # start iperf
#         net_perf_client.interfaces.net_perf.start()
#         # capture device output
#         wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
#
#     # get and print throughput
#     tp = net_perf_client.interfaces.net_perf.process_output(result)
#     assert tp is not None
#     # __print_throughput(tp)
#
# @pytest.mark.config(
#         "wifi_dut",
#         wifi=
#          {
#              "oper_mode": 0,
#              "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#              "features": RS9116FeatureBitMap.LPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#              "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#              "band": 0,
#              "beacon_interval": 1000
#          }
#      )
# @pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
# @pytest.mark.parametrize("protocol", [IperfConstants.TCP])
#
# def test_TCP_UDP_Rx_data_transfer_in_powersave_mode2_C3993(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
#     # scan the AP
#     wifi_dut.interfaces.wifi.scan()
#     # Connect to the AP
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#
#     # preparing wifi_dut
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     ip_config = wifi_dut.interfaces.wifi.start_ip()
#     device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
#     # Initiating power save2
#     wifi_dut.interfaces.wifi.power_save(2, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#         power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
#     )
#
#     # preparing iperf
#     host_ip = wifi_client.interfaces.wifi.get_ip_address()
#     net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
#
#     # creating results object for sharing between host and dut
#     result = Result(net_perf_client.interfaces.net_perf.protocol)
#
#     # open socket and start listening
#     with wifi_dut.interfaces.wifi.start_socket_reader(
#             log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
#             result=result,
#             protocol=net_perf_client.interfaces.net_perf.protocol,
#             port=net_perf_client.interfaces.net_perf.client_port,
#             device_ip=device_ip,
#             data_len=net_perf_client.interfaces.net_perf.client_data_len,
#             time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
#         # start iperf
#         net_perf_client.interfaces.net_perf.start()
#         # capture device output
#         wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
#
#     # get and print throughput
#     tp = net_perf_client.interfaces.net_perf.process_output(result)
    # assert tp is not None
#     # __print_throughput(tp)


# @pytest.mark.config(
#          "wifi_dut",
#         wifi=
#          {
#              "oper_mode": 0,
#              "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#              "features": RS9116FeatureBitMap.LPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#              "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#
#              "band": 0,
#
#              "beacon_interval": 1000
#          }
#      )
# @pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
# @pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
# def test_TCP_UDP_Rx_data_transfer_in_powersave_mode2_C3994(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
#     # scan the AP
#     wifi_dut.interfaces.wifi.scan()
#     # Connect to the AP
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#
#     # preparing wifi_dut
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     ip_config = wifi_dut.interfaces.wifi.start_ip()
#     device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
#     # Initiating power save2
#     wifi_dut.interfaces.wifi.power_save(2, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#         power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
#     )
#
#     # preparing iperf
#     host_ip = wifi_client.interfaces.wifi.get_ip_address()
#     net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
#
#     # creating results object for sharing between host and dut
#     result = Result(net_perf_client.interfaces.net_perf.protocol)
#
#     # open socket and start listening
#     with wifi_dut.interfaces.wifi.start_socket_reader(
#             log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
#             result=result,
#             protocol=net_perf_client.interfaces.net_perf.protocol,
#             port=net_perf_client.interfaces.net_perf.client_port,
#             device_ip=device_ip,
#             data_len=net_perf_client.interfaces.net_perf.client_data_len,
#             time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
#         # start iperf
#         net_perf_client.interfaces.net_perf.start()
#         # capture device output
#         wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
#
#     # get and print throughput
#     tp = net_perf_client.interfaces.net_perf.process_output(result)
#     assert tp is not None
# #     # __print_throughput(tp)



# @pytest.mark.config(
#          "wifi_dut",
#         wifi=
#          {
#              "oper_mode": 0,
#              "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#              "features": RS9116FeatureBitMap.LPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#              "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#
#              "band": 0,
#
#              "beacon_interval": 1000
#          }
#      )
# @pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
# @pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
# def test_TCP_UDP_Tx_data_transfer_in_powersave_mode3_C3996(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
#     # scan the AP
#     wifi_dut.interfaces.wifi.scan()
#     # Connect to the AP
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#
#     # preparing wifi_dut
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     ip_config = wifi_dut.interfaces.wifi.start_ip()
#     device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
#     # Initiating power save3
#     wifi_dut.interfaces.wifi.power_save(3, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#        power_save_mode=RS9116PowerSaveModes.PowerSaveMode3
#     )
#
#     # preparing iperf
#     host_ip = wifi_client.interfaces.wifi.get_ip_address()
#     net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
#
#     # creating results object for sharing between host and dut
#     result = Result(net_perf_client.interfaces.net_perf.protocol)
#
#     # open socket and start listening
#     with wifi_dut.interfaces.wifi.start_socket_reader(
#             log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
#             result=result,
#             protocol=net_perf_client.interfaces.net_perf.protocol,
#             port=net_perf_client.interfaces.net_perf.client_port,
#             device_ip=device_ip,
#             data_len=net_perf_client.interfaces.net_perf.client_data_len,
#             time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
#         # start iperf
#         net_perf_client.interfaces.net_perf.start()
#         # capture device output
#         wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
#
#     # get and print throughput
#     tp = net_perf_client.interfaces.net_perf.process_output(result)
#     assert tp is not None
    # __print_throughput(tp)


# @pytest.mark.config(
#          "wifi_dut",
#         wifi=
#          {
#              "oper_mode": 0,
#              "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#              "features": RS9116FeatureBitMap.LPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#              "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#              "band": 0,
#              "beacon_interval": 1000
#          }
#      )
# @pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
# @pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
# def test_TCP_UDP_Rx_data_transfer_in_powersave_mode3_C3997(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
#    #scan the AP
#     wifi_dut.interfaces.wifi.scan()
#     # Connect to the AP
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#
#     # preparing wifi_dut
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     ip_config = wifi_dut.interfaces.wifi.start_ip()
#     device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
#     # Initiating power save3
#     wifi_dut.interfaces.wifi.power_save(3, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#         power_save_mode=RS9116PowerSaveModes.PowerSaveMode3
#     )
#
#     # preparing iperf
#     host_ip = wifi_client.interfaces.wifi.get_ip_address()
#     net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
#
#     # creating results object for sharing between host and dut
#     result = Result(net_perf_client.interfaces.net_perf.protocol)
#
#     # open socket and start listening
#     with wifi_dut.interfaces.wifi.start_socket_reader(
#             log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
#             result=result,
#             protocol=net_perf_client.interfaces.net_perf.protocol,
#             port=net_perf_client.interfaces.net_perf.client_port,
#             device_ip=device_ip,
#             data_len=net_perf_client.interfaces.net_perf.client_data_len,
#             time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
#         # start iperf
#         net_perf_client.interfaces.net_perf.start()
#         # capture device output
#         wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
#
#     # get and print throughput
#     tp = net_perf_client.interfaces.net_perf.process_output(result)
#     assert tp is not None


# @pytest.mark.config(
#          "wifi_dut",
#         wifi=
#          {
#              "oper_mode": 0,
#              "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#              "features": RS9116FeatureBitMap.LPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#              "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#
#              "band": 0,
#
#              "beacon_interval": 1000
#          }
#      )
# @pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
# @pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
# def test_TCP_UDP_Tx_data_transfer_in_powersave_mode3_C4000(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
#     # scan the AP
#     wifi_dut.interfaces.wifi.scan()
#     # Connect to the AP
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#
#     # preparing wifi_dut
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     ip_config = wifi_dut.interfaces.wifi.start_ip()
#     device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
#     # Initiating power save3
#     wifi_dut.interfaces.wifi.power_save(3, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#         power_save_mode=RS9116PowerSaveModes.PowerSaveMode3
#     )
#
#     # preparing iperf
#     host_ip = wifi_client.interfaces.wifi.get_ip_address()
#     net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
#
#     # creating results object for sharing between host and dut
#     result = Result(net_perf_client.interfaces.net_perf.protocol)
#
#     # open socket and start listening
#     with wifi_dut.interfaces.wifi.start_socket_reader(
#             log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
#             result=result,
#             protocol=net_perf_client.interfaces.net_perf.protocol,
#             port=net_perf_client.interfaces.net_perf.client_port,
#             device_ip=device_ip,
#             data_len=net_perf_client.interfaces.net_perf.client_data_len,
#             time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
#         # start iperf
#         net_perf_client.interfaces.net_perf.start()
#         # capture device output
#         wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
#
#     # get and print throughput
#     tp = net_perf_client.interfaces.net_perf.process_output(result)
#     assert tp is not None



# @pytest.mark.config(
#          "wifi_dut",
#         wifi=
#          {
#              "oper_mode": 0,
#              "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#              "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#              "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#              "band": 0,
#              "beacon_interval": 1000
#          }
#      )
# @pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
# @pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
# def test_TCP_UDP_Rx_data_transfer_in_powersave_mode3_C4001(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
#     # scan the AP
#     wifi_dut.interfaces.wifi.scan()
#     # Connect to the AP
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#
#     # preparing wifi_dut
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     ip_config = wifi_dut.interfaces.wifi.start_ip()
#     device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
#     # Initiating power save3
#     wifi_dut.interfaces.wifi.power_save(3, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#         power_save_mode=RS9116PowerSaveModes.PowerSaveMode3
#     )
#
#     # preparing iperf
#     host_ip = wifi_client.interfaces.wifi.get_ip_address()
#     net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
#
#     # creating results object for sharing between host and dut
#     result = Result(net_perf_client.interfaces.net_perf.protocol)
#
#     # open socket and start listening
#     with wifi_dut.interfaces.wifi.start_socket_reader(
#             log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
#             result=result,
#             protocol=net_perf_client.interfaces.net_perf.protocol,
#             port=net_perf_client.interfaces.net_perf.client_port,
#             device_ip=device_ip,
#             data_len=net_perf_client.interfaces.net_perf.client_data_len,
#             time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
#         # start iperf
#         net_perf_client.interfaces.net_perf.start()
#         # capture device output
#         wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
#
#     # get and print throughput
#     tp = net_perf_client.interfaces.net_perf.process_output(result)
#     assert tp is not None
# #     # __print_throughput(tp)

#
# @pytest.mark.config(
#          "wifi_dut",
#         wifi=
#          {
#              "oper_mode": 0,
#              "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#              "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#              "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#              "band": 0,
#              "beacon_interval": 1000
#          }
#      )
# # @pytest.mark.start_state(wifi=['init'])
# def test_powersave_mode_switching_after_association_case3_C4004(wifi_access_point, wifi_dut, wifi_sniffer):
#     validation = True
#     logger().info("********** configuring the sniffer with access point channel **********")
#     wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
#     logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
#     wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case_C4004.txt')
#     logger().info(f"Fetches the DUT mac address")
#     dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
#     logger().info(f"Device mac address: {dut_mac_address}")
#     bssid = wifi_access_point.interfaces.wifi.bssid
#       #scan the AP
#     wifi_dut.interfaces.wifi.scan()
#       #Connect to the AP
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#       #Get IP over DHCP
#     wifi_dut.interfaces.wifi.start_ip()
#        #Initiating power save2
#     wifi_dut.interfaces.wifi.power_save(2, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#             power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
#         )
#     time.sleep(30)
#      #Disable powersave mode
#     wifi_dut.interfaces.wifi.power_save(0, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#             power_save_mode=RS9116PowerSaveModes.PowerSaveDisabled
#         )
#    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
#                          f'and (wlan.da == {bssid}))'
#    wifi_sniffer.interfaces.capture.stop_capture()
#    logger().info("Stop Sniffer finally")

# @pytest.mark.config(
#          "wifi_dut",
#         wifi=
#          {
#              "oper_mode": 0,
#              "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#              "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#              "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#              "band": 0,
#              "beacon_interval": 1000
#          }
#      )
# # @pytest.mark.start_state(wifi=['init'])
# def test_powersave_mode_switching_after_association_case1_C4004(wifi_access_point, wifi_dut, wifi_sniffer):
#     validation = True
#     logger().info("********** configuring the sniffer with access point channel **********")
#     wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
#     logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
#     wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case_C4004.txt')
#     logger().info(f"Fetches the DUT mac address")
#     dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
#     logger().info(f"Device mac address: {dut_mac_address}")
#     bssid = wifi_access_point.interfaces.wifi.bssid
#       #scan the AP
#     wifi_dut.interfaces.wifi.scan()
#       #Connect to the AP
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#       #Get IP over DHCP
#     wifi_dut.interfaces.wifi.start_ip()
#        #Initiating power save1
#     wifi_dut.interfaces.wifi.power_save(1, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#             power_save_mode=RS9116PowerSaveModes.PowerSaveMode1
#         )
#     time.sleep(30)
#      #Disable powersave mode
#     wifi_dut.interfaces.wifi.power_save(0, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#             power_save_mode=RS9116PowerSaveModes.PowerSaveDisabled
#         )
#    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
#                          f'and (wlan.da == {bssid}))'
#    wifi_sniffer.interfaces.capture.stop_capture()
#   Need to validate this
# @pytest.mark.config(
#          "wifi_dut",
#         wifi=
#          {
#              "oper_mode": 0,
#              "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#              "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#              "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#              "band": 0,
#              "beacon_interval": 1000
#          }
#      )
# # @pytest.mark.start_state(wifi=['init'])
# def test_powersave_mode_switching_after_association_case2_C4004(wifi_access_point, wifi_dut, wifi_sniffer):
#     validation = True
#     logger().info("********** configuring the sniffer with access point channel **********")
#     wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
#     logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
#     wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case_C4004.txt')
#     logger().info(f"Fetches the DUT mac address")
#     dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
#     logger().info(f"Device mac address: {dut_mac_address}")
#     bssid = wifi_access_point.interfaces.wifi.bssid
#       #scan the AP
#     wifi_dut.interfaces.wifi.scan()
#       #Connect to the AP
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#       #Get IP over DHCP
#     wifi_dut.interfaces.wifi.start_ip()
#        #Initiating power save2
#     wifi_dut.interfaces.wifi.power_save(2, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#             power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
#         )
#     time.sleep(30)
#      #Disable powersave mode
#     wifi_dut.interfaces.wifi.power_save(0, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#             power_save_mode=RS9116PowerSaveModes.PowerSaveDisabled
#         )
#    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
#                          f'and (wlan.da == {bssid}))'
#    wifi_sniffer.interfaces.capture.stop_capture()
#    logger().info("Stop Sniffer finally")

# @pytest.mark.config(
#          "wifi_dut",
#         wifi=
#          {
#              "oper_mode": 0,
#              "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#              "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#              "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#              "band": 0,
#              "beacon_interval": 1000
#          }
#      )
# @pytest.mark.start_state(wifi=['init'])
# def test_powersave_mode_after_rejoin_C4013(wifi_access_point, wifi_dut, wifi_sniffer):
#     validation = True
#     logger().info("********** configuring the sniffer with access point channel **********")
#     wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
#     logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
#     wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case_C4013.txt')
#     logger().info(f"Fetches the DUT mac address")
#     dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
#     logger().info(f"Device mac address: {dut_mac_address}")
#       #scan the AP
#     result = wifi_dut.interfaces.wifi.scan()
#     assert result is not None, "No AP Found"
#       #Connect to the AP
#     result = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     assert result is not None, "Could not connect to the AP"
#       #Get IP over DHCP
#     wifi_dut.interfaces.wifi.start_ip()
#        #Initiating power save2
#     result = wifi_dut.interfaces.wifi.power_save(2, 0)
#     assert result is not None
#     wifi_dut.interfaces.wifi.bt_power_save(
#             power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
#         )
#     # host_ip = wifi_dut.interfaces.wifi.get_ip_address()
#     # Stop the ap
#     wifi_access_point.interfaces.wifi.stop_ap()
#     # Start the ap
#     wifi_access_point.interfaces.wifi.start_ap()
#     packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}))'
#     wifi_sniffer.interfaces.capture.stop_capture()
#     logger().info("Stop Sniffer finally")


# @pytest.mark.config(
#          "wifi_dut",
#         wifi=
#          {
#              "oper_mode": 0,
#              "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#              "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#              "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#              "band": 0,
#              "beacon_interval": 1000
#              "ext_tcpip_features": RS9116CertificateType.EAPClientCertificate,
#              "eap_cert": "wifi-user.pem"
#          }
#      )
#
#
# def test_powersave2_in_Enterprise_security_C4014(wifi_access_point, wifi_dut, wifi_sniffer):
#     ap_user_name = "\\\"user1\\\""
#     ap_password = "\\\"12345678\\\""
#     dut_ssid = wifi_access_point.interfaces.wifi.ssid
#     dut_security = wifi_access_point.interfaces.wifi.security
#     validation = True
#     logger().info("********** configuring the sniffer with access point channel **********")
#     wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
#     logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
#     wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case_C4013.txt')
#     logger().info(f"Fetches the DUT mac address")
#     dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
#     logger().info(f"Device mac address: {dut_mac_address}")
#     bssid = wifi_access_point.interfaces.wifi.bssid
#     # scan the AP
#     wifi_dut.interfaces.wifi.scan()
#     # Connect to the AP
# 
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     # Get IP over DHCP
#     wifi_dut.interfaces.wifi.start_ip()
#     # Initiating power save2
#     wifi_dut.interfaces.wifi.power_save(2, 0)
#     wifi_dut.interfaces.wifi.bt_power_save(
#         power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
#     )

#
# @pytest.mark.config(
#          "wifi_dut",
#         wifi=
#          {
#              "oper_mode": 0,
#              "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#              "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#              "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#              "band": 0,
#              "beacon_interval": 1000
#          }
#      )
#
# def test_powersave_disable_functionality_case1_C4006(wifi_access_point, wifi_dut, wifi_sniffer):
#     validation = True
#     logger().info("********** configuring the sniffer with access point channel **********")
#     wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
#     logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
#     wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case_C4006.txt')
#     logger().info(f"Fetches the DUT mac address")
#     dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
#     logger().info(f"Device mac address: {dut_mac_address}")
#     bssid = wifi_access_point.interfaces.wifi.bssid
#       #scan the AP
#     result = wifi_dut.interfaces.wifi.scan()
#     assert result is not None, "No AP Found"
#       #Connect to the AP
#     result = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     assert result is not None, "Could not connect to the AP"
#       #Get IP over DHCP
#     wifi_dut.interfaces.wifi.start_ip()
#        #Initiating power save1
#     result = wifi_dut.interfaces.wifi.power_save(1, 0)
#     assert result is not None
#     wifi_dut.interfaces.wifi.bt_power_save(
#             power_save_mode=RS9116PowerSaveModes.PowerSaveMode1
#         )
#     time.sleep(30)
#     packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}))'
#     wifi_sniffer.interfaces.capture.stop_capture()
#     logger().info("Stop Sniffer finally")

C19860,C19861,C19862,C19863,C19864
#
import pytest
from utf_wiseconnect.devices.rs911x import (RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap,
                            RS9116CustomFeatureBitMap,
                            RS9116ConfigFeatureBitMap,
                            RS9116TCPIPFeatureBitMap,
                            RS9116ExtCustomFeatureBitMap,
                            RS9116ExtTCPIPFeatureBitMap,
                            RS9116SecurityMode,
                            RS9116OperatingMode, RS9116ULPModes
                            )
from utf.interfaces import wifi
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants,IperfTrafficType
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.iperf.iperf_utils import ping
import time


"""This function runs below test steps for DUT-RS9116
    Step1: 1. Configuration of DUT in 2G mode
    Step2 : Do Scan the AP
    Step3: Connect to the AP
    Step4 :Initiate the different powersave modes and check the connectivity 
    Step7 : Issue init,scan and connect to the AP
    Need to use separate .hex files for lp and ulp msb_based and gpio based until we get updated one from Vinod

    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC device)

    Author: Srisha
"""

def logger():
    return get_logger(__name__)


@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "band": 0
        }
    )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_connect_and_disconnect_when_module_is_in_power_save_mode_C3990(wifi_dut, wifi_access_point, wifi_sniffer):
    validation = True
    packet_filter2 = False
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C3990')
    # Scan for the AP's
    result_scan = wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None, "No AP Found"
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
        # Initiating power save
    wifi_dut.interfaces.wifi.power_save(2, 0)
    result= wifi_dut.interfaces.wifi.power_save(2, 0)
    assert result is not None
    wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
        )
    time.sleep(30)
    # Add disconnect.leave api
    wifi_dut.interfaces.wifi.leave()
    time.sleep(5)
        # scan the AP
    result_scan= wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None, "No AP Found"
        # Connect to the AP
    result= wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result is not None, "Could not connect to the AP"

    # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                         f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'],'Sniffer validation failed for NULL data frame with PM bit 1'


@pytest.mark.config(
         "wifi_dut",
        wifi=
         {
             "oper_mode": 0,
             "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
             "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
             "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
             "band": 0,
             "beacon_interval": 1000
         }
     )
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
def test_TCP_UDP_Rx_data_transfer_in_powersave_mode1_C3991(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
    # scan the AP
    result_scan= wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None , "No AP found"
    # Connect to the AP
    result_ap= wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    # preparing wifi_dut
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    # Initiating power save1
    result= wifi_dut.interfaces.wifi.power_save(1, 0)
    assert result is not None
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode1
    )
    # preparing iperf
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    # open socket and start listening
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        # start iperf
        net_perf_client.interfaces.net_perf.start()
        # capture device output
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
    # get throughput
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp is not None


@pytest.mark.config(
        "wifi_dut",
        wifi=
         {
             "oper_mode": 0,
             "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
             "features": RS9116FeatureBitMap.LPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
             "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
             "band": 0,
             "beacon_interval": 1000
         }
     )
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_TCP_UDP_Rx_data_transfer_in_powersave_mode2_C3993(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
    # scan the AP
    result_scan = wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None , "No AP found"
    # Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    # preparing wifi_dut
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    # Initiating power save2
    result= wifi_dut.interfaces.wifi.power_save(2, 0)
    assert result is not None
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    # preparing iperf
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    # open socket and start listening
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        # start iperf
        net_perf_client.interfaces.net_perf.start()
        # capture device output
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp is not None
    
    
@pytest.mark.config(
         "wifi_dut",
        wifi=
         {
             "oper_mode": 0,
             "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
             "features": RS9116FeatureBitMap.LPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
             "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
             "band": 0,
             "beacon_interval": 1000
         }
     )
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
def test_TCP_UDP_Rx_data_transfer_in_powersave_mode2_C3994(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
    # scan the AP
    result_scan = wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None , "No AP found"
    # Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    # preparing wifi_dut
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    # Initiating power save2
    result= wifi_dut.interfaces.wifi.power_save(2, 0)
    assert result is not None
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    # preparing iperf
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    # open socket and start listening
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        # start iperf
        net_perf_client.interfaces.net_perf.start()
        # capture device output
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp is not None
    
    

@pytest.mark.config(
         "wifi_dut",
        wifi=
         {
             "oper_mode": 0,
             "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
             "features": RS9116FeatureBitMap.LPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
             "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
             "band": 0,
             "beacon_interval": 1000
         }
     )
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
def test_TCP_UDP_Tx_data_transfer_in_powersave_mode3_C3996(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
    # scan the AP
    result_scan = wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None , "No AP found"
    # Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    # preparing wifi_dut
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger.info(f"Obtained the device ip address, {device_ip}")
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    # Initiating power save3
    result= wifi_dut.interfaces.wifi.power_save(3, 0)
    assert result is not None, "Device did not go to power save mode3"
    wifi_dut.interfaces.wifi.bt_power_save(
       power_save_mode=RS9116PowerSaveModes.PowerSaveMode3
    )
    # preparing iperf
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    # open socket and start listening
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        # start iperf
        net_perf_client.interfaces.net_perf.start()
        # capture device output
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp is not None
    
    

@pytest.mark.config(
         "wifi_dut",
        wifi=
         {
             "oper_mode": 0,
             "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
             "features": RS9116FeatureBitMap.LPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
             "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
             "band": 0,
             "beacon_interval": 1000
         }
     )
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
def test_TCP_UDP_Rx_data_transfer_in_powersave_mode3_C3997(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
   #scan the AP
    result_scan = wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None, "No AP Found"
    # Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger.info(f"Obtained the device ip address, {device_ip}")
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    # Initiating power save3
    result= wifi_dut.interfaces.wifi.power_save(3, 0)
    assert result is not None, "Device did not go to powersave mode3"
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode3
    )
    # preparing iperf
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    # open socket and start listening
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        # start iperf
        net_perf_client.interfaces.net_perf.start()
        # capture device output
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp is not None
    
    
@pytest.mark.config(
         "wifi_dut",
        wifi=
         {
             "oper_mode": 0,
             "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
             "features": RS9116FeatureBitMap.LPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
             "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
             "band": 0,
             "beacon_interval": 1000
         }
     )
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
def test_TCP_UDP_Tx_data_transfer_in_powersave_mode3_C4000(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
    # scan the AP
    result_scan= wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None , "No AP found"
    # Connect to the AP
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger.info(f"Obtained the device ip address, {device_ip}")
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    # Initiating power save3
    result_power_save = wifi_dut.interfaces.wifi.power_save(3, 0)
    assert result_power_save is not None, "Device did not go to powersave mode3"
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode3
    )
    # preparing iperf
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    # open socket and start listening
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        # start iperf
        net_perf_client.interfaces.net_perf.start()
        # capture device output
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp is not None
    
    
    
@pytest.mark.config(
         "wifi_dut",
        wifi=
         {
             "oper_mode": 0,
             "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
             "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
             "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
             "band": 0,
             "beacon_interval": 1000
         }
     )
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
def test_TCP_UDP_Rx_data_transfer_in_powersave_mode3_C4001(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
    # scan the AP
    result_scan = wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None , "No AP found"
    # Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger.info(f"Obtained the device ip address, {device_ip}")
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    # Initiating power save3
    wifi_dut.interfaces.wifi.power_save(3, 0)
    assert result is not None, "Device did not go to powersave mode3"
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode3
    )
    # preparing iperf
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    # open socket and start listening
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        # start iperf
        net_perf_client.interfaces.net_perf.start()
        # capture device output
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp is not None
    
    

@pytest.mark.config(
         "wifi_dut",
        wifi=
         {
             "oper_mode": 0,
             "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
             "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
             "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
             "band": 0,
             "beacon_interval": 1000
         }
     )
# @pytest.mark.start_state(wifi=['init'])
def test_powersave_mode_switching_after_association_case3_C4004(wifi_access_point, wifi_dut, wifi_sniffer):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case_C4004.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    # scan the AP
    result_scan = wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None , "No AP found"
    # Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
      #Get IP over DHCP
    wifi_dut.interfaces.wifi.start_ip()
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
       #Initiating power save2
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
        )
    time.sleep(30)
    logger().info(f"*****Disable Power save in DUT******")
     #Disable powersave mode
    wifi_dut.interfaces.wifi.power_save(0, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveDisabled
        )
    # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
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
             "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
             "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
             "band": 0,
             "beacon_interval": 1000
         }
     )
# @pytest.mark.start_state(wifi=['init'])
def test_powersave_mode_switching_after_association_case1_C4004(wifi_access_point, wifi_dut, wifi_sniffer):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case_C4004.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
   # scan the AP
    result_scan = wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None , "No AP found"
    # Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
      #Get IP over DHCP
    wifi_dut.interfaces.wifi.start_ip()
       #Initiating power save1
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    wifi_dut.interfaces.wifi.power_save(1, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode1
        )
    time.sleep(30)
     #Disable powersave mode
    logger().info(f"*****Disable Enhanced Max Power save in DUT******")
    wifi_dut.interfaces.wifi.power_save(0, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveDisabled
        )
    # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "band": 0
    }
)

def test_powersave_mode_switching_before_association_case1_C4005(wifi_dut, wifi_access_point, wifi_sniffer):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case1_C4005.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
          #Initiating powersave mode8
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    wifi_dut.interfaces.wifi.power_save(8, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode8
    )
        # Disable powersave mode
    logger().info(f"*****Disable Enhanced Max Power save in DUT******")
    wifi_dut.interfaces.wifi.power_save(0, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveDisabled
    )
   # scan the AP
    result_scan = wifi_dut.interfaces.wifi.scan()
    assert result is not None , "No AP found"
    wifi_sniffer.interfaces.capture.stop_capture()
    # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.ULPGPIOHandshake,
        "band": 0
    }
)
def test_powersave_mode_switching_before_association_case2_C4005(wifi_dut, wifi_access_point, wifi_sniffer):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case2_C4005.txt')
    logger().info(f"Fetches the DUT mac address")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
        #Initiating powersave mode9
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    wifi_dut.interfaces.wifi.power_save(9, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode9
    )
    # Disable powersave mode
    logger().info(f"*****Disable Enhanced Max Power save in DUT******")
    wifi_dut.interfaces.wifi.power_save(0, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveDisabled
    )
    # scan the AP
    wifi_dut.interfaces.wifi.scan()
    wifi_sniffer.interfaces.capture.stop_capture()
    # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
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
            "features": RS9116FeatureBitMap.LPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "band": 1

        }
    )
)
def test_Power_save_mode_8_with_LP_mode_C4007(wifi_dut, wifi_access_point, wifi_sniffer):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Powersave8_LP_C4007')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    logger().info(f"*****Enable Powersave mode8 in LP mode in DUT******")
        # Initiating power save
    wifi_dut.interfaces.wifi.power_save(8, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode8
        )
    time.sleep(120)
         #scan the AP
    wifi_dut.interfaces.wifi.scan()
        #Initiate powersave mode8
    wifi_dut.interfaces.wifi.power_save(8, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode8
    )
    # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
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
            "features": RS9116FeatureBitMap.LPGPIOHandshake| RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "band": 1
        }
    )
def test_Power_save_mode_9_with_LP_mode_C4008(wifi_sniffer, wifi_dut, wifi_access_point):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Powersave9_LP_C4008')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
       # init
    wifi_dut.interfaces.wifi.init()
    logger().info(f"*****Enable Powersave mode9 in LP mode in DUT******")
       # Initiating power save
    wifi_dut.interfaces.wifi.power_save(9, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
          power_save_mode=RS9116PowerSaveModes.PowerSaveMode9
        )
       # Send ACK
    wifi_dut.interfaces.wifi.send_ack(timeout=3)
       # scan the AP
    wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    time.sleep(10)
       # init
    wifi_dut.interfaces.wifi.init()
    time.sleep(10)
       # Initiating power save
    wifi_dut.interfaces.wifi.power_save(9, 0)
       # Send ACK
    wifi_dut.interfaces.wifi.send_ack(timeout=10)
       # scan the AP
    wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
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
            "features": RS9116FeatureBitMap.ULPGPIOHandshake| RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "band": 1
        }
    )

def test_power_save_mode_9_with_ULP_mode_C4010(wifi_sniffer, wifi_dut, wifi_access_point):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Powersave9_ULP_C4007')
       # init
    wifi_dut.interfaces.wifi.init()
    logger().info(f"*****Enable Powersave9 in ULP mode in  DUT******")
       # Initiating power save
    wifi_dut.interfaces.wifi.power_save(9, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
         power_save_mode=RS9116PowerSaveModes.PowerSaveMode9
    )
        # Send ACK
    wifi_dut.interfaces.wifi.send_ack(timeout=3)
       # scan the Ap
    wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    time.sleep(10)
       # init
    wifi_dut.interfaces.wifi.init()
    time.sleep(10)
       # Initiating power save
    wifi_dut.interfaces.wifi.power_save(9, 0)
      # Send ACK
    wifi_dut.interfaces.wifi.send_ack(timeout=10)
      # scan the Ap
    wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}))'
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
             "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
             "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
             "band": 0,
             "beacon_interval": 1000
         }
     )
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_TCP_Rx_data_transfer_in_powersave_mode(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
    # scan the AP
    result_scan = wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None, "No AP Found"
    # Connect to the AP
    result_ap= wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    # Initiating power save3
    logger().info(f"*****Enable Powersave3 in DUT******")
    wifi_dut.interfaces.wifi.power_save(3, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode3
    )
    # preparing iperf
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    # open socket and start listening
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        # start iperf
        net_perf_client.interfaces.net_perf.start()
        # capture device output
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp is not None       
    
    
    

@pytest.mark.config(
         "wifi_dut",
        wifi=
         {
             "oper_mode": 0,
             "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
             "features": RS9116FeatureBitMap.LPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
             "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
             "band": 0,
             "beacon_interval": 1000
         }
     )
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
def test_TCP_UDP_Tx_data_transfer_in_powersave_mode2(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol):
    # scan the AP
    result_scan = wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None, "No AP Found"
    # Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f"*****Enable Powersave3 in DUT******")
    # Initiating power save3
    wifi_dut.interfaces.wifi.power_save(3, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode3
    )

    # preparing iperf
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)

    # open socket and start listening
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        # start iperf
        net_perf_client.interfaces.net_perf.start()
        # capture device output
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp is not None
       



@pytest.mark.config(
         "wifi_dut",
        wifi=
         {
             "oper_mode": 0,
             "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
             "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
             "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
             "band": 0,
             "beacon_interval": 1000
         }
     )
@pytest.mark.start_state(wifi=['init'])
def test_powersave_mode_after_rejoin_C4013(wifi_access_point, wifi_dut, wifi_sniffer):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case_C4013.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
      #scan the AP
    result_scan = wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None, "No AP Found"
      #Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
      #Get IP over DHCP
    wifi_dut.interfaces.wifi.start_ip()
    logger().info(f"*****Enable Powersave3 in  DUT******")
       #Initiating power save2
    result = wifi_dut.interfaces.wifi.power_save(2, 0)
    assert result is not None , "Device has not gone to powersave mode" 
    wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
        )
    # host_ip = wifi_dut.interfaces.wifi.get_ip_address()
    # Stop the ap
    wifi_access_point.interfaces.wifi.stop_ap()
    logger.info("Disconnecting from the AP")
    # Start the ap
    wifi_access_point.interfaces.wifi.start_ap()
    logger.info("Reconnecting from the AP")
    # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
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
             "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
             "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
             "band": 0,
             "beacon_interval": 1000
         }
     )

def test_powersave_disable_functionality_case1_C4006(wifi_access_point, wifi_dut, wifi_sniffer):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case_C4006.txt')
    logger().info(f"Fetches the DUT mac address")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
      #scan the AP
    result_ap = wifi_dut.interfaces.wifi.scan()
    assert result_ap is not None, "No AP Found"
      #Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
      #Get IP over DHCP
    wifi_dut.interfaces.wifi.start_ip()
       #Initiating power save1
    result = wifi_dut.interfaces.wifi.power_save(1, 0)
    logger().info(f"*****Enable Powersave1 in  DUT******")
    wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode1
        )
    assert result is not None, "Device didnot enable in powersave mode1"
    time.sleep(30)
    # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
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
             "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
             "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
             "band": 0,
             "beacon_interval": 1000
         }
     )
def test_powersave_disable_functionality_case2_C4006(wifi_access_point, wifi_dut, wifi_sniffer):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case_C4006.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    # bssid = wifi_access_point.interfaces.wifi.bssid
      #scan the AP
    result_scan = wifi_dut.interfaces.wifi.scan()
    assert result_scan is not None, "No AP Found"
      #Connect to the AP
    result_ap = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert result_ap is not None, "Could not connect to the AP"
      #Get IP over DHCP
    wifi_dut.interfaces.wifi.start_ip()
    logger().info(f"*****Enable Powersave2 in  DUT******")
       #Initiating power save2
    result = wifi_dut.interfaces.wifi.power_save(2, 0)
    assert result is not None
    wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
        )
    time.sleep(30)
    # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}))'
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
            "features": RS9116FeatureBitMap.ULPGPIOHandshake| RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "band": 1
        }
    )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_Power_save_mode_8_with_ULP_mode_C4009(wifi_sniffer, wifi_dut, wifi_access_point):
        validation = True
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Powersave8_ULP_C4009')
        logger().info(f"*****Enable Powersave mode8 in DUT******")
        # Initiating power save
        wifi_dut.interfaces.wifi.power_save(8, 0)
        wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode8
        )
        time.sleep(120)
         #scan the Ap
        result = wifi_dut.interfaces.wifi.scan()
        assert result is not None, "No AP Found"
        #Initiate powersave mode8
        wifi_dut.interfaces.wifi.power_save(8, 0)
        # validate NULL data frame with PM bit set to '1'
        packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}))'
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info('Validation for NULL packet with pm bit 1')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'

