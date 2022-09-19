import pytest

from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.logger import get_logger
from utf_wiseconnect.devices.rs911x import (
    RS9116OperatingMode,
    RS9116Band,
    RS9116PowerSaveModes,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116CustomFeatureBitMap,
    RS9116TCPIPFeatureBitMap,RS9116CoexMode)
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.iperf.iperf_utils import ping, print_dict
import time
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.bluetooth import BTSocketRole
from utf.utils.stopwatch import Stopwatch
import pytest
from utf.utils.logger import get_logger
from utf import UtfDatabaseProperties

# from utf_wifi.utf_core.src.utf import UtfDatabaseProperties


def logger():
    return get_logger(__name__)

# Configuring static IP to DUT
mode = 'static'
ip_address = '192.168.100.76'
subnet = '255.255.255.0'
gateway = '192.168.100.76'


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))

]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SMOKE',
                                                       test_case_name='test_version_testcase_id1',
                                                       test_case_id='testcase_id1',
                                                       notes='test notes'))
@pytest.mark.dut("rs9116")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_version_testcase_id1(wifi_dut):
    expected_version = parse_version()
    if expected_version is None:
        pytest.skip("No firmware version for 9116x in manifest, skipping test_version")

    logger().info(f"Expected FW version: {expected_version}")
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f"Actual version: {result}")
    assert result == expected_version

@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SMOKE',
                                                       test_case_name='test_version_testcase_id2',
                                                       test_case_id='testcase_id2',
                                                       notes='test notes'))
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_version_testcase_id2(wifi_dut):
    expected_version = parse_version()
    if expected_version is None:
        pytest.skip("No firmware version for 9116x in manifest, skipping test_version")

    logger().info(f"Expected FW version: {expected_version}")
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f"Actual version: {result}")
    assert result == expected_version

@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SMOKE',
                                                       test_case_name='test_wifi_connect_testcase_id6',
                                                       test_case_id='testcase_id6',
                                                       notes='test notes'))
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_wifi_connect_testcase_id6(wifi_dut, wifi_access_point):
    with TimeMeasurer() as t:
        result = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        assert result

        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
            ), f"Failed to get IP address. Result = {result}"

        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

        status = ping(device_ip, 10)
        assert status == 1
    logger().info(f"Associated and ping in {t.duration} seconds")

@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SMOKE',
                                                       test_case_name='test_ble_connect_testcase_id_19',
                                                       test_case_id='testcase_id_19',
                                                       notes='test notes'))
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_ble_connect_testcase_id_19(wifi_dut, ble_client):
    # Set up DUT for BLE advertising
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None
    wifi_dut.interfaces.wifi.ble_start_advertising()

    # Begin Scanning for BLE devices
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
        bt_dut_address=bt_dut_address
        )
    assert bt_client_address is not None
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        if wifi_dut.interfaces.wifi.ble_address in ble_client.interfaces.bluetooth.get_devices():
            break
    else:
        logger.error(f"Unable to find device {wifi_dut.interfaces.wifi.ble_address} within 30 sec.")
    ble_client.interfaces.bluetooth.stop_scanning()

    # See that we found our device
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert wifi_dut.interfaces.wifi.ble_address in found_devices
    assert (
            found_devices[wifi_dut.interfaces.wifi.ble_address]
            == wifi_dut.interfaces.wifi.ble_advertising_data
    )
    time.sleep(1)
    ble_client.interfaces.bluetooth.connect(bt_dut_address)
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    time.sleep(5)
    ble_client.interfaces.bluetooth.disconnect(bt_dut_address)

@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SMOKE',
                                                       test_case_name='test_wifi_ble_connect_testcase_id_27',
                                                       test_case_id='testcase_id_27',
                                                       notes='test notes'))
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_wifi_ble_connect_testcase_id_27(wifi_dut, wifi_access_point, ble_client):
    # Join Wi-Fi Access Point
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    result = wifi_dut.interfaces.wifi.start_ip(timeout=25)
    # Set up DUT for BLE advertising
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None
    wifi_dut.interfaces.wifi.ble_start_advertising()

    # Begin Scanning for BLE devices
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
        bt_dut_address=bt_dut_address
        )
    assert bt_client_address is not None
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        if wifi_dut.interfaces.wifi.ble_address in ble_client.interfaces.bluetooth.get_devices():
            break
    else:
        logger.error(f"Unable to find device {wifi_dut.interfaces.wifi.ble_address} within 30 sec.")
    ble_client.interfaces.bluetooth.stop_scanning()

    time.sleep(2)

    ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address,
                                            min_conn_interval=160,
                                            max_conn_interval=160,
                                            conn_latency=0,
                                            supervision_timeout=2000)

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    status = ping(device_ip, 10)
    assert status == 1
    time.sleep(5)
    ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SMOKE',
                                                       test_case_name='test_throughput_tcp_tx_2_4_channel1',
                                                       test_case_id='tcp_tx_2_4_channel1',
                                                       notes='test notes'))
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        }
    )
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE, "protocol": IperfConstants.TCP})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_throughput_tcp_tx_2_4_channel1(net_perf_client, wifi_access_point, wifi_dut, wifi_client):
    # preparing wifi_dut
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    # preparing wifi_client
    if wifi_access_point != wifi_client:
        wifi_client.interfaces.wifi.join_ap(wifi_access_point)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

    # starting iperf
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip)
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )

    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp is not None
    __print_throughput(tp)

@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SMOKE',
                                                       test_case_name='test_throughput_udp_rx_2_4_channel1',
                                                       test_case_id='udp_rx_2_4_channel1',
                                                       notes='test notes'))
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        }
    )
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE, "protocol":IperfConstants.UDP})
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_throughput_udp_rx_2_4_channel1(net_perf_client, wifi_access_point, wifi_dut, wifi_client):
    # preparing wifi_dut
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    # preparing wifi_client
    if wifi_access_point != wifi_client:
        wifi_client.interfaces.wifi.join_ap(wifi_access_point)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

    # preparing iperf
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip)

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
    __print_throughput(tp)
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SMOKE',
                                                       test_case_name='test_bt_master_ssp_keyboardonly',
                                                       test_case_id='master_ssp_keyboardonly',
                                                       notes='test notes'))
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        }
    )
# This test case verifies the spp connection in keyboardonly mode
def test_bt_master_ssp_keyboardonly(wifi_dut, bt_client):
    with TimeMeasurer() as t:
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_master_ssp_display(pair_mode="1", capability="2")
        assert bt_dut_address is not None
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code, capability="KeyboardOnly")
        assert bt_client_address is not None
        with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Client
        ) as bt_client_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                addr = bt_client_socket.accept(timeout=10)
                assert addr == bt_dut_address
            # Ping dut
            time.sleep(5)
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                dest_addr=bt_dut_address
            )
            # Close connection
            bt_client_socket.close()
            time.sleep(
                0.2
            )  # to overcome Unexpected response from 'at+rsibt_unbond=B8-27-EB-8E-A9-99': b'AT+RSIBT_SPPDISCONNECTED B8-27-EB-8E-A9-99\r\n\r\nOK'
            wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
    logger().info(f"test completed in {t.duration} seconds")

@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SMOKE',
                                                       test_case_name='test_bt_standard_inquiry_C19983',
                                                       test_case_id='C19983',
                                                       notes='test notes'))
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        }
    )
def test_bt_standard_inquiry_C19983(wifi_dut, bt_client):

    with TimeMeasurer() as t:
        # Configure Raspberry pi in slave mode
        logger().info(f'******Configure Raspberry pi in slave mode******')
        bt_client_address = bt_client.interfaces.bluetooth.start_slave()
        assert bt_client_address is not None
        logger().info(f"Raspberry pi BD address {bt_client_address}")

        # BT initialization
        logger().info(f'******BT initialization******')
        wifi_dut.interfaces.wifi.bt_start()

        device_found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address,
                                                               inquiry_type=2,
                                                               inquiry_duration_ms=20000,
                                                               timeout=22,
                                                               retry_counts=3)
        if not device_found:
            logger().error(f"Dut unable to find the bt client device. The test case may fail.")
        logger().info(f'BT address found = {device_found} and BT address is {bt_client_address} ')
    logger().info(f"Test case executed in {t.duration} seconds")