import pytest
import time
import re
from datetime import datetime
from utf.interfaces.shell.ssh_shell import SSHShell
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xOperatingMode,
    DeviceConstants,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
)
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from threading import Thread

"""
    setup requirement:
        1. DUT(Si917_SDK)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode and enable rts threshold
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Check for rts, cts, data packets in sniffer capture

    Author: CG team
"""


def logger():
    return get_logger(__name__)


def rts_cts_data_sequence_check(wifi_sniffer, dut_mac, ap_bssid, rts_threshold, test_case, data_len_check=True):
    snf_shell = wifi_sniffer.interfaces.capture.shell
    remote_cap_file = wifi_sniffer.interfaces.capture.remote_capture_file
    logger().info(f"capture file is:{remote_cap_file}")

    filter_files = "/tmp/filter_files"
    snf_shell(f"sudo rm -rf {filter_files}; sudo mkdir {filter_files}; sudo chmod +777 {filter_files};")
    rts_cts_file = f'{filter_files}/{test_case}_rts_cts.txt'
    data_filter = f'wlan.fc.type_subtype == 0x0028 && data.len > {rts_threshold}' if data_len_check else 'wlan.fc.type_subtype == 0x0028'
    rts_cts_filter = (f'tshark -r {remote_cap_file} -Tfields -e "frame.number" -e "wlan.fc.subtype" -Y '
                      f'"(wlan.ta == {dut_mac} && ({data_filter}) || (wlan.fc.type_subtype == 0x001b)) || '
                      f'(wlan.ra == {dut_mac} && wlan.fc.type_subtype == 0x001c)"')
    snf_shell(f'{rts_cts_filter} > {rts_cts_file}')

    if isinstance(snf_shell, SSHShell):
        with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp_main:
            time_stamp = datetime.fromtimestamp(time.time()).strftime('%m_%d_%Y-%H_%M_%S')
            out_file = f"./reports/{test_case}_rts_cts_{time_stamp}.txt"
            sftp_main.get(rts_cts_file, out_file)
            sftp_main.close()

    logger().info("************ Checking RTS, CTS, DATA Packets Sequence in Sniffer ************")
    frames_dict = {}
    with open(out_file, "r") as fd:
        for line in fd.readlines():
            frames_dict[line.split()[0]] = line.split()[1]

    status = False
    rts = cts = 0
    for frame_num, frame_type in frames_dict.items():
        if frame_type == '11':
            rts = int(frame_num)
        elif frame_type == '12' and rts:
            cts = int(frame_num)
        elif frame_type == '8' and cts:
            data = int(frame_num)
            message = (f"Found Sequence [RTS--->CTS--->DATA] with frame numbers {list((rts, cts, data))} and "
                       f"data length greater than rts_threshold value '{rts_threshold}'")
            if not data_len_check:
                message = f"Found Sequence [RTS--->CTS--->DATA] with frame numbers {list((rts, cts, data))}"
            logger().info(message)
            rts = cts = 0
            status = True
        else:
            rts = cts = 0
    return status


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_rts": 1,
        "rts_threshold": 256,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                                         "set_default_rts_threshold"])
@pytest.mark.legacy_deployed
def test_wsdk_verify_rts_threshold_256_c19511(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections):
    """
    Verify whether DUT is not sending any RTS packet for every data packet if we configure RTS Threshold as '256'
    """
    try:
        capture_filename = "test_rts_c19511"
        logger().info(f"Configuring the sniffer with access point channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(3)

        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=True, ping_count=10,
                                                     associated=False, retry_count=3)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'DUT ip {device_ip}')
        logger().info("pinging to dut.....")
        ping_status = sl_collections.ping_with_custom_size(device_ip, ping_counts=60, byte_size=300)
        assert ping_status, "DUT is not responding to ping request after powersave"
        logger().info("ping to DUT is successful....")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating power management bit in sniffer capture")
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(True, packet_filter1)['packet_count'], \
            'Unable to find power management bit 1 in sniffer'

        logger().info("\n\nValidating RTS,CTS,DATA Packets in sniffer capture")
        status = rts_cts_data_sequence_check(wifi_sniffer, dut_mac_address, ap_bssid, rts_threshold=256,
                                             test_case="test_C19511")
        assert status, "Unable to find sequence RTS--->CTS--->DATA packets with data length more than rts_threshold value"
    except Exception as err:
        sl_collections.exception_handling(wifi_dut, err)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_rts": 1,
        "rts_threshold": 0,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                                         "set_default_rts_threshold"])
@pytest.mark.legacy_deployed
def test_wsdk_verify_rts_threshold_0_c19512(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections):
    """
    Verify whether DUT is sending RTS packets for every data packet if we configure RTS Threshold as '0'
    """
    try:
        capture_filename = "test_rts_c19512"
        logger().info(f"Configuring the sniffer with access point channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(3)

        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=True, ping_count=10,
                                                     associated=False, retry_count=3)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'DUT ip {device_ip}')
        logger().info("pinging to dut.....")
        ping_status = sl_collections.ping_with_custom_size(device_ip, ping_counts=60, byte_size=10)
        assert ping_status, "DUT is not responding to ping request after powersave"
        logger().info("ping to DUT is successful....")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating power management bit in sniffer capture")
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(True, packet_filter1)['packet_count'], \
            'Unable to find power management bit 1 in sniffer'

        logger().info("\n\nValidating RTS,CTS,DATA Packets in sniffer capture")
        status = rts_cts_data_sequence_check(wifi_sniffer, dut_mac_address, ap_bssid, rts_threshold=0,
                                             test_case="test_C19512")
        assert status, "Unable to find sequence RTS--->CTS--->DATA packets with data length more than rts_threshold value"
    except Exception as err:
        sl_collections.exception_handling(wifi_dut, err)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_rts": 1,
        "rts_threshold": 2347,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                                         "set_default_rts_threshold"])
@pytest.mark.legacy_deployed
def test_wsdk_verify_rts_threshold_2347_c19513(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections):
    """
    Verify whether DUT is not sending any RTS packet for every data packet if we configure RTS Threshold as '2347'
    """
    try:
        capture_filename = "test_rts_c19513"
        logger().info(f"Configuring the sniffer with access point channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(3)

        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=True, ping_count=10,
                                                     associated=False, retry_count=3)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'DUT ip {device_ip}')
        logger().info("pinging to dut.....")
        ping_status = sl_collections.ping_with_custom_size(device_ip, ping_counts=60, byte_size=10)
        assert ping_status, "DUT is not responding to ping request after powersave"
        logger().info("ping to DUT is successful....")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating power management bit in sniffer capture")
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(True, packet_filter1)['packet_count'], \
            'Unable to find power management bit 1 in sniffer'

        logger().info("\n\nValidating RTS,CTS,DATA Packets in sniffer capture")
        status = rts_cts_data_sequence_check(wifi_sniffer, dut_mac_address, ap_bssid, rts_threshold=2347,
                                             test_case="test_c19513")
        assert not status, "Found sequence RTS--->CTS--->DATA packets with data length more than rts_threshold value which is not expected"
        logger().info("DUT did not send RTS packets which is expected as per the testcase")
    except Exception as err:
        sl_collections.exception_handling(wifi_dut, err)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['deinit'])
@pytest.mark.end_state("wifi_dut", wifi=["reset"])
@pytest.mark.parametrize("rts_threshold", [-5, 2500])
@pytest.mark.legacy_deployed
def test_wsdk_invalid_rts_c537946(wifi_dut, sl_collections, rts_threshold):
    """
    Verify DUT is throwing error or not by setting Invalid RTS threshold.
    """
    try:
        logger().info(f"Setting rts threshold value as '{rts_threshold}'")
        wifi_dut.interfaces.wifi.set_rts_threshold(config_rts_threshold=1, rts_threshold=rts_threshold, timeout=60)
        wifi_dut.interfaces.wifi.init(expected_status=SLStatus.SL_STATUS_SI91X_INVALID_CONFIG_RANGE_PROVIDED)
        logger().info(
            f"Received expected error code '0x10063' from DUT for invalid RTS threshold value {rts_threshold}\n")
    except Exception as err:
        sl_collections.exception_handling(wifi_dut, err)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_rts": 1,
        "rts_threshold": 235,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                                         "set_default_rts_threshold"])
@pytest.mark.legacy_deployed
def test_wsdk_verify_rts_in_high_congestion_ping_trf_c535103(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections):
    """
    Verify whether DUT is sending CTS packets for every RTS initiated by AP in High congestion environment with ping
    from AP Backend machine.
    """
    try:
        capture_filename = "test_rts_c535103"
        logger().info(f"Configuring the sniffer with access point channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="channel_utilization_check_c535103")
        time.sleep(20)
        wifi_sniffer.interfaces.capture.stop_capture()

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"*********** Validating channel utilization percentage in sniffer capture ***********")
        packet_filter1 = f'(wlan.bssid == {ap_bssid} && wlan.fc.type_subtype == 0x0008) && wlan.qbss.cu >= 206'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(True, packet_filter1)['packet_count'], \
            ('Channel utilization percentage is less than 80%, Please makes sure to have high congestion environment'
             ' with channel utilization more than 80%')
        logger().info("*********** Channel utilization is more than 80% in sniffer capture ***********\n")

        logger().info(f"Again configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(3)
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=True, ping_count=10,
                                                     associated=False, retry_count=3)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        logger().info(f'DUT ip {device_ip}')
        logger().info("pinging to dut.....")
        ping_status = sl_collections.ping_with_custom_size(device_ip, ping_counts=60, byte_size=10)
        assert ping_status, "DUT is not responding to ping request after powersave"
        logger().info("ping to DUT is successful....")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating power management bit in sniffer capture")
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address} || (wlan.addr == {ap_bssid})'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(True, packet_filter1)['packet_count'], \
            'Unable to find power management bit 1 in sniffer'

        logger().info("\n\nValidating RTS,CTS,DATA Packets in sniffer capture")
        status = rts_cts_data_sequence_check(wifi_sniffer, dut_mac_address, ap_bssid, rts_threshold=235,
                                             test_case="test_c535103", data_len_check=False)
        assert status, "Unable to find sequence RTS--->CTS--->DATA packets sequence in sniffer capture"
    except Exception as err:
        sl_collections.exception_handling(wifi_dut, err)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": 0,
        "set_rts": 1,
        "rts_threshold": 235,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                                         "set_default_rts_threshold"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.legacy_deployed
def test_wsdk_verify_rts_in_high_congestion_tcp_rx_c537948(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
                                                           net_perf_client, protocol, wifi_client):
    """
    Verify whether DUT is sending CTS packets for every RTS initiated by AP in High congestion environment with TCP Rx.
    """
    try:
        capture_filename = "test_rts_c537948"
        ap_bssid = wifi_access_point.interfaces.wifi.bssid

        logger().info(f"Configuring the sniffer with access point channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="channel_utilization_check_c537948")
        time.sleep(20)
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"*********** Validating channel utilization percentage in sniffer capture ***********")
        packet_filter1 = f'(wlan.bssid == {ap_bssid} && wlan.fc.type_subtype == 0x0008) && wlan.qbss.cu >= 206'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(True, packet_filter1)['packet_count'], \
            ('Channel utilization percentage is less than 80%, Please makes sure to have high congestion environment'
             ' with channel utilization more than 80%')
        logger().info("*********** Channel utilization is more than 80% in sniffer capture ***********\n")

        logger().info(f"Again configuring the sniffer with channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(3)
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False, ping_count=10,
                                                     associated=False, retry_count=3)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")

        logger().info("Initiating TCP-RX traffic from DUT")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"***** starting iperf ******")
        net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip,
                                                        protocol=protocol, time_out=60)
        logger().info(f"Host IP: {host_ip}, Dut IP: {device_ip}, Protocol: {protocol}")
        time.sleep(2)
        logger().info(f"***** starting iperf ******")
        trf_thread = Thread(target=net_perf_client.interfaces.net_perf.start, args=[3])
        trf_thread.start()
        logger().info(f"***** start listening  ******")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6, local_ip=device_ip, remote_ip=host_ip,
                                       local_port=net_perf_client.interfaces.net_perf.client_port,
                                       remote_port=net_perf_client.interfaces.net_perf.client_port,
                                       size=net_perf_client.interfaces.net_perf.client_options[protocol]["data_len"],
                                       throughput_type=3, qos=0, ttl=60, timeout=80)
        trf_thread.join()
        logger().info("data transfer is successful")

        logger().info("\n\n********** Checking for zero stalls in iperf log file **********")
        iperf_result = net_perf_client.interfaces.net_perf.log_file_path
        with open(iperf_result, 'r') as fd:
            data = fd.read()
        zero_stalls_count = len(list(filter(lambda num: float(num) <= 0, re.findall(r'([\d.]+)\s+\w?bits/sec',
                                                                                    data, re.IGNORECASE))))
        logger().info(f"TCP zero stalls count: {zero_stalls_count}")

        logger().info("\n\nStop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("\n\n************ Validating RTS,CTS,DATA Packets in sniffer capture ************")
        rts_status = rts_cts_data_sequence_check(wifi_sniffer, dut_mac_address, ap_bssid, rts_threshold=235,
                                                 test_case="test_c537948", data_len_check=False)
        assert rts_status, "Unable to find sequence RTS--->CTS--->DATA packets sequence in sniffer capture"
        assert zero_stalls_count == 0, "Observed tcp zero stalls in iperf log file"
    except Exception as err:
        sl_collections.exception_handling(wifi_dut, err)
