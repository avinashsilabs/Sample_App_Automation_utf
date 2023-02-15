import time
import pytest
from paramiko.util import log_to_file
from utf.interfaces.bluetooth import BTSocketRole
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes
from utf.utils.logger import get_logger

def logger():
    return get_logger(__name__)

""" Author: RaviNemali
This test plan aims to verify the BT bracktooth vulnerabilities test cases

Setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Bracktooth ESP-WROVER-KIT
"""

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_bt_vulnerability_invalid_feature_page_execution_C101986(bt_dut, bt_vulnerability_sniffer, bt_client):
    logger().info("======= start bt advertisement in dut")
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_spp()
    assert bt_dut_address,"failed to start BT in dut"
    logger().info(f"dut address{bt_dut_address}")
    time.sleep(1500)
    logger().info("======= start capture of bt sniffer with invalid page execution script")
    sniff_log =f"reports/"+"invalid_feature_page"+".log_"+str(int(time.time()))
    logger().info(f"logfile == {sniff_log}")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.start_capture(
        dut_address=bt_dut_address,
        log_file=sniff_log,
        bt_exploit_type="invalid_feature_page_execution"
    )
    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address=bt_dut_address,
                                                                        pin_code=pin_code)
    assert bt_client_address, "failed to start bluetooth in remote device"

    device_found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=30,
                                                                             retry_counts=3)
    assert device_found, "device not found in scan list"
    logger().info("======= stop sniffer")
    time.sleep(20)
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.stop_capture()
    with open(sniff_log, 'r') as file:
        sniffer_logs = file.read()
        logger().info("\n\n ======= printing Sniffer capture logs \n\n")
        logger().info(sniffer_logs)
        assert"LMP_host_connection_req" in str(sniffer_logs),"failed... Attack from 3rd party script is not found...!"
        logger().info("======= found 'LMP_host_connection_req' in sniffer capture and DUT is stable throughout the test execution")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_bt_vulnerability_truncated_sco_link_request_C101987(bt_dut, bt_client, bt_vulnerability_sniffer):
    logger().info("======= start bt advertisement in dut")
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_spp()
    assert bt_dut_address,"failed to start BT in dut"
    logger().info(f"dut address{bt_dut_address}")
    time.sleep(1500)
    logger().info("======= start capture of bt sniffer with truncated sco link request script")
    sniff_log = f"reports/" + "truncated_sco" + ".log_" + str(int(time.time()))
    logger().info(f"logfile == {sniff_log}")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.start_capture(
        dut_address=bt_dut_address,
        log_file=sniff_log,
        bt_exploit_type="truncated_sco_link_request"
    )

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address=bt_dut_address, pin_code=pin_code)
    assert bt_client_address, "failed to start bluetooth in remote device"

    device_found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=30, retry_counts=3)
    assert device_found,"device not found in scan list"

    logger().info("======= stop sniffer")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.stop_capture()
    with open(sniff_log, 'r') as file:
        sniffer_logs = file.read()
        logger().info("\n\n ======= printing Sniffer capture logs \n\n")
        logger().info(sniffer_logs)
        assert"LMP_host_connection_req" in str(sniffer_logs),"failed... Attack from 3rd party script is not found...!"
        logger().info("======= found 'LMP_host_connection_req' in sniffer capture and DUT is stable throughout the test execution")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_bt_vulnerability_duplicated_iocap_C101988(bt_dut, bt_client, bt_vulnerability_sniffer):
    logger().info("======= start bt advertisement in dut")
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_spp()
    assert bt_dut_address,"failed to start BT in dut"
    logger().info(f"dut address{bt_dut_address}")
    time.sleep(1500)
    logger().info("======= start capture of bt sniffer with duplicated iocap script")
    sniff_log = f"reports/" + "duplicated_iocap" + ".log_" + str(int(time.time()))
    logger().info(f"logfile == {sniff_log}")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.start_capture(
        dut_address=bt_dut_address,
        log_file=sniff_log,
        bt_exploit_type="duplicated_iocap"
    )
    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address=bt_dut_address, pin_code=pin_code)
    assert bt_client_address,"failed to start bluetooth in remote device"
    device_found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=30, retry_counts=3)
    assert device_found,"device not found in scan list"
    logger().info("======= stop sniffer")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.stop_capture()
    with open(sniff_log, 'r') as file:
        sniffer_logs = file.read()
        logger().info("\n\n ======= printing Sniffer capture logs \n\n")
        logger().info(sniffer_logs)
        assert"LMP_host_connection_req" in str(sniffer_logs),"failed... Attack from 3rd party script is not found...!"
        logger().info("======= found 'LMP_host_connection_req' in sniffer capture and DUT is stable throughout the test execution")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_bt_vulnerability_feature_response_flooding_C101989(bt_dut, bt_client, bt_vulnerability_sniffer):
    logger().info("======= start bt advertisement in dut")
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_spp()
    assert bt_dut_address,"failed to start BT in dut"
    logger().info(f"dut address{bt_dut_address}")
    time.sleep(1500)
    logger().info("======= start capture of bt sniffer with feature response flooding script")
    sniff_log = f"reports/" + "feature_response_flooding" + ".log_" + str(int(time.time()))
    logger().info(f"logfile == {sniff_log}")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.start_capture(
        dut_address=bt_dut_address,
        log_file=sniff_log,
        bt_exploit_type="feature_response_flooding"
    )
    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address=bt_dut_address, pin_code=pin_code)
    assert bt_client_address,"failed to start bluetooth in remote device"
    device_found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=30, retry_counts=3)
    assert device_found,"device not found in scan list"
    logger().info("======= stop sniffer")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.stop_capture()
    with open(sniff_log, 'r') as file:
        sniffer_logs = file.read()
        logger().info("\n\n ======= printing Sniffer capture logs \n\n")
        logger().info(sniffer_logs)
        assert"LMP_host_connection_req" in str(sniffer_logs),"failed... Attack from 3rd party script is not found...!"
        logger().info("======= found 'LMP_host_connection_req' in sniffer capture and DUT is stable throughout the test execution")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_bt_vulnerability_lmp_auto_rate_overflow_C101990(bt_dut, bt_client, bt_vulnerability_sniffer):
    logger().info("======= start bt advertisement in dut")
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_spp()
    assert bt_dut_address,"failed to start BT in dut"
    logger().info(f"dut address{bt_dut_address}")
    time.sleep(1500)
    logger().info("======= start capture of bt sniffer with lmp auto rate overflow script")
    sniff_log = f"reports/" + "lmp_auto_rate" + ".log_" + str(int(time.time()))
    logger().info(f"logfile == {sniff_log}")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.start_capture(
        dut_address=bt_dut_address,
        log_file=sniff_log,
        bt_exploit_type="lmp_auto_rate_overflow"
    )
    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address=bt_dut_address, pin_code=pin_code)
    assert bt_client_address,"failed to start bluetooth in remote device"
    device_found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=30, retry_counts=3)
    assert device_found,"device not found in scan list"
    logger().info("======= stop sniffer")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.stop_capture()
    with open(sniff_log, 'r') as file:
        sniffer_logs = file.read()
        logger().info("\n\n ======= printing Sniffer capture logs \n\n")
        logger().info(sniffer_logs)
        assert"LMP_host_connection_req" in str(sniffer_logs),"failed... Attack from 3rd party script is not found...!"
        logger().info("======= found 'LMP_host_connection_req' in sniffer capture and DUT is stable throughout the test execution")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_bt_vulnerability_lmp_2_DH1_Overflow_C101991(bt_dut, bt_client, bt_vulnerability_sniffer):
    logger().info("======= start bt advertisement in dut")
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_spp()
    assert bt_dut_address,"failed to start BT in dut"
    logger().info(f"dut address{bt_dut_address}")
    time.sleep(1500)
    logger().info("======= start capture of bt sniffer with lmp 2dh1 overflow script")
    sniff_log = f"reports/" + "lmp_2dh1" + ".log_" + str(int(time.time()))
    logger().info(f"logfile == {sniff_log}")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.start_capture(
        dut_address=bt_dut_address,
        log_file=sniff_log,
        bt_exploit_type="lmp_overflow_2dh1"
    )
    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address=bt_dut_address, pin_code=pin_code)
    assert bt_client_address,"failed to start bluetooth in remote device"
    device_found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=30, retry_counts=3)
    assert device_found,"device not found in scan list"
    logger().info("======= stop sniffer")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.stop_capture()
    with open(sniff_log, 'r') as file:
        sniffer_logs = file.read()
        logger().info("\n\n ======= printing Sniffer capture logs \n\n")
        logger().info(sniffer_logs)
        assert"LMP_host_connection_req" in str(sniffer_logs),"failed... Attack from 3rd party script is not found...!"
        logger().info("======= found 'LMP_host_connection_req' in sniffer capture and DUT is stable throughout the test execution")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_bt_vulnerability_lmp_Dm1_Overflow_C101992(bt_dut, bt_client, bt_vulnerability_sniffer):
    logger().info("======= start bt advertisement in dut")
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_spp()
    assert bt_dut_address,"failed to start BT in dut"
    logger().info(f"dut address{bt_dut_address}")
    time.sleep(1500)
    logger().info("======= start capture of bt sniffer with lmp dm1 overflow script")
    sniff_log = f"reports/" + "lmp_dm1" + ".log_" + str(int(time.time()))
    logger().info(f"logfile == {sniff_log}")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.start_capture(
        dut_address=bt_dut_address,
        log_file=sniff_log,
        bt_exploit_type="lmp_overflow_dm1"
    )

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address=bt_dut_address, pin_code=pin_code)
    assert bt_client_address,"failed to start bluetooth in remote device"
    device_found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=30, retry_counts=3)
    assert device_found,"device not found in scan list"
    logger().info("======= stop sniffer")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.stop_capture()
    with open(sniff_log, 'r') as file:
        sniffer_logs = file.read()
        logger().info("\n\n ======= printing Sniffer capture logs \n\n")
        logger().info(sniffer_logs)
        assert"LMP_host_connection_req" in str(sniffer_logs),"failed... Attack from 3rd party script is not found...!"
        logger().info("======= found 'LMP_host_connection_req' in sniffer capture and DUT is stable throughout the test execution")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_bt_vulnerability_truncated_lmp_accepted_C101993(bt_dut, bt_client, bt_vulnerability_sniffer):
    logger().info("======= start bt advertisement in dut")
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_spp()
    assert bt_dut_address,"failed to start BT in dut"
    logger().info(f"dut address{bt_dut_address}")
    time.sleep(1500)
    logger().info("======= start capture of bt sniffer with truncated lmp accepted script")
    sniff_log = f"reports/" + "truncated_lmp_accepted" + ".log_" + str(int(time.time()))
    logger().info(f"logfile == {sniff_log}")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.start_capture(
        dut_address=bt_dut_address,
        log_file=sniff_log,
        bt_exploit_type="truncated_lmp_accepted"
    )
    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address=bt_dut_address, pin_code=pin_code)
    assert bt_client_address,"failed to start bluetooth in remote device"
    device_found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=30, retry_counts=3)
    assert device_found,"device not found in scan list"
    logger().info("======= stop sniffer")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.stop_capture()
    with open(sniff_log, 'r') as file:
        sniffer_logs = file.read()
        logger().info("\n\n ======= printing Sniffer capture logs \n\n")
        logger().info(sniffer_logs)
        assert"LMP_host_connection_req" in str(sniffer_logs),"failed... Attack from 3rd party script is not found...!"
        logger().info("======= found 'LMP_host_connection_req' in sniffer capture and DUT is stable throughout the test execution")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_bt_vulnerability_same_host_connected_C101995(bt_dut, bt_client, bt_vulnerability_sniffer):
    logger().info("======= start bt advertisement in dut")
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_spp()
    assert bt_dut_address,"failed to start BT in dut"
    logger().info(f"dut address{bt_dut_address}")
    time.sleep(1500)
    logger().info("======= start capture of bt sniffer with same host connected script")
    sniff_log = f"reports/" + "same_host" + ".log_" + str(int(time.time()))
    logger().info(f"logfile == {sniff_log}")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.start_capture(
        dut_address=bt_dut_address,
        log_file=sniff_log,
        bt_exploit_type="repeated_host_connection"
    )
    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address=bt_dut_address, pin_code=pin_code)
    assert bt_client_address,"failed to start bluetooth in remote device"
    device_found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=30, retry_counts=3)
    assert device_found,"device not found in scan list"
    logger().info("======= stop sniffer")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.stop_capture()
    with open(sniff_log, 'r') as file:
        sniffer_logs = file.read()
        logger().info("\n\n ======= printing Sniffer capture logs \n\n")
        logger().info(sniffer_logs)
        assert"LMP_host_connection_req" in str(sniffer_logs),"failed... Attack from 3rd party script is not found...!"
        logger().info("======= found 'LMP_host_connection_req' in sniffer capture and DUT is stable throughout the test execution")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_bt_vulnerability_lmp_au_rand_C101996(bt_dut, bt_client, bt_vulnerability_sniffer):
    logger().info("======= start bt advertisement in dut")
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_spp()
    assert bt_dut_address,"failed to start BT in dut"
    logger().info(f"dut address{bt_dut_address}")
    time.sleep(1500)
    logger().info("======= start capture of bt sniffer with lmp au rand script")
    sniff_log = f"reports/" + "lmp_au_rand" + ".log_" + str(int(time.time()))
    logger().info(f"logfile == {sniff_log}")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.start_capture(
        dut_address=bt_dut_address,
        log_file=sniff_log,
        bt_exploit_type="au_rand_flooding"
    )
    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address=bt_dut_address, pin_code=pin_code)
    assert bt_client_address,"failed to start bluetooth in remote device"
    device_found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=30, retry_counts=3)
    assert device_found,"device not found in scan list"
    logger().info("======= stop sniffer")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.stop_capture()
    with open(sniff_log, 'r') as file:
        sniffer_logs = file.read()
        logger().info("\n\n ======= printing Sniffer capture logs \n\n")
        logger().info(sniffer_logs)
        assert"LMP_host_connection_req" in str(sniffer_logs),"failed... Attack from 3rd party script is not found...!"
        logger().info("======= found 'LMP_host_connection_req' in sniffer capture and DUT is stable throughout the test execution")

        
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_bt_vulnerability_lmp_invalid_max_slot_C101997(bt_dut, bt_client, bt_vulnerability_sniffer):
    logger().info("======= start bt advertisement in dut")
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_spp()
    assert bt_dut_address,"failed to start BT in dut"
    logger().info(f"dut address{bt_dut_address}")
    time.sleep(1500)
    logger().info("======= start capture of bt sniffer with lmp invalid max slot script")
    sniff_log = f"reports/" + "lmp_invalid_max_slot" + ".log_" + str(int(time.time()))
    logger().info(f"logfile == {sniff_log}")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.start_capture(
        dut_address=bt_dut_address,
        log_file=sniff_log,
        bt_exploit_type="invalid_max_slot"
    )
    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address=bt_dut_address, pin_code=pin_code)
    assert bt_client_address,"failed to start bluetooth in remote device"
    device_found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=30, retry_counts=3)
    assert device_found,"device not found in scan list"
    logger().info("======= stop sniffer")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.stop_capture()
    with open(sniff_log, 'r') as file:
        sniffer_logs = file.read()
        logger().info("\n\n ======= printing Sniffer capture logs \n\n")
        logger().info(sniffer_logs)
        assert"LMP_host_connection_req" in str(sniffer_logs),"failed... Attack from 3rd party script is not found...!"
        logger().info("======= found 'LMP_host_connection_req' in sniffer capture and DUT is stable throughout the test execution")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_bt_vulnerability_lmp_max_slot_length_C101998(bt_dut, bt_client, bt_vulnerability_sniffer):
    logger().info("======= start bt advertisement in dut")
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_spp()
    assert bt_dut_address,"failed to start BT in dut"
    logger().info(f"dut address{bt_dut_address}")
    time.sleep(1500)
    logger().info("======= start capture of bt sniffer with lmp max slot length script")
    sniff_log = f"reports/" + "lmp_invalid" + ".log_" + str(int(time.time()))
    logger().info(f"logfile == {sniff_log}")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.start_capture(
        dut_address=bt_dut_address,
        log_file=sniff_log,
        bt_exploit_type="lmp_max_slot_overflow"
    )
    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address=bt_dut_address, pin_code=pin_code)
    assert bt_client_address,"failed to start bluetooth in remote device"
    device_found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=30, retry_counts=3)
    assert device_found,"device not found in scan list"
    logger().info("======= stop sniffer")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.stop_capture()
    with open(sniff_log, 'r') as file:
        sniffer_logs = file.read()
        logger().info("\n\n ======= printing Sniffer capture logs \n\n")
        logger().info(sniffer_logs)
        assert"LMP_host_connection_req" in str(sniffer_logs),"failed... Attack from 3rd party script is not found...!"
        logger().info("======= found 'LMP_host_connection_req' in sniffer capture and DUT is stable throughout the test execution")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_bt_vulnerability_invalid_timing_accuracy_C101999(bt_dut, bt_client, bt_vulnerability_sniffer):
    logger().info("======= start bt advertisement in dut")
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_spp()
    assert bt_dut_address,"failed to start BT in dut"
    logger().info(f"dut address{bt_dut_address}")
    time.sleep(1500)
    logger().info("======= start capture of bt sniffer with invalid timing accuracy script")
    sniff_log = f"reports/" + "invalid_timing" + ".log_" + str(int(time.time()))
    logger().info(f"logfile == {sniff_log}")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.start_capture(
        dut_address=bt_dut_address,
        log_file=sniff_log,
        bt_exploit_type="invalid_timing_accuracy"
    )
    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address=bt_dut_address, pin_code=pin_code)
    assert bt_client_address,"failed to start bluetooth in remote device"
    device_found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=30, retry_counts=3)
    assert device_found,"device not found in scan list"
    logger().info("======= stop sniffer")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.stop_capture()
    with open(sniff_log, 'r') as file:
        sniffer_logs = file.read()
        logger().info("\n\n ======= printing Sniffer capture logs \n\n")
        logger().info(sniffer_logs)
        assert"LMP_host_connection_req" in str(sniffer_logs),"failed... Attack from 3rd party script is not found...!"
        logger().info("======= found 'LMP_host_connection_req' in sniffer capture and DUT is stable throughout the test execution")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_bt_vulnerability_paging_scan_disable_C1012000(bt_dut, bt_client, bt_vulnerability_sniffer):
    logger().info("======= start bt advertisement in dut")
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_spp()
    assert bt_dut_address,"failed to start BT in dut"
    logger().info(f"dut address{bt_dut_address}")
    time.sleep(1500)
    logger().info("======= start capture of bt sniffer with page scan disable script")
    sniff_log = f"reports/" + "page_scan" + ".log_" + str(int(time.time()))
    logger().info(f"logfile == {sniff_log}")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.start_capture(
        dut_address=bt_dut_address,
        log_file=sniff_log,
        bt_exploit_type="paging_scan_disable"
    )
    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address=bt_dut_address, pin_code=pin_code)
    assert bt_client_address,"failed to start bluetooth in remote device"
    device_found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=30, retry_counts=3)
    assert device_found,"device not found in scan list"
    logger().info("======= stop sniffer")
    bt_vulnerability_sniffer.interfaces.bt_vul_sniffer.stop_capture()
    with open(sniff_log, 'r') as file:
        sniffer_logs = file.read()
        logger().info("\n\n ======= printing Sniffer capture logs \n\n")
        logger().info(sniffer_logs)
        assert"LMP_host_connection_req" in str(sniffer_logs),"failed... Attack from 3rd party script is not found...!"
        logger().info("======= found 'LMP_host_connection_req' in sniffer capture and DUT is stable throughout the test execution")
