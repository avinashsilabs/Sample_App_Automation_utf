import time
import pytest

from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116PowerSaveModes,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116TCPIPFeatureBitMap,
    RS9116CustomFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116BLEFeatureBitMap,
    RS9116BTFeatureBitMap,

)
from utf.interfaces.wifi import WlanError
from utf.utils.logger import get_logger

def logger():
    return get_logger(__name__)

def __print_throughput(throughput: dict):
    if throughput is not None:
        print_dict("##     ", throughput)
"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in Wifi+Bluetooth dual mode
        2. Put DUT in BLE advertising mode
        3. Put RaspberryPi in scan mode
        4. Initiate connection from Raspberry pi over BLE
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
"""
"""Author : Aravind"""


class device_scan_result:
    def check_for_devices_in_scanned_results(self, ble_client, bt_dut_address, adv_data):
        sw = Stopwatch()
        previously_found_devices = {}
        while sw.elapsed_sec < 30:
            found_devices = ble_client.interfaces.bluetooth.get_devices()
            if previously_found_devices != found_devices:
                logger().info(f"BLE scan results :{found_devices}")
                previously_found_devices = found_devices
            if (
            bt_dut_address in found_devices
            and found_devices[bt_dut_address]
            == adv_data):
                return True
        return False

class power_number_output():
    def __init__(self, power_meter = None, dtim=None):
        super().__init__()
        self.power_meter = power_meter

    def __print_throughput(self, throughput: dict):
        if throughput is not None:
            print_dict("##     ", throughput)

    def get_power_value(self):
        logger().info("initiating power meter")
        self.power_meter.interfaces.power_meter.init_power_meter(data_log_file_name=f"UTF1_Data_Log")
        # Init power meter module

        self.power_meter.interfaces.power_meter.init_power_meter_module("data_logger")
        # set power meter out put channels
        logger().info("setting output channels")
        self.power_meter.interfaces.power_meter.set_output_channels_settings(
            [{"channel": "1", "emulation_mode": "Current Measure", "trace_current": True, "trace_voltage": False,
              "trace_power": False}])
        # start capture power meter datalog/scope
        logger().info("starting power meter capture")
        self.power_meter.interfaces.power_meter.start_capture()

        # Parse result as throughput object
        logger().info("parsing output result")
        parsed_result = self.power_meter.interfaces.power_meter.power_meter_module.process_output(
            self.power_meter.interfaces.power_meter.results)
        self.__print_throughput(parsed_result)
        assert parsed_result["Output"] is not None


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 |
        RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.BLEFeatureBitmapValid | RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": RS9116BLEFeatureBitMap.Default,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv"])
def test_ble_advertise_connectable_power_0dBm_C20571(wifi_dut, ble_client, power_meter):
    with BleLogs(
        start_collecting_logs=True,
        bt_log_path=f"./test_ble_advertise_connectable_power_{int(time.time())}.log",
    ) as bt_logs:

        logger().info("Initializing BLE")
        # Set up DUT for BLE advertising
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()

        logger().info("Advertising DUT ")

        logger().info("keeping the DUT in undirected_connectable ADV mode")

        wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128, ble_adv_int_min=2056, ble_adv_int_max=2056, ble_adv_channel_map=7)

        logger().info("Enabling power save")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

        logger().info("Initiating scan from remote BLE device")

        # Begin Scanning for BLE devices
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address
        )
        assert bt_client_address is not None,"Unable to fetch remote bluetooth address"
        scan_result=device_scan_result()

        device_found = scan_result.check_for_devices_in_scanned_results(ble_client=ble_client,
                                                             bt_dut_address=bt_dut_address,
                                                             adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
        if device_found:
            logger().info("Dut found in scan results")
        logger().info("Initiating stop scanning from remote device")
        ble_client.interfaces.bluetooth.stop_scanning()
        assert device_found, "Dut not found in scan results"
        logger().info(f"Getting Remote BLE characteristics by passing address "
                      f"{wifi_dut.interfaces.wifi.ble_address} from BTmon logs")

        bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)

        logger().info(f"fetched data from bt mon {bt_logs.device_adv_type}")

        assert "Connectable undirected - ADV_IND (0x00)" in bt_logs.device_adv_type,\
            "Expected adv type not found in bt mon logs"
        logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")
        time.sleep(10)
        power_obj = power_number_output(power_meter=power_meter)
        power_obj.get_power_value()
        time.sleep(3)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 |
        RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.BLEFeatureBitmapValid | RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": RS9116BLEFeatureBitMap.Default,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv"])
def test_ble_advertise_non_connectable_power_0dBm_C20572(wifi_dut, ble_client, power_meter):
    with BleLogs(
        start_collecting_logs=True,
        bt_log_path=f"./test_ble_advertise_non_connectable_power{int(time.time())}.log",
    ) as bt_logs:

        logger().info("Initializing BLE")
        # Set up DUT for BLE advertising
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()

        logger().info("Advertising DUT ")

        logger().info("keeping the DUT in undirected_non_connectable_adv mode")
        wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=131, ble_adv_int_min=2056, ble_adv_int_max=2056, ble_adv_channel_map=7)

        logger().info("Initiating power save")

        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

        logger().info("Initiating scanning from Remote remote device")

        # Begin Scanning for BLE devices
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address
        )
        assert bt_client_address is not None,"Unable to fetch bluetooth address from remote device"
        scan_result = device_scan_result()

        device_found = scan_result.check_for_devices_in_scanned_results(ble_client=ble_client,
                                                                        bt_dut_address=bt_dut_address,
                                                                        adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
        if device_found:
            logger().info("Dut found in scan results")

        logger().info("initiating stop scanning")
        ble_client.interfaces.bluetooth.stop_scanning()
        assert device_found, "dut not found in scan results"
        logger().info(f"Getting Remote BLE characteristics by passing address "
                      f"{wifi_dut.interfaces.wifi.ble_address} from BTmon logs")

        bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)

        logger().info(f"fetched data from bt mon {bt_logs.device_adv_type}")

        assert (
            "Non connectable undirected - ADV_NONCONN_IND (0x03)"
            in bt_logs.device_adv_type
        ),"Expected avd type not found bt mon logs"
        logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")
        time.sleep(10)

        power_obj = power_number_output(power_meter=power_meter)
        power_obj.get_power_value()
        time.sleep(3)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 |
        RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.BLEFeatureBitmapValid | RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": RS9116BLEFeatureBitMap.Default,
    },
)
def test_ble_connect_with_200ms_0dBm_C20574(wifi_dut, ble_client, power_meter):
    device_found=None
    logger().info("Initializing BLE")
    # Set up DUT for BLE advertising
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()

    logger().info("Advertising DUT ")

    wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128, ble_adv_int_min=2056, ble_adv_int_max=2056,
                                                   ble_adv_channel_map=7)
    logger().info("Initiating power save")

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

    logger().info("Initiating scan from remote device")

    # Begin Scanning for BLE devices
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
        bt_dut_address=bt_dut_address
    )
    assert bt_client_address is not None,"Unable to fetch BD address from remote BLE device"
    scan_result = device_scan_result()

    for i in range(0, 3):
        device_found = scan_result.check_for_devices_in_scanned_results(ble_client=ble_client,
                                                                        bt_dut_address=bt_dut_address,
                                                                        adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
        if device_found:
            logger().info("DUT found in scan results")
            break
    assert device_found, "DUT not found in scan results"

    logger().info("initiating stop scanning")
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Initiating connection from remote device")

    ble_client.interfaces.bluetooth.connect(bt_dut_address, min_conn_interval=0xa0,
                                                 max_conn_interval=0xa0, conn_latency=0,
                                                 supervision_timeout=3200)
    time.sleep(10)
    logger().info("started power meter process")
    power_obj = power_number_output(power_meter=power_meter)
    power_obj.get_power_value()

    logger().info("Initiating disconnection from remote device")
    ble_client.interfaces.bluetooth.disconnect(wifi_dut.interfaces.wifi.ble_address)
    time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 |
        RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.BLEFeatureBitmapValid | RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": RS9116BLEFeatureBitMap.Default,
    },
)
def test_ble_connect_with_1_28ms_0dBm_C20575(wifi_dut, ble_client, power_meter):
    device_found=None
    logger().info("Initializing BLE")

    # Set up DUT for BLE advertising
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()

    logger().info("Advertising DUT ")

    wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128, ble_adv_int_min=2056, ble_adv_int_max=2056,
                                                   ble_adv_channel_map=7)
    logger().info("Initiating power save")

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

    logger().info("Initiating scan from remote device")

    # Begin Scanning for BLE devices
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
        bt_dut_address=bt_dut_address
    )
    assert bt_client_address is not None,"Unable to fetch BD address from remote BLE device"

    scan_result = device_scan_result()

    for i in range(0, 3):
        device_found = scan_result.check_for_devices_in_scanned_results(ble_client=ble_client,
                                                                    bt_dut_address=bt_dut_address,
                                                                    adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
        if device_found:
            logger().info("DUT found in scan results")
            break
    assert device_found, "DUT not found in scan results"
    logger().info("initiating stop scanning")
    ble_client.interfaces.bluetooth.stop_scanning()

    time.sleep(20)
    ble_client.interfaces.bluetooth.connect(bt_dut_address, min_conn_interval=0x400,
                                                 max_conn_interval=0x400, conn_latency=0, supervision_timeout=3200)

    time.sleep(10)
    logger().info("started power meter process")
    power_obj = power_number_output(power_meter=power_meter)
    power_obj.get_power_value()
    logger().info("Initiating disconnection from remote device")
    ble_client.interfaces.bluetooth.disconnect(wifi_dut.interfaces.wifi.ble_address)
    time.sleep(5)

################################################

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
                               | RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "bt_features": RS9116BTFeatureBitMap.BLEFeatureBitmapValid | RS9116BTFeatureBitMap.RFTypeSelection,
        "enable_ble_power_index_params": 1,
        "power_index": 63,
       },
)
def test_ble_connect_with_200ms_4dBm_C20576(wifi_dut, ble_client, power_meter):
    device_found=None
    logger().info("Initializing BLE")

    # Set up DUT for BLE advertising
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()

    logger().info("Advertising DUT ")

    wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128, ble_adv_int_min=1285, ble_adv_int_max=1285,
                                                   ble_adv_channel_map=7)
    logger().info("Initiating power save")

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

    logger().info("Initiating scan from remote device")

    # Begin Scanning for BLE devices
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
        bt_dut_address=bt_dut_address
    )
    assert bt_client_address is not None, "Unable to fetch BD address from remote BLE device"
    scan_result = device_scan_result()

    for i in range(0, 3):
        device_found = scan_result.check_for_devices_in_scanned_results(ble_client=ble_client,
                                                                        bt_dut_address=bt_dut_address,
                                                                        adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
        if device_found:
            logger().info("DUT found in scan results")
            break
    assert device_found, "DUT not found in scan results"
    logger().info("initiating stop scanning")
    ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found, "DUT not found in scan results"

    logger().info("Initiating connection from remote device")

    # ble_client.interfaces.bluetooth.connect(wifi_dut.interfaces.wifi.ble_address)

    time.sleep(60)
    ble_client.interfaces.bluetooth.connect(bt_dut_address, min_conn_interval=0xa0,
                                                 max_conn_interval=0xa0,conn_latency=0, supervision_timeout=3200)

    logger().info("Initiating disconnection from remote device")
    time.sleep(10)

    power_obj = power_number_output(power_meter=power_meter)
    power_obj.get_power_value()
    ble_client.interfaces.bluetooth.disconnect(wifi_dut.interfaces.wifi.ble_address)
    time.sleep(5)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 |
        RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.BLEFeatureBitmapValid | RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": RS9116BLEFeatureBitMap.Default,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv"])
def test_ble_advertise_connectable_power_1065ms_C20569(wifi_dut, ble_client, power_meter):
    with BleLogs(
        start_collecting_logs=True,
        bt_log_path=f"./test_ble_advertise_connectable_power_{int(time.time())}.log",
    ) as bt_logs:
        ble_advertising_data = 'Silabsautomation'

        logger().info("Initializing BLE")
        # Set up DUT for BLE advertising
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        logger().info("configure bt local name....")
        wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name='Silabsautomation')

        logger().info("Advertising DUT ")

        logger().info("keeping the DUT in undirected_connectable ADV mode"  )

        wifi_dut.interfaces.wifi.ble_start_advertising(ble_advertising_data=ble_advertising_data,ble_adv_type=128,
                                                       ble_adv_int_min=1704, ble_adv_int_max=1704, ble_adv_channel_map=7)

        logger().info("Enabling power save")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

        logger().info("Initiating scan from remote BLE device")

        # Begin Scanning for BLE devices
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address
        )
        assert bt_client_address is not None,"Unable to fetch remote bluetooth address"
        scan_result=device_scan_result()

        device_found = scan_result.check_for_devices_in_scanned_results(ble_client=ble_client,
                                                             bt_dut_address=bt_dut_address,
                                                             adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
        if device_found:
            logger().info("Dut found in scan results")
        logger().info("Initiating stop scanning from remote device")
        ble_client.interfaces.bluetooth.stop_scanning()
        assert device_found, "Dut not found in scan results"
        logger().info(f"Getting Remote BLE characteristics by passing address "
                      f"{wifi_dut.interfaces.wifi.ble_address} from BTmon logs")

        bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)

        logger().info(f"fetched data from bt mon {bt_logs.device_adv_type}")

        assert "Connectable undirected - ADV_IND (0x00)" in bt_logs.device_adv_type,\
            "Expected adv type not found in bt mon logs"
        logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")

        time.sleep(10)
        power_obj = power_number_output(power_meter=power_meter)
        power_obj.get_power_value()
        time.sleep(3)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 |
        RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.BLEFeatureBitmapValid | RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": RS9116BLEFeatureBitMap.Default,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv"])
def test_ble_advertise_connectable_power_20ms_C20568(wifi_dut, ble_client, power_meter):
    with BleLogs(
        start_collecting_logs=True,
        bt_log_path=f"./test_ble_advertise_connectable_power_{int(time.time())}.log",
    ) as bt_logs:
        ble_advertising_data = 'Silabsautomation'

        logger().info("Initializing BLE")
        # Set up DUT for BLE advertising
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        logger().info("configure bt local name....")
        wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name='Silabsautomation')

        logger().info("Advertising DUT ")

        logger().info("keeping the DUT in undirected_connectable ADV mode")

        wifi_dut.interfaces.wifi.ble_start_advertising(ble_advertising_data=ble_advertising_data,ble_adv_type=128,
                                                       ble_adv_int_min=0x20, ble_adv_int_max=0x20, ble_adv_channel_map=7)

        logger().info("Enabling power save")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)


        logger().info("Initiating scan from remote BLE device")

        # Begin Scanning for BLE devices
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address
        )
        assert bt_client_address is not None,"Unable to fetch remote bluetooth address"
        scan_result=device_scan_result()

        device_found = scan_result.check_for_devices_in_scanned_results(ble_client=ble_client,
                                                             bt_dut_address=bt_dut_address,
                                                             adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
        if device_found:
            logger().info("Dut found in scan results")
        logger().info("Initiating stop scanning from remote device")
        ble_client.interfaces.bluetooth.stop_scanning()
        assert device_found, "Dut not found in scan results"
        logger().info(f"Getting Remote BLE characteristics by passing address "
                      f"{wifi_dut.interfaces.wifi.ble_address} from BTmon logs")

        bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)

        logger().info(f"fetched data from bt mon {bt_logs.device_adv_type}")

        assert "Connectable undirected - ADV_IND (0x00)" in bt_logs.device_adv_type,\
            "Expected adv type not found in bt mon logs"
        logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")
        time.sleep(10)
        power_obj = power_number_output(power_meter=power_meter)
        power_obj.get_power_value()
        time.sleep(3)

##############################################

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 |
        RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.BLEFeatureBitmapValid | RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": RS9116BLEFeatureBitMap.Default,
        "enable_ble_power_index_params": 1,
        "power_index": 63,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv"])
def test_ble_advertise_connectable_power_4dBm_c20573(wifi_dut, ble_client, power_meter):
    with BleLogs(
        start_collecting_logs=True,
        bt_log_path=f"./test_ble_advertise_connectable_power_{int(time.time())}.log",
    ) as bt_logs:
        device_found=None

        logger().info("Initializing BLE")
        # Set up DUT for BLE advertising
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()

        logger().info("Advertising DUT ")

        logger().info("keeping the DUT in undirected_connectable ADV mode")

        wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128, ble_adv_int_min=2056, ble_adv_int_max=2056, ble_adv_channel_map=7)

        logger().info("Enabling power save")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

        logger().info("Initiating scan from remote BLE device")

        # Begin Scanning for BLE devices
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address
        )
        assert bt_client_address is not None,"Unable to fetch remote bluetooth address"
        scan_result=device_scan_result()

        for i in range(0, 3):
            device_found = scan_result.check_for_devices_in_scanned_results(ble_client=ble_client,
                                                                            bt_dut_address=bt_dut_address,
                                                                            adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
            if device_found:
                logger().info("DUT found in scan results")
                break
        assert device_found, "DUT not found in scan results"
        logger().info("Initiating stop scanning from remote device")
        ble_client.interfaces.bluetooth.stop_scanning()
        assert device_found, "Dut not found in scan results"
        logger().info(f"Getting Remote BLE characteristics by passing address "
                      f"{wifi_dut.interfaces.wifi.ble_address} from BTmon logs")

        bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)

        logger().info(f"fetched data from bt mon {bt_logs.device_adv_type}")

        assert "Connectable undirected - ADV_IND (0x00)" in bt_logs.device_adv_type,\
            "Expected adv type not found in bt mon logs"
        logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")
        time.sleep(10)
        power_obj = power_number_output(power_meter=power_meter)
        power_obj.get_power_value()
        time.sleep(3)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
                               | RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "bt_features": RS9116BTFeatureBitMap.BLEFeatureBitmapValid | RS9116BTFeatureBitMap.RFTypeSelection,
        "enable_ble_power_index_params": 1,
        "power_index": 63,
       },
)
def test_ble_connect_with_1_28ms_4dBm_C20577(wifi_dut, ble_client, power_meter):
    device_found=None
    logger().info("Initializing BLE")

    # Set up DUT for BLE advertising
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()

    logger().info("Advertising DUT ")

    wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128, ble_adv_int_min=1285, ble_adv_int_max=1285,
                                                   ble_adv_channel_map=7)
    logger().info("Initiating power save")

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

    logger().info("Initiating scan from remote device")

    # Begin Scanning for BLE devices
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
        bt_dut_address=bt_dut_address
    )
    assert bt_client_address is not None, "Unable to fetch BD address from remote BLE device"
    scan_result = device_scan_result()

    for i in range(0, 3):
        device_found = scan_result.check_for_devices_in_scanned_results(ble_client=ble_client,
                                                                        bt_dut_address=bt_dut_address,
                                                                        adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
        if device_found:
            logger().info("DUT found in scan results")
            break
    assert device_found, "DUT not found in scan results"

    logger().info("initiating stop scanning")
    ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found, "DUT not found in scan results"

    logger().info("Initiating connection from remote device")

    # ble_client.interfaces.bluetooth.connect(wifi_dut.interfaces.wifi.ble_address)

    time.sleep(60)
    ble_client.interfaces.bluetooth.connect(bt_dut_address, min_conn_interval=0x400,
                                                 max_conn_interval=0x400,conn_latency=0, supervision_timeout=3200)

    logger().info("Initiating disconnection from remote device")
    time.sleep(10)

    power_obj = power_number_output(power_meter=power_meter)
    power_obj.get_power_value()

    ble_client.interfaces.bluetooth.disconnect(wifi_dut.interfaces.wifi.ble_address)
    time.sleep(5)


##############BLE PER_0dBm##########
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.BLEFeatureBitmapValid | RS9116BTFeatureBitMap.RFTypeSelection,
       },
)
def test_ble_per_1mbps_tx_0dBm_C20578(bt_dut, bt_client, power_meter):
    cmd_ix = 0x13
    access_addr = 1903575337
    pkt_len = 240
    phy_rate = 1
    rx_chnl_num = 10
    tx_chnl_num = 10
    scrambler_seed = 0
    le_chnl_type = 1
    payload_type = 0x06
    tx_power = 31
    transmit_mode = 1
    freq_hop_en = 0
    ant_sel = 2
    rf_type = 1
    pll_mode = 0
    inter_pkt_gap = 0
    num_pkts = 1000
    rf_chain = 3
    cmd_type = 8

    logger().info("get dut bt address.....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("configure bt local name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name='SILABS_BT')

    logger().info("get bt local name....")
    bt_dut.interfaces.bluetooth.bt_get_local_name()

    bt_dut.interfaces.bluetooth.set_ble_per_tx_params(cmd_ix=cmd_ix, transmit_enable=1, access_addr=access_addr,
                                                      phy_rate=phy_rate, rx_chnl_num =rx_chnl_num, tx_chnl_num=tx_chnl_num,
                                                      scrambler_seed=scrambler_seed, le_chnl_type=le_chnl_type,
                                                      freq_hop_en=freq_hop_en,ant_sel=ant_sel,pll_mode=pll_mode,
                                                      rf_type=rf_type,rf_chain=rf_chain,pkt_len=pkt_len, payload_type=payload_type,tx_power=tx_power,
                                                      transmit_mode=transmit_mode, inter_pkt_gap=inter_pkt_gap,
                                                      num_pkts=num_pkts)
    time.sleep(10)

    logger().info("starting per stats")
    bt_dut.interfaces.bluetooth.get_bt_per_tx_stats(cmd_type=cmd_type)
    time.sleep(10)
    logger().info("power number measurement initiated")
    power_obj = power_number_output(power_meter=power_meter)
    power_obj.get_power_value()


##############BLE PER_10dBm##########
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.BLEFeatureBitmapValid | RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
def test_ble_per_1mbps_tx_10dBm_C20579(bt_dut, bt_client, power_meter):
    cmd_ix = 19
    access_addr = 1903575337
    pkt_len = 240
    phy_rate = 1
    rx_chnl_num = 10
    tx_chnl_num = 10
    scrambler_seed = 0
    le_chnl_type = 1
    payload_type = 0x06
    tx_power = 63
    transmit_mode = 1
    freq_hop_en = 0
    ant_sel = 2
    rf_type = 1
    pll_mode = 0
    inter_pkt_gap = 0
    num_pkts = 1000
    rf_chain = 3
    cmd_type = 8

    logger().info("get dut bt address.....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("configure bt local name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name='SILABS_BT')

    logger().info("get bt local name....")
    bt_dut.interfaces.bluetooth.bt_get_local_name()

    bt_dut.interfaces.bluetooth.set_ble_per_tx_params(cmd_ix=cmd_ix, transmit_enable=1, access_addr=access_addr,
                                                      phy_rate=phy_rate, rx_chnl_num=rx_chnl_num,
                                                      tx_chnl_num=tx_chnl_num,
                                                      scrambler_seed=scrambler_seed, le_chnl_type=le_chnl_type,
                                                      freq_hop_en=freq_hop_en, ant_sel=ant_sel, pll_mode=pll_mode,
                                                      rf_type=rf_type, rf_chain=rf_chain, pkt_len=pkt_len,
                                                      payload_type=payload_type, tx_power=tx_power,
                                                      transmit_mode=transmit_mode, inter_pkt_gap=inter_pkt_gap,
                                                      num_pkts=num_pkts)
    time.sleep(10)

    logger().info("starting per stats")
    bt_dut.interfaces.bluetooth.get_bt_per_tx_stats(cmd_type=cmd_type)
    time.sleep(10)
    logger().info("power number measurement initiated")
    power_obj = power_number_output(power_meter=power_meter)
    power_obj.get_power_value()
    time.sleep(3)



