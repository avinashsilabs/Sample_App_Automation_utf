import time
import pytest
from utf.interfaces.bluetooth import BLEDeviceState
import os
from utf.utils.thread_base import ThreadBase
from utf.utf_config import UtfConfig
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils import print_dict
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.wifi import WlanError
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth.bluez.gatt_application.link_loss_service import LinkLossService, \
    LinkLossAlertLevelCharacteristic
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xPowerSaveModes,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xPowerSaveProcedureTypes,
    Si91xOperatingMode,
)
from utf import UtfDatabaseProperties, TestUserPropertiesSource, UtfTestReport, TransformFileProperties


def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4

    Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. Enable the wlan and bt power save mode in dut after the connection
        3. Initiates ble in DUT 
        4. Connect to the remote device/connect to the dut
        5. Measure the power numbers

    Author: Jyothi Nagireddy
"""

def __print_throughput(throughput: dict):
    if throughput is not None:
        print_dict("##     ", throughput)


def power_measurement(power_device=None, power_meter=None, dtim=None):
    if power_device == "keysight_benchvue_power_analyzer_win_wcf":
        power_obj = power_number_output(power_meter=power_meter, dtim=dtim)
    elif power_device == "nrf_ppk2_device":
        power_obj = ppk_power_number_output(power_meter=power_meter)
    power_obj.get_power_value()


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
                    and found_devices[bt_dut_address] == adv_data  
            ):
                return True
            elif(
                    bt_dut_address in found_devices
                    and len(bt_dut_address) == len(found_devices[bt_dut_address])
            ):
                return True
        return False


class Power_Device:

    def __init__(self) -> None:
        pass
        
    def power_measurement(power_device=None, power_meter=None, dtim=None, capture_time=60):
        
        if power_device == "keysight_benchvue_power_analyzer_win_wcf":
            power_obj = power_number_output(power_meter=power_meter, dtim=dtim, capture_time=capture_time)
        elif power_device == "nrf_ppk2_device":
            power_obj = ppk_power_number_output(power_meter=power_meter)
        power_obj.get_power_value()


class power_number_output():
    def __init__(self, power_meter=None, dtim=None, capture_time=60):
        super().__init__()
        self.power_meter = power_meter
        self.dtim = dtim
        self.capture_time = capture_time

    def __print_throughput(self, throughput: dict):
        if throughput is not None:
            print_dict("##     ", throughput)

    def get_power_value(self):
        dut = UtfConfig.instance().defaults.get("dut", {})
        logger().info(f"dut: {dut}")
        if self.dtim:
            # Init power meter by specifying module name as datalogger or scope
            logger().info(f"initiating power meter wih dtim")
            self.power_meter.interfaces.power_meter.init_power_meter(data_log_file_name=f"UTF1_Data_Log_{self.dtim}", data_log_stop_after_elapsed_time=self.capture_time)
        else:
            logger().info(f"initiating power meter")
            self.power_meter.interfaces.power_meter.init_power_meter(data_log_file_name=f"UTF1_Data_Log", data_log_stop_after_elapsed_time=self.capture_time)
        # Init power meter module

        self.power_meter.interfaces.power_meter.init_power_meter_module("data_logger")
        # set power meter out put channels
        logger().info(f"setting output channels")
        
        if dut == "si917_ncp_sl_wifi":
            self.power_meter.interfaces.power_meter.set_output_channels_settings(
            [{"channel": "1", "emulation_mode": "Current Measure", "trace_current": True, "trace_voltage": False,
              "trace_power": False}])
            
        else:
            self.power_meter.interfaces.power_meter.set_output_channels_settings([{"channel": "3",
                                                                        "emulation_mode": "2 Quadrant Power Supply",
                                                                        "voltage": "3.3000", "current_limit": "1.00000",
                                                                        "voltage_slew": "MAX",
                                                                        "voltage_meter_range": "Auto",
                                                                        "current_meter_range": "Auto",
                                                                        "trace_current": True, "trace_power": True}])
        time.sleep(10)
        # start capture power meter datalog/scope
        logger().info(f"starting power meter capture")
        self.power_meter.interfaces.power_meter.start_capture()

        # Parse result as throughput object
        logger().info(f"parsing output result")
        parsed_result = self.power_meter.interfaces.power_meter.power_meter_module.process_output(
            self.power_meter.interfaces.power_meter.results)
        self.__print_throughput(parsed_result)
        assert parsed_result["Output"] is not None


class ppk_power_number_output():
    def __init__(self, power_meter=None):
        super().__init__()
        self.power_meter = power_meter

    def __print_throughput(self, throughput: dict):
        if throughput is not None:
            print_dict("##     ", throughput)

    def get_power_value(self):
        # Start Capture
        logger().info("Starting PPK capture")
        self.power_meter.interfaces.power_meter.start_capture()
        # Process Output
        file_size = os.path.getsize(self.power_meter.interfaces.power_meter.capture_file)
        assert file_size > 0
        parsed_result = self.power_meter.interfaces.power_meter.process_output()
        self.__print_throughput(parsed_result)
        assert parsed_result["Output"] is not None
        time.sleep(10)

class M4_Sleep_Thread(ThreadBase):
    def __init__(self, wifi_dut=None, m4_sleep_time=100000, deep_sleep_without_ret=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.m4_sleep_time = m4_sleep_time
        self.deep_sleep_without_ret = deep_sleep_without_ret

    def run(self):
        logger().info(f"Enabling M4 power save")
        if self.deep_sleep_without_ret:
            self.wifi_dut.interfaces.wifi.m4_power_manager_deep_sleep(state=0,
                                                                      sleep_time=self.m4_sleep_time)
        else:
            self.wifi_dut.interfaces.wifi.m4_power_manager(sleep_time=self.m4_sleep_time, timeout=150)

class Power_Measurement_Thread(ThreadBase, Power_Device):


    def __init__(self, power_meter=None, capture_time=60):
        super().__init__()
        Power_Device().__init__()
        self.power_meter = power_meter
        self.capture_time = capture_time
	
    def run(self):
        logger().info(f"Starting Power Capture")
        self.power_device = UtfConfig.instance().defaults.get("power_meter", {})
        Power_Device.power_measurement(power_device=self.power_device, power_meter=self.power_meter, capture_time=self.capture_time)


# ********************************************************************************************************************

dut = UtfConfig.instance().defaults.get("dut", {})
logger().info(f"dut: {dut}")

# ********************************************************************************************************************

pytestmark = [pytest.mark.firmware_app("test_352K_M4SS_320K")]   

# ********************************************************************************************************************


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_sdk_advertise_connectable_power_0dBm_C20656(firmware_loader, power_meter, wifi_dut, ble_client, sl_collections, request, performance_data, custom_performance_fixture):
    """ Verify BLE Undirected Connectable advertisement """
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_ble_advertise_connectable_power_{int(time.time())}.log",
    ) as bt_logs:
        try:
            dut = UtfConfig.instance().defaults.get("dut", {})
            logger().info(f"dut: {dut}")
            if dut != "si917_ncp_sl_wifi":
                logger().info(f"M4-TA secure handshake")
                wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
            logger().info("Initializing BLE")
            # Set up DUT for BLE advertising
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=3, bond_info=0, set_smp=1, timeout=10)
            logger().info("configure bt local name....")
            wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name='Silabsautomation')
            logger().info(f"Setting Adv Data")
            wifi_dut.interfaces.wifi.ble_set_adv_data(ble_advertising_data="123456789011234567")
            logger().info(f"fetch the local name")
            wifi_dut.interfaces.wifi.bt_get_local_name()
            logger().info("Advertising DUT ")
            logger().info("keeping the DUT in undirected_connectable ADV mode")
            wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128, ble_adv_int_min=2048, ble_adv_int_max=2048,
                                                           ble_adv_channel_map=7)
            logger().info("Enabling power save")
            
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                   psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            
            wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")

            logger().info("Initiating scan from remote BLE device")
            # Begin Scanning for BLE devices
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=bt_dut_address
            )
            assert bt_client_address is not None, "Unable to fetch remote bluetooth address"
            scan_result = device_scan_result()
            device_found = scan_result.check_for_devices_in_scanned_results(ble_client=ble_client,
                                                                            bt_dut_address=bt_dut_address,
                                                                            adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
            logger().info("Initiating stop scanning from remote device")
            ble_client.interfaces.bluetooth.stop_scanning()
            assert device_found, "Dut not found in scan results"
            logger().info(f"Getting Remote BLE characteristics by passing address "
                          f"{wifi_dut.interfaces.wifi.ble_address} from BTmon logs")

            bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)

            logger().info(f"fetched data from bt mon {bt_logs.device_adv_type}")

            assert "Connectable undirected - ADV_IND (0x00)" in bt_logs.device_adv_type, \
                "Expected adv type not found in bt mon logs"
            logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")
            time.sleep(5)
            pm_obj = Power_Measurement_Thread(power_meter=power_meter)

            if dut != "si917_ncp_sl_wifi":
                m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
                m4_obj.start()
                time.sleep(2)

            pm_obj.start()
            pm_obj.wait_for_exit()

            if dut != "si917_ncp_sl_wifi":
                m4_obj.wait_for_exit()
            
            parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
            __print_throughput(parsed_result)
            assert parsed_result["Output"] is not None
            performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name, 
                                                                  opn=opn, 
                                                                  build_number=build_number,
                                                                  memory_configuration="test_352K_M4SS_320K",
                                                                  parsed_result=parsed_result["Output"],
                                                                  file_path = performance_file_root_dir,
                                                                  file_name = perf_file_name
                                                                  )
            time.sleep(10)

        except Exception as error:
           sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


# ********************************************************************************************************************


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_sdk_advertise_non_connectable_power_0dBm_C20657(firmware_loader, power_meter, wifi_dut, ble_client, sl_collections, request, performance_data, custom_performance_fixture):
    """ Verify BLE Undirected Non-Connectable Advertisement"""
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_ble_advertise_non_connectable_power{int(time.time())}.log",
    ) as bt_logs:
        try:
            dut = UtfConfig.instance().defaults.get("dut", {})
            logger().info(f"dut: {dut}")
            if dut != "si917_ncp_sl_wifi":
                logger().info(f"M4-TA secure handshake")
                wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
            logger().info("Initializing BLE")
            # Set up DUT for BLE advertising
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=3, bond_info=0, set_smp=1, timeout=10)
            logger().info("configure bt local name....")
            wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name='SILABS_DEVICE')
            logger().info(f"Setting Adv Data")
            wifi_dut.interfaces.wifi.ble_set_adv_data(ble_advertising_data="123456789011234567")
            logger().info(f"fetch the local name")
            wifi_dut.interfaces.wifi.bt_get_local_name()
            logger().info("Advertising DUT ")
            logger().info("keeping the DUT in undirected_non_connectable_adv mode")
            wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=131, ble_adv_int_min=2048, ble_adv_int_max=2048,
                                                           ble_adv_channel_map=7)
            logger().info("Initiating power save")
            
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                   psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            
            wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            
            logger().info("Initiating scanning from Remote remote device")
            # Begin Scanning for BLE devices
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=bt_dut_address
            )
            assert bt_client_address is not None, "Unable to fetch bluetooth address from remote device"
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
            ), "Expected avd type not found bt mon logs"
            logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")
            time.sleep(5)
            pm_obj = Power_Measurement_Thread(power_meter=power_meter)

            if dut != "si917_ncp_sl_wifi":
                m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
                m4_obj.start()
                time.sleep(2)

            pm_obj.start()
            pm_obj.wait_for_exit()

            if dut != "si917_ncp_sl_wifi":
                m4_obj.wait_for_exit()
            
            parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
            __print_throughput(parsed_result)
            assert parsed_result["Output"] is not None
            performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name, 
                                                                  opn=opn, 
                                                                  build_number=build_number,
                                                                  memory_configuration="test_352K_M4SS_320K",
                                                                  parsed_result=parsed_result["Output"],
                                                                  file_path = performance_file_root_dir,
                                                                  file_name = perf_file_name
                                                                  )
            time.sleep(10)

        except Exception as error:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


# ********************************************************************************************************************


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_sdk_advertise_1sec_connectable_power_0dBm_C537352(firmware_loader, power_meter, wifi_dut, ble_client, sl_collections, request, performance_data, custom_performance_fixture):
    """ Verify BLE Undirected Connectable advertisement """
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_ble_advertise_connectable_power_{int(time.time())}.log",
    ) as bt_logs:
        try:
            dut = UtfConfig.instance().defaults.get("dut", {})
            logger().info(f"dut: {dut}")
            if dut != "si917_ncp_sl_wifi":
                logger().info(f"M4-TA secure handshake")
                wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
            logger().info("Initializing BLE")
            # Set up DUT for BLE advertising
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=3, bond_info=0, set_smp=1, timeout=10)
            logger().info("configure bt local name....")
            wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name='SILABS_DEVICE')
            logger().info(f"Setting Adv Data")
            wifi_dut.interfaces.wifi.ble_set_adv_data(ble_advertising_data="123456789011234567")
            logger().info(f"fetch the local name")
            wifi_dut.interfaces.wifi.bt_get_local_name()
            logger().info("Advertising DUT ")
            logger().info("keeping the DUT in undirected_connectable ADV mode")
            wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128, ble_adv_int_min=1600, ble_adv_int_max=1600,
                                                           ble_adv_channel_map=7)
            logger().info("Enabling power save")
            
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                   psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            
            wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            
            logger().info("Initiating scan from remote BLE device")
            # Begin Scanning for BLE devices
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=bt_dut_address
            )
            assert bt_client_address is not None, "Unable to fetch remote bluetooth address"
            scan_result = device_scan_result()
            device_found = scan_result.check_for_devices_in_scanned_results(ble_client=ble_client,
                                                                            bt_dut_address=bt_dut_address,
                                                                            adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
            logger().info("Initiating stop scanning from remote device")
            ble_client.interfaces.bluetooth.stop_scanning()
            assert device_found, "Dut not found in scan results"
            logger().info(f"Getting Remote BLE characteristics by passing address "
                          f"{wifi_dut.interfaces.wifi.ble_address} from BTmon logs")

            bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)

            logger().info(f"fetched data from bt mon {bt_logs.device_adv_type}")

            assert "Connectable undirected - ADV_IND (0x00)" in bt_logs.device_adv_type, \
                "Expected adv type not found in bt mon logs"
            logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")
            time.sleep(5)
            pm_obj = Power_Measurement_Thread(power_meter=power_meter)
            if dut != "si917_ncp_sl_wifi":
                m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
                m4_obj.start()
                time.sleep(2)

            pm_obj.start()
            pm_obj.wait_for_exit()

            if dut != "si917_ncp_sl_wifi":
                m4_obj.wait_for_exit()
            
            parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
            __print_throughput(parsed_result)
            assert parsed_result["Output"] is not None
            performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name, 
                                                                  opn=opn, 
                                                                  build_number=build_number,
                                                                  memory_configuration="test_352K_M4SS_320K",
                                                                  parsed_result=parsed_result["Output"],
                                                                  file_path = performance_file_root_dir,
                                                                  file_name = perf_file_name
                                                                  )
            time.sleep(10)
        except Exception as error:
           sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


# ********************************************************************************************************************


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_sdk_advertise_1sec_non_connectable_power_0dBm_C537353(firmware_loader, power_meter, wifi_dut, ble_client, sl_collections, request, performance_data, custom_performance_fixture):
    """ Verify BLE Undirected Non-Connectable Advertisement"""
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_ble_advertise_non_connectable_power{int(time.time())}.log",
    ) as bt_logs:
        try:
            dut = UtfConfig.instance().defaults.get("dut", {})
            logger().info(f"dut: {dut}")
            if dut != "si917_ncp_sl_wifi":
                logger().info(f"M4-TA secure handshake")
                wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
            logger().info("Initializing BLE")
            # Set up DUT for BLE advertising
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=3, bond_info=0, set_smp=1, timeout=10)
            logger().info("configure bt local name....")
            wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name='SILABS_DEVICE')
            logger().info(f"Setting Adv Data")
            wifi_dut.interfaces.wifi.ble_set_adv_data(ble_advertising_data="123456789011234567")
            logger().info(f"fetch the local name")
            wifi_dut.interfaces.wifi.bt_get_local_name()
            logger().info("Advertising DUT ")
            logger().info("keeping the DUT in undirected_non_connectable_adv mode")
            wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=131, ble_adv_int_min=1600, ble_adv_int_max=1600,
                                                           ble_adv_channel_map=7)
            logger().info("Initiating power save")
            
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                   psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            
            wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            
            logger().info("Initiating scanning from Remote remote device")
            # Begin Scanning for BLE devices
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=bt_dut_address
            )
            assert bt_client_address is not None, "Unable to fetch bluetooth address from remote device"
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
            ), "Expected avd type not found bt mon logs"
            logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")
            time.sleep(5)
            pm_obj = Power_Measurement_Thread(power_meter=power_meter)
            if dut != "si917_ncp_sl_wifi":
                m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
                m4_obj.start()
                time.sleep(2)

            pm_obj.start()
            pm_obj.wait_for_exit()

            if dut != "si917_ncp_sl_wifi":
                m4_obj.wait_for_exit()
            time.sleep(10)

        except Exception as error:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


# ********************************************************************************************************************


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid ,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES  | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_ble_sdk_connect_with_200ms_0dBm_C20659(firmware_loader, power_meter, wifi_dut, ble_client, sl_collections, request, performance_data, custom_performance_fixture):
    """Verify ble connection with 200ms"""
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_ble_connection_C20659_power{int(time.time())}.log",
    ) as bt_logs:
        try:
            dut = UtfConfig.instance().defaults.get("dut", {})
            logger().info(f"dut: {dut}")
            if dut != "si917_ncp_sl_wifi":
                logger().info(f"M4-TA secure handshake")
                wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
            conn_params = {"min_conn_interval": 0xa0,
                           "max_conn_interval": 0xa0,
                           "conn_latency": 0,
                           "supervision_timeout": 3200}
            logger().info("Initializing BLE")
            # Set up DUT for BLE advertising
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=3, bond_info=0, set_smp=1, timeout=10)
            logger().info("configure bt local name....")
            wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name='Silabsautomation')
            logger().info(f"fetch the local name")
            wifi_dut.interfaces.wifi.bt_get_local_name()
            logger().info("Advertising DUT ")
            wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128, ble_adv_int_min=2048, ble_adv_int_max=2048,
                                                           ble_adv_channel_map=7)
            logger().info("Initiating power save")
            
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            
            wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")

            logger().info("Initiating scan from remote device")
            # Begin Scanning for BLE devices
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=bt_dut_address
            )
            assert bt_client_address is not None, "Unable to fetch BD address from remote BLE device"
            scan_result = device_scan_result()
            device_found = scan_result.check_for_devices_in_scanned_results(ble_client=ble_client,
                                                                            bt_dut_address=bt_dut_address,
                                                                            adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
            assert device_found, "DUT not found in scan results"
            logger().info("initiating stop scanning")
            ble_client.interfaces.bluetooth.stop_scanning()
            time.sleep(5)
            logger().info("Initiating connection from remote device")
            ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address,
                                                    min_conn_interval=conn_params["min_conn_interval"],
                                                    max_conn_interval=conn_params["max_conn_interval"],
                                                    conn_latency=conn_params["conn_latency"],
                                                    supervision_timeout=conn_params["supervision_timeout"])
            time.sleep(60)
            logger().info("Checking connection status of BLE")
            state = wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
            ble_conn_config = bt_logs.read_ble_connection_params(conn_params)
            logger().info(f"**********{ble_conn_config} values in btmon logs")
            assert ble_conn_config["Status"] == "Success"
            assert (
                    ble_conn_config["max_conn_interval"]
                    == conn_params["max_conn_interval"]
            )
            time.sleep(5)
            logger().info(f"found connection intervals of 200ms in btmon logs")
            pm_obj = Power_Measurement_Thread(power_meter=power_meter)
            if dut != "si917_ncp_sl_wifi":
                m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
                m4_obj.start()
                time.sleep(2)

            pm_obj.start()
            pm_obj.wait_for_exit()

            if dut != "si917_ncp_sl_wifi":
                m4_obj.wait_for_exit()
            
            parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
            __print_throughput(parsed_result)
            assert parsed_result["Output"] is not None
            performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name, 
                                                                  opn=opn, 
                                                                  build_number=build_number,
                                                                  memory_configuration="test_352K_M4SS_320K",
                                                                  parsed_result=parsed_result["Output"],
                                                                  file_path = performance_file_root_dir,
                                                                  file_name = perf_file_name
                                                                  )
            time.sleep(10)
            logger().info("Initiating disconnection from remote device")
            ble_client.interfaces.bluetooth.disconnect(wifi_dut.interfaces.wifi.ble_address)
            time.sleep(5)

        except Exception as error:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


# ********************************************************************************************************************


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode |  Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid ,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_ble_sdk_connect_with_1_28s_0dBm_C20660(firmware_loader, power_meter, wifi_dut, nrf_ble_client, sl_collections, request, performance_data, custom_performance_fixture):
    """Verify ble connection with 1.28s """
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_ble_connection_C20660_power{int(time.time())}.log",
    ) as bt_logs:
        try:
            dut = UtfConfig.instance().defaults.get("dut", {})
            logger().info(f"dut: {dut}")
            if dut != "si917_ncp_sl_wifi":
                logger().info(f"M4-TA secure handshake")
                wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
            device_found = None
            logger().info("Initializing BLE")
            # Set up DUT for BLE advertising
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=3, bond_info=0, set_smp=0, timeout=10)
            logger().info("configure bt local name....")
            wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name='Silabsautomation')
            logger().info(f"fetch the local name")
            wifi_dut.interfaces.wifi.bt_get_local_name()
            logger().info("Advertising DUT ")
            wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128, ble_adv_int_min=2048, ble_adv_int_max=2048,
                                                           ble_adv_channel_map=7)
            logger().info("Initiating power save")
            
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                   psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            
            wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            
            logger().info("Initiating scan from remote device")
            # Begin Scanning for BLE devices
            nrf_ble_client.interfaces.bluetooth.start_scanning()
            found_devices = nrf_ble_client.interfaces.bluetooth.get_devices()
            logger().info(f"\n\nFound devices: {found_devices}")
            assert str(bt_dut_address) in found_devices
            nrf_ble_client.interfaces.bluetooth.stop_scanning()
            time.sleep(5)
            logger().info("Initiating connection from remote device")
            
            nrf_ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address)

            nrf_ble_client.interfaces.bluetooth.set_peer_connection_parameters(min_connection_interval=1280,
                                                                                max_connection_interval=1280,
                                                                                connection_timeout=3200,
                                                                                slave_latency=0)

            time.sleep(10)

            logger().info("Checking connection status of BLE")
            state = wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
            
            pm_obj = Power_Measurement_Thread(power_meter=power_meter)
            if dut != "si917_ncp_sl_wifi":
                m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
                m4_obj.start()
                time.sleep(2)

            pm_obj.start()
            pm_obj.wait_for_exit()

            if dut != "si917_ncp_sl_wifi":
                m4_obj.wait_for_exit()
            
            parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
            __print_throughput(parsed_result)
            assert parsed_result["Output"] is not None
            performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name, 
                                                                  opn=opn, 
                                                                  build_number=build_number,
                                                                  memory_configuration="test_352K_M4SS_320K",
                                                                  parsed_result=parsed_result["Output"],
                                                                  file_path = performance_file_root_dir,
                                                                  file_name = perf_file_name
                                                                  )
            time.sleep(10)
            logger().info("Initiating disconnection from remote device")
            nrf_ble_client.interfaces.bluetooth.disconnect(wifi_dut.interfaces.wifi.ble_address)
            time.sleep(5)
        except Exception as error:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


# ********************************************************************************************************************


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid ,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX_HIGH,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "enable_ble_power_index_params": 1,
            "power_index": 63,
        },
    )
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_ble_sdk_connect_with_200ms_7p5dBm_C20661(firmware_loader, power_meter, wifi_dut, ble_client, sl_collections, request, performance_data, custom_performance_fixture):
    """Verify ble connection with 200ms"""
    with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_ble_connection_C20661_power{int(time.time())}.log",
    ) as bt_logs:
        try:
            dut = UtfConfig.instance().defaults.get("dut", {})
            logger().info(f"dut: {dut}")
            if dut != "si917_ncp_sl_wifi":
                logger().info(f"M4-TA secure handshake")
                wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
            device_found = None
            logger().info("Initializing BLE")
            # Set up DUT for BLE advertising
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=3, bond_info=0, set_smp=1, timeout=10)
            logger().info("configure bt local name....")
            wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name='Silabsautomation')
            logger().info(f"fetch the local name")
            wifi_dut.interfaces.wifi.bt_get_local_name()
            logger().info("Advertising DUT ")
            wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128, ble_adv_int_min=2048, ble_adv_int_max=2048,
                                                           ble_adv_channel_map=7)
            logger().info("Initiating power save")
            
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                   psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            
            wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            
            logger().info("Initiating scan from remote device")
            # Begin Scanning for BLE devices
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=bt_dut_address
            )
            assert bt_client_address is not None, "Unable to fetch BD address from remote BLE device"
            scan_result = device_scan_result()
            device_found = scan_result.check_for_devices_in_scanned_results(ble_client=ble_client,
                                                                            bt_dut_address=bt_dut_address,
                                                                            adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
            assert device_found, "DUT not found in scan results"
            logger().info("initiating stop scanning")
            ble_client.interfaces.bluetooth.stop_scanning()
            assert device_found, "DUT not found in scan results"
            logger().info("Initiating connection from remote device")
            logger().info("Initiating connection from remote device")
            conn_params = {"min_conn_interval": 0xa0,
                           "max_conn_interval": 0xa0,
                           "conn_latency": 0,
                           "supervision_timeout": 3200}
            ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address,
                                                    min_conn_interval=conn_params["min_conn_interval"],
                                                    max_conn_interval=conn_params["max_conn_interval"],
                                                    conn_latency=conn_params["conn_latency"],
                                                    supervision_timeout=conn_params["supervision_timeout"])
            time.sleep(60)
            logger().info("Checking connection status of BLE")
            state = wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
            ble_conn_config = bt_logs.read_ble_connection_params(conn_params)
            logger().info(f"**********{ble_conn_config} values in btmon logs")
            assert ble_conn_config["Status"] == "Success"
            assert (
                    ble_conn_config["max_conn_interval"]
                    == conn_params["max_conn_interval"]
            )
            logger().info(f"found connection intervals of 200ms in btmon logs")

            time.sleep(5)
            pm_obj = Power_Measurement_Thread(power_meter=power_meter)
            if dut != "si917_ncp_sl_wifi":
                m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
                m4_obj.start()
                time.sleep(2)

            pm_obj.start()
            pm_obj.wait_for_exit()

            if dut != "si917_ncp_sl_wifi":
                m4_obj.wait_for_exit()
            
            parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
            __print_throughput(parsed_result)
            assert parsed_result["Output"] is not None
            performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name, 
                                                                  opn=opn, 
                                                                  build_number=build_number,
                                                                  memory_configuration="test_352K_M4SS_320K",
                                                                  parsed_result=parsed_result["Output"],
                                                                  file_path = performance_file_root_dir,
                                                                  file_name = perf_file_name
                                                                  )
            time.sleep(10)
            logger().info("Initiating disconnection from remote device")
            ble_client.interfaces.bluetooth.disconnect(wifi_dut.interfaces.wifi.ble_address)
            time.sleep(5)

        except Exception as error:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


# ********************************************************************************************************************


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid ,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX_63,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_ble_sdk_connect_with_1_28s_7p5dBm_C20662(firmware_loader, power_meter, wifi_dut, nrf_ble_client, sl_collections, request, performance_data, custom_performance_fixture):
    """Verify ble connection with 1.28s """
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_ble_connection_C20660_power{int(time.time())}.log",
    ) as bt_logs:
        try:
            dut = UtfConfig.instance().defaults.get("dut", {})
            logger().info(f"dut: {dut}")
            if dut != "si917_ncp_sl_wifi":
                logger().info(f"M4-TA secure handshake")
                wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
            device_found = None
            logger().info("Initializing BLE")
            # Set up DUT for BLE advertising
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=3, bond_info=0, set_smp=0, timeout=10)
            logger().info("configure bt local name....")
            wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name='Silabsautomation')
            logger().info(f"fetch the local name")
            wifi_dut.interfaces.wifi.bt_get_local_name()
            logger().info("Advertising DUT ")
            wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128, ble_adv_int_min=2048, ble_adv_int_max=2048,
                                                           ble_adv_channel_map=7)
            logger().info("Initiating power save")
            
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                   psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            
            wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            
            logger().info("Initiating scan from remote device")
            # Begin Scanning for BLE devices
            nrf_ble_client.interfaces.bluetooth.start_scanning()
            found_devices = nrf_ble_client.interfaces.bluetooth.get_devices()
            logger().info(f"\n\nFound devices: {found_devices}")
            assert str(bt_dut_address) in found_devices
            nrf_ble_client.interfaces.bluetooth.stop_scanning()
            time.sleep(5)
            logger().info("Initiating connection from remote device")
            
            nrf_ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address)

            nrf_ble_client.interfaces.bluetooth.set_peer_connection_parameters(min_connection_interval=1280,
                                                                                max_connection_interval=1280,
                                                                                connection_timeout=3200,
                                                                                slave_latency=0)

            time.sleep(10)

            logger().info("Checking connection status of BLE")
            state = wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
            
            pm_obj = Power_Measurement_Thread(power_meter=power_meter)
            if dut != "si917_ncp_sl_wifi":
                m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
                m4_obj.start()
                time.sleep(2)

            pm_obj.start()
            pm_obj.wait_for_exit()

            if dut != "si917_ncp_sl_wifi":
                m4_obj.wait_for_exit()
            
            parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
            __print_throughput(parsed_result)
            assert parsed_result["Output"] is not None
            performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name, 
                                                                  opn=opn, 
                                                                  build_number=build_number,
                                                                  memory_configuration="test_352K_M4SS_320K",
                                                                  parsed_result=parsed_result["Output"],
                                                                  file_path = performance_file_root_dir,
                                                                  file_name = perf_file_name
                                                                  )
            time.sleep(10)
            logger().info("Initiating disconnection from remote device")
            nrf_ble_client.interfaces.bluetooth.disconnect(wifi_dut.interfaces.wifi.ble_address)
            time.sleep(5)
        except Exception as error:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


# ********************************************************************************************************************


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_sdk_advertise_non_connectable_power_1065ms_C20654(firmware_loader, power_meter, wifi_dut, ble_client, sl_collections, request, performance_data, custom_performance_fixture):
    "To verify with non-connectable mode , with 1065 min and max advertising intervals"
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"./test_ble_non_advertise_connectable_power_C20654_{int(time.time())}.log",
    ) as bt_logs:
        try:
            dut = UtfConfig.instance().defaults.get("dut", {})
            logger().info(f"dut: {dut}")
            ble_advertising_data = 'SILABS_DEVICE123'
            ble_adv_type = 131
            logger().info("Initializing BLE")
            # Set up DUT for BLE advertising
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=3, bond_info=0, set_smp=1, timeout=10)
            logger().info("configure bt local name....")
            wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name='SILABS_DEVICE123')
            logger().info(f"fetch the local name")
            wifi_dut.interfaces.wifi.bt_get_local_name()
            logger().info("Advertising DUT ")
            logger().info("keeping the DUT in undirected_connectable ADV mode")
            wifi_dut.interfaces.wifi.ble_start_advertising(ble_advertising_data=ble_advertising_data,
                                                           ble_adv_type=ble_adv_type,
                                                           ble_adv_int_min=1704, ble_adv_int_max=1704,
                                                           ble_adv_channel_map=7)

            logger().info("Enabling power save")
            
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                   psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            
            wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            
            logger().info("Initiating scan from remote BLE device")
            # Begin Scanning for BLE devices
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=bt_dut_address
            )
            assert bt_client_address is not None, "Unable to fetch remote bluetooth address"
            scan_result = device_scan_result()

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

            assert "Non connectable undirected - ADV_NONCONN_IND (0x03)" in bt_logs.device_adv_type, \
                "Expected adv type not found in bt mon logs"
            logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")

            time.sleep(5)
            pm_obj = Power_Measurement_Thread(power_meter=power_meter)
            if dut != "si917_ncp_sl_wifi":
                m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
                m4_obj.start()
                time.sleep(2)

            pm_obj.start()
            pm_obj.wait_for_exit()

            if dut != "si917_ncp_sl_wifi":
                m4_obj.wait_for_exit()
            time.sleep(10)
        except Exception as error:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


# ********************************************************************************************************************


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_sdk_advertise_connectable_power_20ms_C20653(firmware_loader, power_meter, wifi_dut, ble_client, sl_collections, request, performance_data, custom_performance_fixture):
    "To verify with connectable mode , with 20ms min and max advertising intervals"
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"./test_ble_advertise_connectable_power_C20653_{int(time.time())}.log",
    ) as bt_logs:
        try:
            dut = UtfConfig.instance().defaults.get("dut", {})
            logger().info(f"dut: {dut}")
            ble_advertising_data = 'Silabsautomation'
            ble_adv_type = 131
            logger().info("Initializing BLE")
            # Set up DUT for BLE advertising
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=3, bond_info=0, set_smp=1, timeout=10)
            logger().info("configure bt local name....")
            wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name='Silabsautomation')
            logger().info(f"fetch the local name")
            wifi_dut.interfaces.wifi.bt_get_local_name()
            logger().info("Advertising DUT ")
            logger().info("keeping the DUT in undirected_connectable ADV mode")
            wifi_dut.interfaces.wifi.ble_start_advertising(ble_advertising_data=ble_advertising_data,
                                                           ble_adv_type=ble_adv_type,
                                                           ble_adv_int_min=32, ble_adv_int_max=32,
                                                           ble_adv_channel_map=7)
            logger().info("Enabling power save")
            
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                   psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            
            wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            
            logger().info("Initiating scan from remote BLE device")
            # Begin Scanning for BLE devices
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=bt_dut_address
            )
            assert bt_client_address is not None, "Unable to fetch remote bluetooth address"
            scan_result = device_scan_result()
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

            assert "Non connectable undirected - ADV_NONCONN_IND (0x03)" in bt_logs.device_adv_type, \
                "Expected adv type not found in bt mon logs"
            logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")
            time.sleep(5)
            pm_obj = Power_Measurement_Thread(power_meter=power_meter)
            if dut != "si917_ncp_sl_wifi":
                m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
                m4_obj.start()
                time.sleep(2)

            pm_obj.start()
            pm_obj.wait_for_exit()

            if dut != "si917_ncp_sl_wifi":
                m4_obj.wait_for_exit()
            time.sleep(10)

        except Exception as error:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


# ********************************************************************************************************************


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid ,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX_HIGH,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "enable_ble_power_index_params": 1,
            "power_index": 63,
        },
    )
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_ble_sdk_advertise_connectable_power_7p5dBm_C20658(firmware_loader, power_meter, wifi_dut, ble_client, sl_collections, request, performance_data, custom_performance_fixture):
    "To verify with connectable mode with Max Tx power of 4dBm"
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"./test_ble_advertise_connectable_power_C20658_{int(time.time())}.log",
    ) as bt_logs:
        try:
            dut = UtfConfig.instance().defaults.get("dut", {})
            logger().info(f"dut: {dut}")
            device_found = None
            logger().info("Initializing BLE")
            # Set up DUT for BLE advertising
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=3, bond_info=0, set_smp=1, timeout=10)
            logger().info("configure bt local name....")
            wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name='SILABS_DEVICE')
            logger().info(f"Setting Adv Data")
            wifi_dut.interfaces.wifi.ble_set_adv_data(ble_advertising_data="SILABS_DEVICE")
            logger().info("keeping the DUT in undirected_connectable ADV mode")
            wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128, ble_adv_int_min=2048, ble_adv_int_max=2048,
                                                           ble_adv_channel_map=7)
            logger().info("Enabling power save")
            
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                   psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            
            wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            
            logger().info("Initiating scan from remote BLE device")
            # Begin Scanning for BLE devices
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=bt_dut_address
            )
            assert bt_client_address is not None, "Unable to fetch remote bluetooth address"
            scan_result = device_scan_result()
            device_found = scan_result.check_for_devices_in_scanned_results(ble_client=ble_client,
                                                                            bt_dut_address=bt_dut_address,
                                                                            adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
            assert device_found, "DUT not found in scan results"
            logger().info("Initiating stop scanning from remote device")
            ble_client.interfaces.bluetooth.stop_scanning()
            assert device_found, "Dut not found in scan results"
            logger().info(f"Getting Remote BLE characteristics by passing address "
                          f"{wifi_dut.interfaces.wifi.ble_address} from BTmon logs")
            bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)
            logger().info(f"fetched data from bt mon {bt_logs.device_adv_type}")
            assert "Connectable undirected - ADV_IND (0x00)" in bt_logs.device_adv_type, \
                "Expected adv type not found in bt mon logs"
            logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")
            time.sleep(5)
            pm_obj = Power_Measurement_Thread(power_meter=power_meter)
            if dut != "si917_ncp_sl_wifi":
                m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
                m4_obj.start()
                time.sleep(2)

            pm_obj.start()
            pm_obj.wait_for_exit()

            if dut != "si917_ncp_sl_wifi":
                m4_obj.wait_for_exit()
            time.sleep(10)
            time.sleep(10)
        except Exception as error:
            sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


# ********************************************************************************************************************


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
def test_ble_sdk_per_1mbps_tx_LP_CHAIN_0dBm_C20663(firmware_loader, power_meter, bt_dut, sl_collections, request, performance_data, custom_performance_fixture):
    "Verify BLE Active_2.4G 1Mbps Tx-0dBm_LP Chain"
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
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
    try:
        dut = UtfConfig.instance().defaults.get("dut", {})
        logger().info(f"dut: {dut}")
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
        time.sleep(5)
        pm_obj = Power_Measurement_Thread(power_meter=power_meter)
        if dut != "si917_ncp_sl_wifi":
                
                m4_obj = M4_Sleep_Thread(wifi_dut=bt_dut)
                m4_obj.start()
                time.sleep(2)

        pm_obj.start()
        pm_obj.wait_for_exit()

        if dut != "si917_ncp_sl_wifi":
            m4_obj.wait_for_exit()
        
        parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
        __print_throughput(parsed_result)
        assert parsed_result["Output"] is not None
        performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name, 
                                                              opn=opn, 
                                                              build_number=build_number,
                                                              memory_configuration="test_352K_M4SS_320K",
                                                              parsed_result=parsed_result["Output"],
                                                              file_path = performance_file_root_dir,
                                                              file_name = perf_file_name
                                                              )
        time.sleep(10)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=bt_dut, exception=error)


# ********************************************************************************************************************


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features":  Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
def test_ble_sdk_per_2mbps_tx_HP_CHAIN_0dBm_C564142(firmware_loader, power_meter, bt_dut, sl_collections, request, performance_data, custom_performance_fixture):
    "Verify BLE Active_2.4G 1Mbps Tx-0dBm_LP Chain"
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    cmd_ix = 0x13
    access_addr = 1903575337
    pkt_len = 240
    phy_rate = 2
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
    rf_chain = 2
    cmd_type = 8
    try:
        dut = UtfConfig.instance().defaults.get("dut", {})
        logger().info(f"dut: {dut}")
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
        time.sleep(5)
        pm_obj = Power_Measurement_Thread(power_meter=power_meter)
        if dut != "si917_ncp_sl_wifi":
                m4_obj = M4_Sleep_Thread(wifi_dut=bt_dut)
                m4_obj.start()
                time.sleep(2)

        pm_obj.start()
        pm_obj.wait_for_exit()

        if dut != "si917_ncp_sl_wifi":
            m4_obj.wait_for_exit()
        
        parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
        __print_throughput(parsed_result)
        assert parsed_result["Output"] is not None
        performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name, 
                                                              opn=opn, 
                                                              build_number=build_number,
                                                              memory_configuration="test_352K_M4SS_320K",
                                                              parsed_result=parsed_result["Output"],
                                                              file_path = performance_file_root_dir,
                                                              file_name = perf_file_name
                                                              )
        time.sleep(10)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=bt_dut, exception=error)


# ********************************************************************************************************************


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX_HIGH,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
def test_ble_sdk_per_1mbps_tx_LP_CHAIN_7p5dBm_C20664(firmware_loader, power_meter, bt_dut, sl_collections, request, performance_data, custom_performance_fixture):
    """Verify BLE Active_2.4G 1Mbps Tx-10dBm_LP Chain"""
    cmd_ix = 0x13
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
    try:
        dut = UtfConfig.instance().defaults.get("dut", {})
        logger().info(f"dut: {dut}")
        logger().info("get dut bt address.....")
        bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
        logger().info(f'bt dut address {bt_dut_address}')
        logger().info("configure bt local name....")
        bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name='SILABS_BLE')
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
        time.sleep(5)
        pm_obj = Power_Measurement_Thread(power_meter=power_meter)
        if dut != "si917_ncp_sl_wifi":
                m4_obj = M4_Sleep_Thread(wifi_dut=bt_dut)
                m4_obj.start()
                time.sleep(2)

        pm_obj.start()
        pm_obj.wait_for_exit()

        if dut != "si917_ncp_sl_wifi":
            m4_obj.wait_for_exit()
        
        parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
        __print_throughput(parsed_result)
        assert parsed_result["Output"] is not None
        performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name, 
                                                              opn=opn, 
                                                              build_number=build_number,
                                                              memory_configuration="test_352K_M4SS_320K",
                                                              parsed_result=parsed_result["Output"],
                                                              file_path = performance_file_root_dir,
                                                              file_name = perf_file_name
                                                              )
        time.sleep(10)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=bt_dut, exception=error)


# ********************************************************************************************************************


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
def test_ble_sdk_connect_with_idlelink_200ms_C20655(firmware_loader, power_meter, wifi_dut, ble_client, sl_collections, request, performance_data, custom_performance_fixture):
    """BLE_2.4G Idle-link connection,200ms. (empty packet, 0 bytes)"""
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    try:
        dut = UtfConfig.instance().defaults.get("dut", {})
        logger().info(f"dut: {dut}")
        logger().info("Initializing BLE")
        # Set up DUT for BLE advertising
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start(capability=3, bond_info=0, set_smp=1, timeout=10)
        logger().info("configure bt local name....")
        wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name='A')
        logger().info("Advertising DUT ")
        wifi_dut.interfaces.wifi.ble_start_advertising(ble_advertising_data="a", ble_adv_type=128, ble_adv_int_min=2048,
                                                       ble_adv_int_max=2048, ble_adv_channel_map=7)
        logger().info("Initiating power save")
        
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                               psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        
        wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")

        logger().info("Initiating scan from remote device")
        # Begin Scanning for BLE devices
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address
        )
        assert bt_client_address is not None, "Unable to fetch BD address from remote BLE device"
        scan_result = device_scan_result()
        device_found = scan_result.check_for_devices_in_scanned_results(ble_client=ble_client,
                                                                        bt_dut_address=bt_dut_address,
                                                                        adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
        assert device_found, "DUT not found in scan results"
        logger().info("initiating stop scanning")
        ble_client.interfaces.bluetooth.stop_scanning()
        logger().info("Initiating connection from remote device")
        ble_client.interfaces.bluetooth.connect(bt_dut_address, min_conn_interval=0xa0,
                                                max_conn_interval=0xa0, conn_latency=0,
                                                supervision_timeout=3200)
        time.sleep(5)
        pm_obj = Power_Measurement_Thread(power_meter=power_meter)
        if dut != "si917_ncp_sl_wifi":
                m4_obj = M4_Sleep_Thread(wifi_dut=wifi_dut)
                m4_obj.start()
                time.sleep(2)

        pm_obj.start()
        pm_obj.wait_for_exit()

        if dut != "si917_ncp_sl_wifi":
            m4_obj.wait_for_exit()
        
        parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
        __print_throughput(parsed_result)
        assert parsed_result["Output"] is not None
        performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name, 
                                                              opn=opn, 
                                                              build_number=build_number,
                                                              memory_configuration="test_352K_M4SS_320K",
                                                              parsed_result=parsed_result["Output"],
                                                              file_path = performance_file_root_dir,
                                                              file_name = perf_file_name
                                                              )
        time.sleep(10)
        logger().info("Initiating disconnection from remote device")
        ble_client.interfaces.bluetooth.disconnect(wifi_dut.interfaces.wifi.ble_address)
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


# ********************************************************************************************************************


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features":  Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
def test_ble_sdk_per_1mbps_rx_LP_CHAIN_C20665(firmware_loader, power_meter, bt_dut, sl_collections, request, performance_data, custom_performance_fixture):
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    cmd_ix = 0x13
    access_addr = 1903575337
    ext_data_len_indication = 1
    loop_back_mode = 0
    duty_cycling_en = 0
    phy_rate = 1
    ant_sel = 2
    rf_type = 1
    pll_mode = 0
    rf_chain = 3
    cmd_type = 8
    config = "\"10 10 0 1 0\""
    try:
        dut = UtfConfig.instance().defaults.get("dut", {})
        logger().info(f"dut: {dut}")
        logger().info("get dut bt address.....")
        bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
        logger().info(f'bt dut address {bt_dut_address}')
        logger().info("configure bt local name....")
        bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name='SILABS_BT')
        logger().info("get bt local name....")
        bt_dut.interfaces.bluetooth.bt_get_local_name()
        bt_dut.interfaces.bluetooth.ble_per_receive(cmd_ix=cmd_ix,
                                                    receive_enable=1,
                                                    access_addr=access_addr,
                                                    phy_rate=phy_rate,
                                                    config = config,
                                                    ant_sel=ant_sel,
                                                    pll_mode=pll_mode,
                                                    rf_type=rf_type,
                                                    rf_chain=rf_chain,
                                                    ext_data_len_indication=ext_data_len_indication,
                                                    loop_back_mode=loop_back_mode,
                                                    duty_cycling_en=duty_cycling_en,
                                                    )
        time.sleep(10)
        logger().info("starting per stats")
        bt_dut.interfaces.bluetooth.get_bt_per_tx_stats(cmd_type=cmd_type)
        time.sleep(5)
        pm_obj = Power_Measurement_Thread(power_meter=power_meter)
        if dut != "si917_ncp_sl_wifi":
                m4_obj = M4_Sleep_Thread(wifi_dut=bt_dut)
                m4_obj.start()
                time.sleep(2)

        pm_obj.start()
        pm_obj.wait_for_exit()

        if dut != "si917_ncp_sl_wifi":
            m4_obj.wait_for_exit()
        
        parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
        __print_throughput(parsed_result)
        assert parsed_result["Output"] is not None
        performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name, 
                                                              opn=opn, 
                                                              build_number=build_number,
                                                              memory_configuration="test_352K_M4SS_320K",
                                                              parsed_result=parsed_result["Output"],
                                                              file_path = performance_file_root_dir,
                                                              file_name = perf_file_name
                                                              )
        time.sleep(10)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=bt_dut, exception=error)


# ********************************************************************************************************************


@pytest.mark.transform_test_results(
    TransformFileProperties(
        file_name="perf_power_consumption_medium.csv", data_type="power_performance"
    )
)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode | Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
def test_ble_sdk_per_125kbps_rx_LP_CHAIN_C20666(firmware_loader, power_meter, bt_dut, sl_collections, request, performance_data, custom_performance_fixture):
    "Verify BLE Active_2.4G 1Mbps Tx-0dBm_LP Chain"
    performance_file_root_dir, perf_file_name = custom_performance_fixture
    obtained_test_name = request.node.name
    test_name = obtained_test_name.split('[')[0] if obtained_test_name and '[' in obtained_test_name else obtained_test_name

    opn = UtfConfig.instance().defaults.get("opn", {})
    build_number = UtfConfig.instance().defaults.get("build_number", {})
    cmd_ix = 0x13
    access_addr = 1903575337
    ext_data_len_indication = 1
    loop_back_mode = 0
    duty_cycling_en = 0
    phy_rate = 4
    ant_sel = 2
    rf_type = 1
    pll_mode = 0
    rf_chain = 3
    cmd_type = 8
    config = "\"10 10 0 1 0\""
    try:
        dut = UtfConfig.instance().defaults.get("dut", {})
        logger().info(f"dut: {dut}")
        logger().info("get dut bt address.....")
        bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
        logger().info(f'bt dut address {bt_dut_address}')
        logger().info("configure bt local name....")
        bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name='SILABS_BT')
        logger().info("get bt local name....")
        bt_dut.interfaces.bluetooth.bt_get_local_name()
        bt_dut.interfaces.bluetooth.ble_per_receive(cmd_ix=cmd_ix,
                                                    receive_enable=1,
                                                    access_addr=access_addr,
                                                    phy_rate=phy_rate,
                                                    config=config,
                                                    ant_sel=ant_sel,
                                                    pll_mode=pll_mode,
                                                    rf_type=rf_type,
                                                    rf_chain=rf_chain,
                                                    ext_data_len_indication=ext_data_len_indication,
                                                    loop_back_mode=loop_back_mode,
                                                    duty_cycling_en=duty_cycling_en,)
        time.sleep(10)
        logger().info("starting per stats")
        bt_dut.interfaces.bluetooth.get_bt_per_tx_stats(cmd_type=cmd_type)
        time.sleep(5)
        pm_obj = Power_Measurement_Thread(power_meter=power_meter)
        if dut != "si917_ncp_sl_wifi":
                m4_obj = M4_Sleep_Thread(wifi_dut=bt_dut)
                m4_obj.start()
                time.sleep(2)

        pm_obj.start()
        pm_obj.wait_for_exit()

        if dut != "si917_ncp_sl_wifi":
            m4_obj.wait_for_exit()
        
        parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(power_meter.interfaces.power_meter.results)
        __print_throughput(parsed_result)
        assert parsed_result["Output"] is not None
        performance_data.interfaces.power_perf_data.generate_csv(test_name=test_name, 
                                                              opn=opn, 
                                                              build_number=build_number,
                                                              memory_configuration="test_352K_M4SS_320K",
                                                              parsed_result=parsed_result["Output"],
                                                              file_path = performance_file_root_dir,
                                                              file_name = perf_file_name
                                                              )
        time.sleep(10)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=bt_dut, exception=error)


# ********************************************************************************************************************
