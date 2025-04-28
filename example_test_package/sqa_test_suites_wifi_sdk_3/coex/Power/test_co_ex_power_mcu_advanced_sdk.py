import pytest
import time
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.utils.stopwatch import Stopwatch
from utf.utils import print_dict
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xOperatingMode,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xPowerSaveModes,
    Si91xJoinFeatureBitMap,
    Si91xPowerSaveProcedureTypes,
    Si91xRegion,
    Si91xRegionCode,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xModuleType,
)
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from random import randint
from utf.utils.thread_base import ThreadBase
import os
from utf.utf_config import UtfConfig
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.interfaces.power_meter.nrf_ppk2.nrf_power_profiler_mp import NRFPowerProfiler

""" Test Steps:
        1. Configure the DUT in Co-Ex mode for 2.4Ghz.
        2. Initiate the Scan from DUT.
        3. BLE Advertise, Connect with clock and with out clock
        4. Initiate the connection with third party Access Point.
        5. Measure current through power meter.
        6. Verify the power values.  

    setup requirement:
        1. DUT(SiWG917)
        2. Si-MB4002A
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Power Meter 

    Author: Benazeer K 
"""


def logger():
    return get_logger(__name__)


def __print_throughput(throughput: dict):
    if throughput is not None:
        print_dict("##     ", throughput)


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
            self.power_meter.interfaces.power_meter.init_power_meter(data_log_file_name=f"UTF1_Data_Log_{self.dtim}",
                                                                     data_log_stop_after_elapsed_time=self.capture_time)
        else:
            logger().info(f"initiating power meter")
            self.power_meter.interfaces.power_meter.init_power_meter(data_log_file_name=f"UTF1_Data_Log",
                                                                     data_log_stop_after_elapsed_time=self.capture_time)
        # Init power meter module

        self.power_meter.interfaces.power_meter.init_power_meter_module("data_logger")
        # set power meter out put channels
        logger().info(f"setting output channels")

        if dut == "si917_ncp_sl_wifi":
            self.power_meter.interfaces.power_meter.set_output_channels_settings(
                [{"channel": "1", "emulation_mode": "Current Measure", "trace_current": True, "trace_voltage": False,
                  "trace_power": False}])

        else:
            self.power_meter.interfaces.power_meter.set_output_channels_settings([{"channel": "1",
                                                                                   "emulation_mode": "2 Quadrant Power Supply",
                                                                                   "voltage": "3.3000",
                                                                                   "current_limit": "1.00000",
                                                                                   "voltage_slew": "MAX",
                                                                                   "voltage_meter_range": "Auto",
                                                                                   "current_meter_range": "Auto",
                                                                                   "trace_current": True,
                                                                                   "trace_power": True}])
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


class WlanThread(ThreadBase):

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, sl_collections=None,
                 dtim=10, listen_interval=0):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.dut_addr = None
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.dtim = dtim
        self.listen_interval = listen_interval
        self.device_ip = None

    def run(self):
        logger().info(f"Configuring Access Point with dtim : {self.dtim}")
        self.wifi_access_point.interfaces.wifi.start_ap(dtim=self.dtim)

        logger().info(f"Scanning and Connecting to Access Point")
        dictionary = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            associated=self.wifi_dut.interfaces.wifi.associated,
            listen_interval=self.listen_interval,
            power_save=False,
            retry_count=3
        )
        self.device_ip = dictionary['device_ip']
        time.sleep(2)
        logger().info("Enabling power save")

        self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                           psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

        self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")

    def getter(self):
        return self.device_ip


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
            self.wifi_dut.interfaces.wifi.m4_power_manager(sleep_time=self.m4_sleep_time)


class Power_Measurement_Thread(ThreadBase, Power_Device):

    def __init__(self, power_meter=None, capture_time=60):
        super().__init__()
        Power_Device().__init__()
        self.power_meter = power_meter
        self.capture_time = capture_time

    def run(self):
        logger().info(f"Starting Power Capture")
        self.power_device = UtfConfig.instance().defaults.get("power_meter", {})
        Power_Device.power_measurement(power_device=self.power_device, power_meter=self.power_meter,
                                       capture_time=self.capture_time)


class StandBy_Associated(ThreadBase):
    def __init__(self, dtim=None, wifi_dut=None, wifi_access_point=None, sl_collections=None, power_meter=None,
                 deep_sleep=False, dtim_aligned_type=1, remote_socket=None, send_data=False, capture_time=60,
                 m4_sleep_time=120000, bcast_filter=True, tcp_ka_time=240, send_ka=False, listen_case=False,
                 ble_client=None, ble_advertisement=None, ble_with_connection=None):
        self.dtim = dtim
        self.wifi_dut = wifi_dut
        self.sl_collections = sl_collections
        self.wifi_access_point = wifi_access_point
        self.power_meter = power_meter
        self.deep_sleep = deep_sleep
        self.remote_socket = remote_socket
        self.send_data = send_data
        self.send_ka = send_ka
        self.capture_time = capture_time
        self.m4_sleep_time = m4_sleep_time
        self.bcast_filter = bcast_filter
        self.tcp_ka_time = tcp_ka_time
        self.dtim_aligned_type = dtim_aligned_type
        self.listen_case = listen_case
        self.ble_client = ble_client
        self.ble_advertisement = ble_advertisement
        self.ble_with_connection = ble_with_connection

    def run(self):
        dut = UtfConfig.instance().defaults.get("dut", {})
        logger().info(f"dut: {dut}")

        if dut != "si917_ncp_sl_wifi":
            logger().info(f"M4-TA secure handshake")
            self.wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

        time.sleep(2)

        self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            interface='client',
            join_feature_bitmap=Si91xJoinFeatureBitMap.Default
        )

        if self.ble_advertisement:
            with BleLogs(
                    start_collecting_logs=True,
                    bt_log_path=f"reports/test_ble_advertise_connectable_power_{int(time.time())}.log",
            ) as bt_logs:
                try:
                    logger().info("Initializing BLE")
                    # Set up DUT for BLE advertising
                    self.wifi_dut.interfaces.wifi.ble_start(capability=3, bond_info=0, set_smp=1, timeout=10)
                    logger().info("configure bt local name....")
                    self.wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name='Silabsautomation')
                    logger().info(f"Setting Adv Data")
                    self.wifi_dut.interfaces.wifi.ble_set_adv_data(ble_advertising_data="123456789011234567")
                    logger().info(f"fetch the local name")
                    self.wifi_dut.interfaces.wifi.bt_get_local_name()
                    logger().info("Advertising DUT ")
                    logger().info("keeping the DUT in undirected_connectable ADV mode")
                    self.wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128, ble_adv_int_min=2048,
                                                                        ble_adv_int_max=2048,
                                                                        ble_adv_channel_map=7)
                    time.sleep(2)

                except Exception as error:
                    self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=error)

        if self.ble_with_connection:
            with BleLogs(
                    start_collecting_logs=True,
                    bt_log_path=f"reports/test_ble_connection_C20659_power{int(time.time())}.log",
            ) as bt_logs:
                try:
                    conn_params = {"min_conn_interval": 0xa0,
                                   "max_conn_interval": 0xa0,
                                   "conn_latency": 0,
                                   "supervision_timeout": 3200}
                    logger().info("Initializing BLE")
                    # Set up DUT for BLE advertising
                    bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start(capability=3, bond_info=0, set_smp=1,
                                                                             timeout=10)
                    logger().info("configure bt local name....")
                    self.wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name='Silabsautomation')
                    logger().info(f"fetch the local name")
                    self.wifi_dut.interfaces.wifi.bt_get_local_name()
                    logger().info("Advertising DUT ")
                    self.wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128, ble_adv_int_min=2048,
                                                                        ble_adv_int_max=2048,
                                                                        ble_adv_channel_map=7)
                    logger().info("Initiating scan from remote device")
                    # Begin Scanning for BLE devices
                    bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(
                        bt_dut_address=bt_dut_address
                    )
                    assert bt_client_address is not None, "Unable to fetch BD address from remote BLE device"
                    scan_result = device_scan_result()
                    device_found = scan_result.check_for_devices_in_scanned_results(ble_client=self.ble_client,
                                                                                    bt_dut_address=bt_dut_address,
                                                                                    adv_data=self.wifi_dut.interfaces.wifi.ble_advertising_data)
                    assert device_found, "DUT not found in scan results"
                    logger().info("initiating stop scanning")
                    self.ble_client.interfaces.bluetooth.stop_scanning()
                    time.sleep(5)
                    logger().info("Initiating connection from remote device")
                    self.ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address,
                                                                 min_conn_interval=conn_params["min_conn_interval"],
                                                                 max_conn_interval=conn_params["max_conn_interval"],
                                                                 conn_latency=conn_params["conn_latency"],
                                                                 supervision_timeout=conn_params["supervision_timeout"])
                    time.sleep(60)
                    logger().info("Checking connection status of BLE")
                    state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
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
                    time.sleep(2)

                except Exception as error:
                    self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=error)

        wlan_obj = WlanThread(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, dtim=self.dtim,
                              sl_collections=self.sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)
        if self.bcast_filter:
            logger().info(f"Setting filter broadcast command")
            self.wifi_dut.interfaces.wifi.set_filter_broadcast()

        time.sleep(2)

        logger().info(f"Enabling TA power save")
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save",
                                                              dtim_aligned_type=self.dtim_aligned_type)
        time.sleep(2)

        if dut != "si917_ncp_sl_wifi":
            if self.deep_sleep:
                m4_obj = M4_Sleep_Thread(wifi_dut=self.wifi_dut, m4_sleep_time=self.m4_sleep_time,
                                         deep_sleep_without_ret=True)
            else:
                m4_obj = M4_Sleep_Thread(wifi_dut=self.wifi_dut, m4_sleep_time=self.m4_sleep_time)
        pm_obj = Power_Measurement_Thread(power_meter=self.power_meter, capture_time=self.capture_time)

        if dut != "si917_ncp_sl_wifi":
            m4_obj.start()
            time.sleep(2)

        pm_obj.start()

        if self.listen_case:
            time.sleep(35)
            self.wifi_access_point.interfaces.wifi.stop_ap()

        pm_obj.wait_for_exit()

        if dut != "si917_ncp_sl_wifi":
            m4_obj.wait_for_exit()

        time.sleep(10)
        if self.ble_with_connection:
            logger().info("Initiating disconnection from remote device")
            self.ble_client.interfaces.bluetooth.disconnect(self.wifi_dut.interfaces.wifi.ble_address)
            time.sleep(5)


# ********************************************************************************************************************

pytestmark = [pytest.mark.firmware_app("test_352K_M4SS_320K")]


# ********************************************************************************************************************

@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,

        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "enable_ble_power_index_params": 1,
        "power_index": 63,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_conn_with_DTIM_10_ble_adv_C20649(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                               sl_collections, dtim, ):
    stdby_obj = StandBy_Associated(dtim=dtim, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                   sl_collections=sl_collections, power_meter=power_meter, ble_advertisement=True)
    stdby_obj.start()
    stdby_obj.wait_for_exit()


@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,

        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "enable_ble_power_index_params": 1,
        "power_index": 63,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_conn_with_DTIM_10_ble_conn_C20650(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                sl_collections, dtim, ble_client):
    stdby_obj = StandBy_Associated(dtim=dtim, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                   ble_client=ble_client, sl_collections=sl_collections, power_meter=power_meter,
                                   ble_with_connection=True)
    stdby_obj.start()
    stdby_obj.wait_for_exit()


@pytest.mark.parametrize("dtim", [10])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,

        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "enable_ble_power_index_params": 1,
        "power_index": 63,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_conn_with_DTIM_10_ble_conn_rc_clock_C537358(firmware_loader, power_meter, wifi_access_point, wifi_dut,
                                                          sl_collections, dtim, ble_client):
    stdby_obj = StandBy_Associated(dtim=dtim, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                   sl_collections=sl_collections, power_meter=power_meter, ble_client=ble_client,
                                   ble_with_connection=True)
    stdby_obj.start()
    stdby_obj.wait_for_exit()

# ********************************************************************************************************************
