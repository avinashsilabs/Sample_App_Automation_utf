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

            if bt_dut_address in found_devices:
                if adv_data:
                  if found_devices[bt_dut_address] == adv_data:
                    return True
                  else:
                    return False
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
@pytest.mark.ble_client("bt_wiseconnect")
@pytest.mark.config(
    "ble_client",
    bluetooth={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
       },
)
def test_blr_125kbps_per_lpchain_C20581(bt_dut, ble_client, power_meter):
    cmd_ix_1 = 0x13
    access_addr_1 = 1903575337
    pkt_len_1 = 240
    phy_rate_1 = 4
    rx_chnl_num_1 = 10
    tx_chnl_num_1 = 10
    scrambler_seed_1 = 0
    le_chnl_type_1 = 1
    payload_type_1 = 0x06
    tx_power_1 = 31
    transmit_mode_1 = 1
    freq_hop_en_1 = 0
    ant_sel_1 = 2
    rf_type_1 = 1
    pll_mode_1 = 0
    inter_pkt_gap_1 = 0
    num_pkts_1 = 1000
    rf_chain_1 = 3
    cmd_type_1 = 8
    transmit_enable=1
    ######RX PARAMETERS#########
    cmd_ix = 0x14
    receive_enable = 1
    access_addr = 0x71764129
    phy_rate = 4
    rx_chnl_num = 10
    tx_chnl_num = 10
    scrambler_seed = 0
    le_chnl_type = 1
    freq_hop_en = 0
    ant_sel = 2
    pll_mode = 0
    loop_back_mode = 0
    duty_cycling_en = 0
    rf_type = 1
    rf_chain = 3
    ext_data_len_indication = 1


    logger().info("get dut bt address.....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("configure bt local name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name='SILABS_BT')

    logger().info("get bt local name....")
    bt_dut.interfaces.bluetooth.bt_get_local_name()

    bt_dut.interfaces.bluetooth.set_ble_per_rx_params(cmd_ix=cmd_ix, receive_enable=receive_enable, access_addr=access_addr,
                                                      phy_rate=phy_rate, rx_chnl_num=rx_chnl_num, tx_chnl_num=tx_chnl_num,
                                                      scrambler_seed=scrambler_seed,le_chnl_type=le_chnl_type, freq_hop_en=freq_hop_en,
                                                      ant_sel=ant_sel, pll_mode=pll_mode, rf_type=rf_type, rf_chain=rf_chain,
                                                      ext_data_len_indication=ext_data_len_indication, loop_back_mode=loop_back_mode, duty_cycling_en=duty_cycling_en)

    ble_client.interfaces.bluetooth.init_device_ble()

    ble_client.interfaces.bluetooth.set_per_tx_params_ble(cmd_ix=cmd_ix_1, transmit_enable=transmit_enable, access_addr=access_addr_1, phy_rate=phy_rate_1,
                                                          rx_chnl_num=rx_chnl_num_1, tx_chnl_num=tx_chnl_num_1, scrambler_seed = scrambler_seed_1,
                                                          le_chnl_type=le_chnl_type_1, freq_hop_en=freq_hop_en_1, ant_sel=ant_sel_1, pll_mode=pll_mode_1, rf_type=rf_type_1, rf_chain=rf_chain_1,
                                                          pkt_len=pkt_len_1, payload_type=payload_type_1, tx_power=tx_power_1, transmit_mode=transmit_mode_1, inter_pkt_gap=inter_pkt_gap_1, num_pkts=num_pkts_1)

    time.sleep(10)

    logger().info("starting per stats")
    ble_client.interfaces.bluetooth.per_tx_stats_bt(cmd_type=cmd_type_1)
    time.sleep(10)
    logger().info("power number measurement initiated")
    power_obj = power_number_output(power_meter=power_meter)
    power_obj.get_power_value()


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
@pytest.mark.ble_client("bt_wiseconnect")
@pytest.mark.config(
    "ble_client",
    bluetooth={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
       },
)
def test_ble_per_1mbps_rx_lpchain_C20580(bt_dut, ble_client, power_meter):
    cmd_ix_1 = 0x13
    access_addr_1 = 1903575337
    pkt_len_1 = 240
    phy_rate_1 = 1
    rx_chnl_num_1 = 10
    tx_chnl_num_1 = 10
    scrambler_seed_1 = 0
    le_chnl_type_1 = 1
    payload_type_1 = 0x06
    tx_power_1 = 31
    transmit_mode_1 = 1
    freq_hop_en_1 = 0
    ant_sel_1 = 2
    rf_type_1 = 1
    pll_mode_1 = 0
    inter_pkt_gap_1 = 0
    num_pkts_1 = 1000
    rf_chain_1 = 3
    cmd_type_1 = 8
    transmit_enable=1
    ######RX PARAMETERS#########
    cmd_ix = 0x14
    receive_enable = 1
    access_addr = 0x71764129
    phy_rate = 1
    rx_chnl_num = 10
    tx_chnl_num = 10
    scrambler_seed = 0
    le_chnl_type = 1
    freq_hop_en = 0
    ant_sel = 2
    pll_mode = 0
    loop_back_mode = 0
    duty_cycling_en = 0
    rf_type = 1
    rf_chain = 3
    ext_data_len_indication = 1


    logger().info("get dut bt address.....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("configure bt local name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name='SILABS_BT')

    logger().info("get bt local name....")
    bt_dut.interfaces.bluetooth.bt_get_local_name()

    bt_dut.interfaces.bluetooth.set_ble_per_rx_params(cmd_ix=cmd_ix, receive_enable=receive_enable, access_addr=access_addr,
                                                      phy_rate=phy_rate, rx_chnl_num=rx_chnl_num, tx_chnl_num=tx_chnl_num,
                                                      scrambler_seed=scrambler_seed,le_chnl_type=le_chnl_type, freq_hop_en=freq_hop_en,
                                                      ant_sel=ant_sel, pll_mode=pll_mode, rf_type=rf_type, rf_chain=rf_chain,
                                                      ext_data_len_indication=ext_data_len_indication, loop_back_mode=loop_back_mode, duty_cycling_en=duty_cycling_en)

    ble_client.interfaces.bluetooth.init_device_ble()

    ble_client.interfaces.bluetooth.set_per_tx_params_ble(cmd_ix=cmd_ix_1, transmit_enable=transmit_enable, access_addr=access_addr_1, phy_rate=phy_rate_1,
                                                          rx_chnl_num=rx_chnl_num_1, tx_chnl_num=tx_chnl_num_1, scrambler_seed = scrambler_seed_1,
                                                          le_chnl_type=le_chnl_type_1, freq_hop_en=freq_hop_en_1, ant_sel=ant_sel_1, pll_mode=pll_mode_1, rf_type=rf_type_1, rf_chain=rf_chain_1,
                                                          pkt_len=pkt_len_1, payload_type=payload_type_1, tx_power=tx_power_1, transmit_mode=transmit_mode_1, inter_pkt_gap=inter_pkt_gap_1, num_pkts=num_pkts_1)

    time.sleep(10)

    logger().info("starting per stats")
    ble_client.interfaces.bluetooth.per_tx_stats_bt(cmd_type=cmd_type_1)
    time.sleep(10)
    logger().info("power number measurement initiated")
    power_obj = power_number_output(power_meter=power_meter)
    power_obj.get_power_value()