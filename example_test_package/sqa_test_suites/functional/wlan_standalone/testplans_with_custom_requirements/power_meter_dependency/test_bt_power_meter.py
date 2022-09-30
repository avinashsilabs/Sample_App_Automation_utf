import pytest
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116PowerSaveModes,
    RS9116ExtCustomFeatureBitMap,
    RS9116FeatureBitMap,
    RS9116BTFeatureBitMap,
    RS9116CustomFeatureBitMap,
    RS9116ConfigFeatureBitMap,
)
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.interfaces.bluetooth import BTSocketRole
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.iperf.iperf_utils import print_dict
import time

def logger():
    return get_logger(__name__)

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
        # power_meter.interfaces.power_meter.set_output_channels(["1"])
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
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "config_features":RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "custom_features": RS9116CustomFeatureBitMap.Default,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 |
                                   RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
            "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        },
)
def test_bt_spp_dut_as_master(wifi_dut, bt_client, power_meter):
    sniff_max_interval = 800
    sniff_min_interval = 800
    sniff_attempt = 5
    sniff_tout = 2

    bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
    assert bt_dut_address ,"Dut address not found"

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
    assert bt_client_address , "bt client address not found"

    found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
    if not found:
        logger().error(f"Dut was not found during the scan by bt client. The test case may fail.")

    with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Server
    ) as bt_server_socket:
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_server_socket.create_server()
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
            assert connected
            time.sleep(5)
            logger().info("initiating wlan power save mode")
            wifi_dut.interfaces.wifi.power_save(2, 0)

            logger().info("initiating bt power save mode")
            # Initiating BT power save
            wifi_dut.interfaces.wifi.bt_power_save(2, 0)

            logger().info("initiated sniff mode")
            wifi_dut.interfaces.wifi.set_bt_sniff_mode(bt_client_address=bt_client_address,
                                                       sniff_max_interval=sniff_max_interval,
                                                       sniff_min_interval=sniff_min_interval,
                                                       sniff_attempt=sniff_attempt, sniff_tout=sniff_tout)

            time.sleep(20)
            logger().info("power numbers measurement initiated")
            power_obj = power_number_output(power_meter=power_meter)
            power_obj.get_power_value()
            time.sleep(5)
            logger().info("disconnecting DUT from 3rd party master")
            wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
            bt_server_socket.close()



@pytest.mark.config(
        "wifi_dut",

       wifi ={
           "oper_mode": 0,
           "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
           "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
           "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
           "custom_features": RS9116CustomFeatureBitMap.Default,
           "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 |
                                  RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
           "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
       },
)
def test_bt_per_tx(bt_dut, bt_client, power_meter):
    pkt_len = 679
    pkt_type = 14
    br_mode = 2
    rx_chan = 10
    tx_chan = 10
    tx_link = 1
    scrambler_seed = 0
    hopping_type = 0
    ant_sel = 2
    pll_mode = 0
    rf_type = 1
    rf_chain = 2
    payload_type = 3
    tx_power = 10
    transmit_mode = 1
    inter_pkt_gap = 0
    num_packets = 1000
    cmd_id = 21
    cmd_type = 8

    logger().info("get dut bt address.....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("configure bt local name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name='SILABS_BT')

    logger().info("get bt local name....")
    bt_dut.interfaces.bluetooth.bt_get_local_name()

    bt_dut.interfaces.bluetooth.set_bt_per_tx_params(cmd_id=cmd_id, transmit_enable=1, device_Addr=bt_dut_address,
                                                         pkt_len=pkt_len,
                                                         pkt_type=pkt_type, br_edr_mode=br_mode, rx_chnl_in=rx_chan,
                                                         tx_chnl_in=tx_chan, link_type=tx_link,
                                                         scrambler_seed=scrambler_seed,
                                                         hopping_type=hopping_type, ant_sel=ant_sel, pll_mode=pll_mode,
                                                         rf_type=rf_type, rf_chain=rf_chain,
                                                         payload_type=payload_type, tx_power=tx_power,
                                                         transmit_mode=transmit_mode,
                                                         inter_pkt_gap=inter_pkt_gap, num_packets=num_packets)

    logger().info("starting per stats")
    bt_dut.interfaces.bluetooth.get_bt_per_tx_stats(cmd_type=cmd_type)
    logger.info("BT per stats successfull")

    time.sleep(10)
    logger().info("power number measurement initiated")
    power_obj = power_number_output(power_meter=power_meter)
    power_obj.get_power_value()


