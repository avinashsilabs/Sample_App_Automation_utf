import pytest
import time
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect.devices.rs911x import RS9116CoexMode,RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116PowerSaveModes, RS9116JoinFeatureBitMap, RS9116Band
from utf.interfaces.iperf.iperf_constants import IperfConstants,IperfTrafficType
from random import randint
from utf.utils.thread_base import ThreadBase

def logger():
    return get_logger(__name__)
"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut

    Author: Aravind
"""
class power_number_output():
    def __init__(self, power_meter = None, dtim=None):
        super().__init__()
        self.power_meter = power_meter

        self.dtim = dtim

    def __print_throughput(self, throughput: dict):
        if throughput is not None:
            print_dict("##     ", throughput)

    def get_power_value(self):
        if self.dtim:
            # Init power meter by specifying module name as datalogger or scope
            logger().info("initiating power meter wih dtim")
            self.power_meter.interfaces.power_meter.init_power_meter(data_log_file_name=f"UTF1_Data_Log_{self.dtim}")
        else:
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
        time.sleep(10)
        # start capture power meter datalog/scope
        logger().info("starting power meter capture")
        self.power_meter.interfaces.power_meter.start_capture()

        # Parse result as throughput object
        logger().info("parsing output result")
        parsed_result = self.power_meter.interfaces.power_meter.power_meter_module.process_output(
            self.power_meter.interfaces.power_meter.results)
        self.__print_throughput(parsed_result)
        assert parsed_result["Output"] is not None

class WifiSockthread(ThreadBase):
    def __init__(self, remote_socket=None, wifi_dut=None, \
                 wifi_access_point=None, devic_ip=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.device_ip = devic_ip
        self.remote_socket = remote_socket

    def run(self):
        data_size = 42
        data = "tcpdatastartedtcpdatastartedtcpdatastarted"
        no_of_iterations = 5
        self.remote_socket.interfaces.socket.time_limit = 3600

        logger().info("Starting tcp server remotely at port number 5001")
        self.remote_socket.interfaces.socket.start_server()

        # DUT opens tcp client socket
        sock = self.wifi_dut.interfaces.wifi.open_tcp_client_socket()
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger().info(f"socket id received is {sock} which is expected")
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        self.wifi_dut.interfaces.wifi.bind(sock, self.device_ip, local_port)
        # tcp socket opened in DUT connects to the tcp server
        self.wifi_dut.interfaces.wifi.connect_to_server(sock, self.remote_socket.interfaces.socket)
        for i in range(1, no_of_iterations):
            self.wifi_dut.interfaces.wifi.send_data(sock, data_size, data=data)
            data = self.remote_socket.interfaces.socket.recv_data_tcp(data_size)
            time.sleep(55)
        time.sleep(10)
        result = self.wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened tcp socket"
        self.remote_socket.interfaces.socket.socket_close_indication(1)



@pytest.mark.parametrize("dtim", [1, 3, 10])

@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "set_send_feature_frame": True,
            "rf_type":1,
            "features_enable":49,

        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_standby_dtim_2g(wifi_access_point, wifi_dut, power_meter, dtim):

    bcast_in_tim_next_cmd = 1
    beacon_drop = 5000
    bcast_in_tim = 1

    logger().info(f"configuring access point with dtim:{dtim}")
    wifi_access_point.interfaces.wifi.start_ap(dtim=dtim)

    logger().info("scan and connecting to access point.....")
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=RS9116JoinFeatureBitMap.Default)

    logger().info("enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f'DUT ip {device_ip}')

    logger().info("sending filter broadcast command")
    wifi_dut.interfaces.wifi.set_filter_broadcast(beacon_drop, bcast_in_tim, bcast_in_tim_next_cmd)

    logger().info("enabling wifi power save mode in DUT......")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    time.sleep(10)
    power_obj = power_number_output(power_meter=power_meter, dtim=dtim)
    power_obj.get_power_value()

@pytest.mark.parametrize("dtim", [1, 3, 10])
@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "band": RS9116Band.FiveGHz,
            "set_send_feature_frame": True,
            "rf_type": 0,
            "features_enable":49,
        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "channel": 149})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_standby_dtim_5g(wifi_access_point, wifi_dut, power_meter, dtim):

    bcast_in_tim_next_cmd = 1
    beacon_drop = 5000
    bcast_in_tim = 1

    logger().info(f"configuring access point with dtim:{dtim}")
    wifi_access_point.interfaces.wifi.start_ap(dtim=dtim)

    logger().info("scan and connecting to access point.....")
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=RS9116JoinFeatureBitMap.Default)

    logger().info("enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f'DUT ip {device_ip}')

    logger().info("sending filter broadcast command")
    wifi_dut.interfaces.wifi.set_filter_broadcast(beacon_drop, bcast_in_tim, bcast_in_tim_next_cmd)
    logger().info("enabling wifi power save mode in DUT......")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    time.sleep(20)
    power_obj = power_number_output(power_meter=power_meter, dtim=dtim)
    power_obj.get_power_value()

@pytest.mark.parametrize("power", [10, 20])
@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 8,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "set_send_feature_frame": True,
            "rf_type":1,
            "features_enable":49,
        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_active_tx_10dBm_20dBm_2_4Ghz(wifi_dut, power_meter, power):
    antenna = 1
    gain_2g = 0
    gain_5g = 0
    rate = 139
    length = 1000
    mode = 0
    channel = 1
    # for power in power_list:

    wifi_dut.interfaces.wifi.set_wireless_antenna(antenna, gain_2g, gain_5g)
    logger().info("setting the wireless antenna ")

    logger().info(f"configuring dut with diff power:{power}")
    wifi_dut.interfaces.wifi.set_wlan_transmit_start(power=power, rate=rate, length=length, mode=mode, channel=channel)

    time.sleep(20)

    power_obj = power_number_output(power_meter=power_meter)

    power_obj.get_power_value()

##################################################################
@pytest.mark.parametrize("power", [10, 20])
@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 8,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "set_send_feature_frame": True,
            "band": RS9116Band.FiveGHz,
            "rf_type":0,
            "features_enable":49
        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_active_tx_10dBm_20dBm_5Ghz(wifi_dut, power_meter, power):
    antenna = 1
    gain_2g = 0
    gain_5g = 0
    rate=139
    length=1000
    mode=0
    channel=36

    logger().info("setting the wireless antenna ")
    wifi_dut.interfaces.wifi.set_wireless_antenna(antenna, gain_2g, gain_5g)

    logger().info(f"configuring dut with diff power:{power}")
    wifi_dut.interfaces.wifi.set_wlan_transmit_start(power=power, rate=rate, length=length, mode=mode, channel=channel)
    time.sleep(20)
    power_obj = power_number_output(power_meter=power_meter)

    power_obj.get_power_value()

#######BGSCAN test case########

@pytest.mark.parametrize("bg_scan_periodicity", [2, 10, 30])
@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "set_send_feature_frame": True,
            "rf_type": 1,
            "features_enable":49,
        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1, "dtim":10})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_bgscan_with_periodicity_2_10_30_C20563(wifi_dut, wifi_access_point, power_meter, bg_scan_periodicity):
    bcast_in_tim_next_cmd = 1
    beacon_drop = 5000
    bcast_in_tim = 1
    bg_scan_enable = 1
    instant_bg = 1
    bg_scan_threshold = 10
    rssi_tolerance_threshold = 4
    active_scan_duration = 50
    passive_scan_duration = 50
    multiprobe = 1

    logger().info(f"setting bgscan command with diff bgscan periodicity:{bg_scan_periodicity}")
    wifi_dut.interfaces.wifi.set_bgscan(bg_scan_enable=bg_scan_enable, instant_bg=instant_bg,
    bg_scan_threshold=bg_scan_threshold, rssi_tolerance_threshold=rssi_tolerance_threshold, bg_scan_periodicity=bg_scan_periodicity,
    active_scan_duration=active_scan_duration,passive_scan_duration=passive_scan_duration, multiprobe=multiprobe)

    logger().info("scan and connecting to access point.....")
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=RS9116JoinFeatureBitMap.Default)

    logger().info("enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f'DUT ip {device_ip}')

    logger().info("sending filter broadcast command")
    wifi_dut.interfaces.wifi.set_filter_broadcast(beacon_drop, bcast_in_tim, bcast_in_tim_next_cmd)

    logger().info("enabling wifi power save mode in DUT......")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    time.sleep(10)

    power_obj = power_number_output(power_meter=power_meter)

    power_obj.get_power_value()

    bg_scan_enable=0

    wifi_dut.interfaces.wifi.set_bgscan(bg_scan_enable, instant_bg, bg_scan_threshold, rssi_tolerance_threshold,
                                        bg_scan_periodicity,
                                        active_scan_duration,
                                        passive_scan_duration,
                                        multiprobe)
    logger().info("bg scan disabled")
    time.sleep(2)

@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "set_send_feature_frame": True,
            "rf_type": 1,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_standby_assoc_novus_li10_c20554(wifi_access_point, wifi_dut, remote_socket, net_perf_client,
                                         protocol, wifi_client, power_meter):
    with TimeMeasurer() as t:
        bcast_in_tim_next_cmd = 1
        beacon_drop = 5000
        bcast_in_tim = 1
        ping_count=10
        logger().info("scan for the ap's.....")

        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=wifi_access_point.interfaces.wifi.ssid, channel=wifi_access_point.interfaces.wifi.channel)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info("connecting to access point.....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point, listen_interval=1000)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        status = ping(device_ip, ping_count)
        logger().info("sending filter broadcast command")

        wifi_dut.interfaces.wifi.set_filter_broadcast(beacon_drop, bcast_in_tim, bcast_in_tim_next_cmd)
        logger().info("enabling wifi power save mode in DUT......")
        wifi_dut.interfaces.wifi.power_save(2, 0)

        #Initiate ping from third party wifi-client to DUT
        logger().info(f'DUT ip {device_ip}')
        logger().info("pinging to dut.....")

        assert status == 1, "DUT not responding for ping request......"
        logger().info("ping to DUT is successful....")
        wifi_obj = WifiSockthread(remote_socket=remote_socket, wifi_dut=wifi_dut,
                                  wifi_access_point=wifi_access_point, devic_ip=device_ip)
        logger().info("tcp send data thread started ")
        wifi_obj.start()

        logger().info("power meter initiated")
        power_obj = power_number_output(power_meter=power_meter)
        power_obj.get_power_value()
        logger().info("exited from socket thread")
        wifi_obj.wait_for_exit()

@pytest.mark.firmware_app("generic_test_agent_wt_aws_wt_ram_ret")
@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "set_send_feature_frame": True,
            "rf_type":1,
            "features_enable":49,

        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_power_save_withou_ram_ret_C20555(wifi_dut, power_meter):

    # Enables the wifi power save in DUT
    logger().info("Setting DUT in wlan power save...")
    wifi_dut.interfaces.wifi.power_save(8, 0)

    time.sleep(10)
    logger().info("starting power meter capture")
    power_obj = power_number_output(power_meter=power_meter)

    power_obj.get_power_value()

    logger().info("doing EFR reset instead of device reset till reset issue is fixed")
    wifi_dut.interfaces.wifi.reset_soft()

@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "set_send_feature_frame": True,
            "rf_type":1,
            "features_enable":49,

        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1, "dtim":200,
                                               "beacon_interval": 300})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_standby_sleep_2_4Ghz_C20553(wifi_access_point, wifi_dut, power_meter):

    bcast_in_tim_next_cmd = 1
    beacon_drop = 5000
    bcast_in_tim = 1

    logger().info("scan and connecting to access point.....")
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=RS9116JoinFeatureBitMap.Default)

    logger().info("enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f'DUT ip {device_ip}')

    logger().info("sending filter broadcast command")
    wifi_dut.interfaces.wifi.set_filter_broadcast(beacon_drop, bcast_in_tim, bcast_in_tim_next_cmd)

    logger().info("enabling wifi power save mode in DUT......")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    time.sleep(25)
    power_obj = power_number_output(power_meter=power_meter)
    power_obj.get_power_value()
    logger().info("doing EFR reset instead of device reset till reset issue is fixed")
    wifi_dut.interfaces.wifi.reset_soft()


@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "band": RS9116Band.FiveGHz,
            "set_send_feature_frame": True,
            "rf_type":0,
            "features_enable":49,

        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "channel": 149, "dtim":200,
                                               "beacon_interval": 300})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_standby_sleep_5Ghz_C20633(wifi_access_point, wifi_dut, power_meter):

    bcast_in_tim_next_cmd = 1
    beacon_drop = 5000
    bcast_in_tim = 1

    logger().info("scan and connecting to access point.....")
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=RS9116JoinFeatureBitMap.Default)

    logger().info("enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f'DUT ip {device_ip}')

    logger().info("sending filter broadcast command")
    wifi_dut.interfaces.wifi.set_filter_broadcast(beacon_drop, bcast_in_tim, bcast_in_tim_next_cmd)

    logger().info("enabling wifi power save mode in DUT......")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    time.sleep(25)
    power_obj = power_number_output(power_meter=power_meter)
    power_obj.get_power_value()
    time.sleep(2)
    logger().info("doing EFR reset instead of device reset till reset issue is fixed")
    wifi_dut.interfaces.wifi.reset_soft()

##############
#######BGSCAN test case########

@pytest.mark.parametrize("bg_scan_periodicity", [2, 10, 30])
@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "set_send_feature_frame": True,
            "rf_type": 0,
            "features_enable":49,
            "band": RS9116Band.FiveGHz,
        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "channel": 149, "dtim":10})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_bgscan_with_periodicity_5g_2_10_30_C20635(wifi_dut, wifi_access_point, power_meter, bg_scan_periodicity):
    bcast_in_tim_next_cmd = 1
    beacon_drop = 5000
    bcast_in_tim = 1
    bg_scan_enable = 1
    instant_bg = 1
    bg_scan_threshold = 10
    rssi_tolerance_threshold = 4
    active_scan_duration = 50
    passive_scan_duration = 50
    multiprobe = 1

    logger().info(f"setting bgscan command with diff bgscan periodicity:{bg_scan_periodicity}")
    wifi_dut.interfaces.wifi.set_bgscan(bg_scan_enable=bg_scan_enable, instant_bg=instant_bg,
    bg_scan_threshold=bg_scan_threshold, rssi_tolerance_threshold=rssi_tolerance_threshold, bg_scan_periodicity=bg_scan_periodicity,
    active_scan_duration=active_scan_duration,passive_scan_duration=passive_scan_duration, multiprobe=multiprobe)

    logger().info("scan and connecting to access point.....")
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=RS9116JoinFeatureBitMap.Default)

    logger().info("enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f'DUT ip {device_ip}')

    logger().info("sending filter broadcast command")
    wifi_dut.interfaces.wifi.set_filter_broadcast(beacon_drop, bcast_in_tim, bcast_in_tim_next_cmd)

    logger().info("enabling wifi power save mode in DUT......")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    time.sleep(10)

    power_obj = power_number_output(power_meter=power_meter)

    power_obj.get_power_value()

    bg_scan_enable=0

    wifi_dut.interfaces.wifi.set_bgscan(bg_scan_enable, instant_bg, bg_scan_threshold, rssi_tolerance_threshold,
                                        bg_scan_periodicity,
                                        active_scan_duration,
                                        passive_scan_duration,
                                        multiprobe)
    logger().info("bg scan disabled")
    time.sleep(2)














