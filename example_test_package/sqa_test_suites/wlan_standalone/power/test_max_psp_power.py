import pytest
import time
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.utils.iperf.iperf_utils import print_dict
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116PowerSaveModes, RS9116JoinFeatureBitMap, RS9116Band, RS9116CustomFeatureBitMap, RS9116TCPIPFeatureBitMap, \
    RS9116ExtCustomFeatureBitMap, RS9116ExtTCPIPFeatureBitMap
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
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
        4.Enable power save 
        5. Initiate ping from the dut
        6.Validate power numbers

    Author: Aravind
"""


class power_number_output():
    def __init__(self, power_meter=None, dtim=None):
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


class Pingthread(ThreadBase):
    def __init__(self, device_ip=None, ping_count=None):
        super().__init__()
        self.device_ip = device_ip
        self.ping_count = ping_count

    def run(self):
        logger().info("wait for 3 sec")
        time.sleep(3)

        status = ping(self.device_ip, self.ping_count)
        assert status == 1, "DUT not responding for ping request......"
        logger().info("ping to DUT is successful....")


#########TCID 40151#################
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "set_send_feature_frame": True,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_max_psp_listen_interval_C40151(wifi_access_point, wifi_dut, wifi_sniffer, power_meter, request):
    with TimeMeasurer() as t:
        ping_count = 150
        validation = True
        monitor_interval = 50
        test_name = request.node.name
        '''Verification on power consumption while doing data transfer when power save mode 1 with max psp enabled '''

        logger().info("sniffer capture started")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                      number_of_dtim_skip=0)
        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {bssid}')

        logger().info("scan and connecting to access point.....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                         join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                         listen_interval=1000)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f'DUT ip {device_ip}')

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info("initiating wifi power save")
        wifi_dut.interfaces.wifi.power_save(1, 0)
        logger().info("initiating bt power save")
        wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
        )
        time.sleep(3)
        logger().info("validate NULL data frame with PM bit set to '1'")
        logger().info("Verifying powersave mode  bit")
        packet_filter1 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) ' \
                         f'and (wlan.sa == {dut_mac_address}) ' \
                         f'and (wlan.da == {bssid}))'
        wifi_obj = Pingthread(device_ip=device_ip, ping_count=ping_count)
        logger().info("tcp send data thread started ")
        wifi_obj.start()

        logger().info("power meter initiated")
        power_obj = power_number_output(power_meter=power_meter)
        power_obj.get_power_value()
        logger().info("exited from socket thread")
        wifi_obj.wait_for_exit()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info('Validation for NULL packet with pm bit 1')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'

        time.sleep(3)


#########C40159################
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower |
                               RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 |
                               RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "set_send_feature_frame": True,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_pw_mode2_max_psp_listen_interval_C40159(wifi_access_point, wifi_dut, wifi_sniffer, power_meter, request):
    with TimeMeasurer() as t:
        ping_count = 150
        validation = True
        monitor_interval = 50
        test_name = request.node.name
        '''Verification on power consumption while doing data transfer when power save mode2-ulp mode
         with max psp enabled '''

        logger().info("sniffer capture started")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                      number_of_dtim_skip=0)

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {bssid}')

        logger().info("scan and connecting to access point.....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                         join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                         listen_interval=1000)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f'DUT ip {device_ip}')

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                      number_of_dtim_skip=0)

        logger().info("initiating wifi power save")
        wifi_dut.interfaces.wifi.power_save(2, 0)
        logger().info("initiating bt power save")
        wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
        )
        time.sleep(3)
        logger().info("validate NULL data frame with PM bit set to '1'")
        logger().info("Verifying powersave mode 2 bit")
        packet_filter1 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) ' \
                         f'and (wlan.sa == {dut_mac_address}) ' \
                         f'and (wlan.da == {bssid}))'
        wifi_obj = Pingthread(device_ip=device_ip, ping_count=ping_count)
        logger().info("tcp send data thread started ")
        wifi_obj.start()

        logger().info("power meter initiated")
        power_obj = power_number_output(power_meter=power_meter)
        power_obj.get_power_value()
        logger().info("exited from socket thread")
        wifi_obj.wait_for_exit()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info('Validation for NULL packet with pm bit 1')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
        time.sleep(3)


##########TCID 40167######################
@pytest.mark.firmware_app("test_wlan_powersave_mode3_ulp")
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "set_send_feature_frame": True,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_pwmode3_max_psp_listen_interval_C40167(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer,
                                                     power_meter, request):
    with TimeMeasurer() as t:
        ping_count = 150
        validation = True
        monitor_interval = 50
        test_name = request.node.name
        '''Verification on power consumption while doing data transfer when power save mode3-ulp mode
         with max psp enabled '''

        logger().info("sniffer capture started")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                      number_of_dtim_skip=0)

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {bssid}')

        logger().info("scan and connecting to access point.....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                         join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                         listen_interval=1000)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f'DUT ip {device_ip}')

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info("initiating wifi power save")
        wifi_dut.interfaces.wifi.power_save(2, 0)
        logger().info("initiating bt power save")
        wifi_dut.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
        )
        time.sleep(3)
        logger().info("validate NULL data frame with PM bit set to '1'")
        logger().info("Verifying powersave mode 2 bit")
        packet_filter1 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) ' \
                         f'and (wlan.sa == {dut_mac_address}) ' \
                         f'and (wlan.da == {bssid}))'
        wifi_obj = Pingthread(device_ip=device_ip, ping_count=ping_count)
        logger().info("tcp send data thread started ")
        wifi_obj.start()

        logger().info("power meter initiated")
        power_obj = power_number_output(power_meter=power_meter)
        power_obj.get_power_value()
        logger().info("exited from socket thread")
        wifi_obj.wait_for_exit()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info('Validation for NULL packet with pm bit 1')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
        time.sleep(3)


#############TCID 113951######################
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "set_send_feature_frame": True,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_power_mode1_enh_max_psp_li_C113951(wifi_access_point, wifi_dut, wifi_sniffer, power_meter, request):
    with TimeMeasurer() as t:
        ping_count = 150
        validation = True
        monitor_interval = 50
        test_name = request.node.name
        '''Verification on power consumption while doing data transfer when power save mode1 
         with enhanced max psp enabled '''

        logger().info("sniffer capture started")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                      number_of_dtim_skip=0)

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {bssid}')

        logger().info("scan and connecting to access point.....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                         join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                         listen_interval=1000)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f'DUT ip {device_ip}')

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info("initiating wifi power save")
        wifi_dut.interfaces.wifi.power_save(1, 1)
        logger().info("initiating bt power save")
        wifi_dut.interfaces.wifi.bt_power_save(2, 1)
        time.sleep(3)
        logger().info("validate NULL data frame with PM bit set to '1'")
        logger().info("Verifying powersave mode 2 bit")
        packet_filter1 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) ' \
                         f'and (wlan.sa == {dut_mac_address}) ' \
                         f'and (wlan.da == {bssid}))'
        wifi_obj = Pingthread(device_ip=device_ip, ping_count=ping_count)
        logger().info("tcp send data thread started ")
        wifi_obj.start()

        logger().info("power meter initiated")
        power_obj = power_number_output(power_meter=power_meter)
        power_obj.get_power_value()
        logger().info("exited from socket thread")
        wifi_obj.wait_for_exit()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info('Validation for NULL packet with pm bit 1')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
        time.sleep(3)


#############TCID 113953######################
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "set_send_feature_frame": True,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_power_mode2_enhmax_psp_li_C113953(wifi_access_point, wifi_dut, wifi_sniffer, power_meter, request):
    with TimeMeasurer() as t:
        ping_count = 150
        validation = True
        monitor_interval = 50
        test_name = request.node.name
        '''Verification on power consumption while doing data transfer when power save mode2 ulp
         with enhanced max psp enabled '''

        logger().info("sniffer capture started")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                      number_of_dtim_skip=0)
        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {bssid}')

        logger().info("scan and connecting to access point.....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                         join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                         listen_interval=1000)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f'DUT ip {device_ip}')

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info("initiating wifi power save")
        wifi_dut.interfaces.wifi.power_save(2, 1)
        logger().info("initiating bt power save")
        wifi_dut.interfaces.wifi.bt_power_save(2, 1)
        time.sleep(3)

        logger().info("validate NULL data frame with PM bit set to '1'")
        logger().info("Verifying powersave mode 2 bit")
        packet_filter1 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) ' \
                         f'and (wlan.sa == {dut_mac_address}) ' \
                         f'and (wlan.da == {bssid}))'
        wifi_obj = Pingthread(device_ip=device_ip, ping_count=ping_count)
        logger().info("tcp send data thread started ")
        wifi_obj.start()

        logger().info("power meter initiated")
        power_obj = power_number_output(power_meter=power_meter)
        power_obj.get_power_value()
        logger().info("exited from socket thread")
        wifi_obj.wait_for_exit()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info('Validation for NULL packet with pm bit 1')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
        time.sleep(3)


@pytest.mark.firmware_app("test_wlan_powersave_mode3_ulp")
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "set_send_feature_frame": True,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_power_mode3_enh_max_psp_li_C113955(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer,
                                                 power_meter, request):
    with TimeMeasurer() as t:
        ping_count = 150
        validation = True
        monitor_interval = 50
        test_name = request.node.name
        '''Verification on power consumption while doing data transfer when power save mode3 ulp
         with enhanced max psp enabled '''

        logger().info("sniffer capture started")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                      number_of_dtim_skip=0)
        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {bssid}')

        logger().info("scan and connecting to access point.....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                         join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                         listen_interval=1000)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f'DUT ip {device_ip}')

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info("initiating wifi power save")
        wifi_dut.interfaces.wifi.power_save(2, 1)
        logger().info("initiating bt power save")
        wifi_dut.interfaces.wifi.bt_power_save(2, 1)
        time.sleep(3)
        logger().info("validate NULL data frame with PM bit set to '1'")
        logger().info("Verifying powersave mode 2 bit")
        packet_filter1 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) ' \
                         f'and (wlan.sa == {dut_mac_address}) ' \
                         f'and (wlan.da == {bssid}))'
        wifi_obj = Pingthread(device_ip=device_ip, ping_count=ping_count)
        logger().info("tcp send data thread started ")
        wifi_obj.start()

        logger().info("power meter initiated")
        power_obj = power_number_output(power_meter=power_meter)
        power_obj.get_power_value()
        logger().info("exited from socket thread")
        wifi_obj.wait_for_exit()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info('Validation for NULL packet with pm bit 1')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
        time.sleep(3)

#########################C40166#####################################

@pytest.mark.firmware_app("test_wlan_powersave_mode3_lp")
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "set_send_feature_frame": True,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_power_mode3_enh_max_psp_li_C40166(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer,
                                                 power_meter, request):
    with TimeMeasurer() as t:
        ping_count = 150
        validation = True
        monitor_interval = 50
        test_name = request.node.name
        '''Verification on power consumption while doing data transfer when power save mode3 lp
         wit max psp enabled '''

        logger().info("sniffer capture started")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                      number_of_dtim_skip=0)

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {bssid}')

        logger().info("scan and connecting to access point.....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                         join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                         listen_interval=1000)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f'DUT ip {device_ip}')

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info("initiating wifi power save")
        wifi_dut.interfaces.wifi.power_save(2, 0)
        logger().info("initiating bt power save")
        wifi_dut.interfaces.wifi.bt_power_save(2, 0)
        time.sleep(3)
        logger().info("validate NULL data frame with PM bit set to '1'")
        logger().info("Verifying powersave mode 2 bit")
        packet_filter1 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) ' \
                         f'and (wlan.sa == {dut_mac_address}) ' \
                         f'and (wlan.da == {bssid}))'
        wifi_obj = Pingthread(device_ip=device_ip, ping_count=ping_count)
        logger().info("tcp send data thread started ")
        wifi_obj.start()

        logger().info("power meter initiated")
        power_obj = power_number_output(power_meter=power_meter)
        power_obj.get_power_value()
        logger().info("exited from socket thread")
        wifi_obj.wait_for_exit()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info('Validation for NULL packet with pm bit 1')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
        time.sleep(3)

@pytest.mark.firmware_app("test_wlan_powersave_mode3_lp")
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "set_send_feature_frame": True,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_power_mode3_enh_lp_max_psp_li_C113954(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer,
                                                 power_meter, request):
    with TimeMeasurer() as t:
        ping_count = 150
        validation = True
        monitor_interval = 50
        test_name = request.node.name
        '''Verification on power consumption while doing data transfer when power save mode3 lp
         with enhanced max psp enabled '''

        logger().info("sniffer capture started")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                      number_of_dtim_skip=0)

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {bssid}')

        logger().info("scan and connecting to access point.....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                         join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                         listen_interval=1000)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f'DUT ip {device_ip}')

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info("initiating wifi power save")
        wifi_dut.interfaces.wifi.power_save(2, 1)
        logger().info("initiating bt power save")
        wifi_dut.interfaces.wifi.bt_power_save(2, 1)
        time.sleep(3)
        logger().info("validate NULL data frame with PM bit set to '1'")
        logger().info("Verifying powersave mode 2 bit")
        packet_filter1 = f'(wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) ' \
                         f'and (wlan.sa == {dut_mac_address}) ' \
                         f'and (wlan.da == {bssid}))'
        wifi_obj = Pingthread(device_ip=device_ip, ping_count=ping_count)
        logger().info("tcp send data thread started ")
        wifi_obj.start()

        logger().info("power meter initiated")
        power_obj = power_number_output(power_meter=power_meter)
        power_obj.get_power_value()
        logger().info("exited from socket thread")
        wifi_obj.wait_for_exit()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info('Validation for NULL packet with pm bit 1')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
        time.sleep(3)