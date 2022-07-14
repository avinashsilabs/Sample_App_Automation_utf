import re
from datetime import datetime, timedelta
import datetime
import pytest as pytest
import time
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer

from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.interfaces.bluetooth import BTSocketRole
from utf.interfaces.wifi import WlanError
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict, ping
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands

from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116AsyncEventType, \
    RS9116CustomFeatureBitMap, RS9116PowerSaveModes, RS9116DataRate, RS9116RejoinParams, RS9116JoinFeatureBitMap, \
    RS9116PowerSaveProcedureTypes, RS9116ExtCustomFeatureBitMap, RS9116BTFeatureBitMap
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116CustomFeatureBitMap,

)

def logger():
    return get_logger(__name__)


def start_iperf_dut_as_server(wifi_dut, net_perf_client, protocol, device_ip, host_ip):
    # # preparing iperf
    net_perf_client.interfaces.net_perf.init_client(
        host_ip=host_ip, device_ip=device_ip, protocol=protocol
    )

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
            time=net_perf_client.interfaces.net_perf.client_timeout,
    ) as obj:
        # start iperf
        net_perf_client.interfaces.net_perf.start()
        # capture device output
        wifi_dut.interfaces.wifi.read_from_device(
            obj, net_perf_client.interfaces.net_perf.client_timeout
        )
    time.sleep(2)
    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp is not None
    if tp is not None:
        print_dict("##     ", tp)


def start_ble_data_transfer(wifi_dut, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )

    service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
    char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
    data1 = "LzY0"
    data2 = "K09x"
    data3 = "Mx3Y"

    # Set up BLE Server on DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()

    # Set up BLE Server on DUT
    wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
    wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
    wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)

    # Start advertising
    wifi_dut.interfaces.wifi.ble_start_advertising()

    # Begin Scanning for BLE devices
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        if bt_dut_address in found_devices and \
                found_devices[bt_dut_address] == wifi_dut.interfaces.wifi.ble_advertising_data:
            device_found = True
            break

    ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found

    # connecting to dut
    ble_client.interfaces.bluetooth.connect(bt_dut_address)
    time.sleep(2)

    # resolving charecteristic
    bus = ble_client.interfaces.bluetooth.bus
    servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics(
        bus)
    assert len(servs) > 0
    assert len(chars) > 0

    char, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(bus,
                                                                                                services=servs,
                                                                                                service_uid=service_uid,
                                                                                                char_uid=char_uid)
    assert char is not None
    assert len(char_props) > 0

    # read value - Notifications not enabled
    result = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
    assert result == data1

    # subscribe to notifications
    ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(characteristic=char)
    ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char,
                                                                                 char_uid=char_uid)

    # notify only
    wifi_dut.interfaces.wifi.ble_notify_value()

    # write/read new value - Notifications enabled
    ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(characteristic=char, data=data2)
    time.sleep(0.1)
    result = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
    assert result == data2

    # write value - Notifications enabled
    ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(characteristic=char, data=data3)

    # auto notify
    ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char,
                                                                                 char_uid=char_uid)
    wifi_dut.interfaces.wifi.ble_start_notify_value(interval_ms=500, count=2)
    time.sleep(1)

    # subscribe to notifications
    ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(characteristic=char)
    ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
    time.sleep(1)
    # notify only - disabled notifications - should raise exception
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.ble_notify_value()
    assert exc_info.value.error_code == 0x21 or exc_info.value.error_code == 0xFFFFFFFD

    # assert received notifications
    notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
    logger().info(notifications)
    assert len(notifications) == 6
    assert notifications[0] == data1
    assert notifications[1] == data2
    assert notifications[2] == data2
    assert notifications[3] == data3
    assert notifications[4] == data3
    assert notifications[5] == data3

    # disconnecting from dut
    ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


class BleThreadConnectionDataTransfer(ThreadBase):
    def __init__(self, wifi_dut, ble_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client

    def run(self):
        start_ble_data_transfer(self.wifi_dut, self.ble_client)


class WifiJoinThread(ThreadBase):
    def __init__(self, wifi_dut, net_perf_client, protocol, device_ip, host_ip):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.device_ip = device_ip
        self.host_ip = host_ip

    def run(self):
        start_iperf_dut_as_server(self.wifi_dut, self.net_perf_client, self.protocol, self.device_ip, self.host_ip)


@pytest.mark.net_perf_client("raspi_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_disconnect"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,

    },
)
def test_coex_ble_wlan_datatransfer(wifi_access_point, wifi_dut, wifi_client, ble_client, net_perf_client, protocol):
    monitor_interval = 50

    '''Validate listen interval from DUT side, DUT should wake up and send data after 11 consecutive beacons'''
    wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
    wifi_access_point.interfaces.wifi.config['dtim'] = '3'
    wifi_access_point.interfaces.wifi.start_ap()

    wifi_dut.interfaces.wifi.set_power_save_param(dtim_aligned_type=0, monitor_interval=monitor_interval,
                                                  number_of_dtim_skip=0)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                     join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromJoin,
                                     listen_interval=1100)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    if wifi_access_point != wifi_client:
        wifi_client.interfaces.wifi.join_ap(wifi_access_point)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                                        power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
    )
    ''' Initiating BLE connection(Master) and start data transfer '''
    ble_obj = BleThreadConnectionDataTransfer(wifi_dut, ble_client)
    ble_obj.start()

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client'''
    wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip, host_ip)
    wlan_obj.start()

    ble_obj.wait_for_exit()
    wlan_obj.wait_for_exit()

    # result = ThreadBase.call_functions_simultaneously(
    #     [(start_ble_data_transfer, wifi_dut, ble_client), (start_iperf_dut_as_server, wifi_dut, net_perf_client, protocol, device_ip, host_ip)])

    # start_ble_data_transfer(wifi_dut, ble_client)
    # start_iperf_dut_as_server(wifi_dut, net_perf_client, protocol, device_ip, host_ip)

    time.sleep(5)
