import time
import re
import uuid
from datetime import datetime
import pytest
from utf.interfaces.bluetooth import BLEDeviceState
from utf.utils.iperf.iperf_utils import ping
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116PowerSaveModes,
    SocketOptions,
    RS9116CustomFeatureBitMap,
    RS9116BTFeatureBitMap,
    RS9116PowerSaveProcedureTypes,
    RS9116RegionCode,
    RS9116AsyncEventType,
    DeviceConstants,
    RS9116Band,
)
from typing import Dict
from retry import retry


def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC)

    Test Steps:
        1. Configure the DUT in Wlan coex mode
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify power management bit to be enable in Null data frames 
        5. Initiate BLE advertise/scan

    Author: Jyothi Nagireddy
"""

iter_count = 5
ping_count = 30


def clean_up_method(wifi_dut, ble_client):
    logger().info(
        "\n\n ---------------------------- Cleaning UP the DUT -------------------------------"
    )
    try:
        logger().info("BLE disconnect from DUT")
        for device_address in wifi_dut.interfaces.wifi.ble_devices_address:
            try:
                wifi_dut.interfaces.wifi.ble_disconnect(device_address)
            except:
                pass
        logger().info("Closing all opened sockets")
        wifi_dut.interfaces.wifi.close_sockets()
        logger().info("Disconnect from AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.inited = False
        time.sleep(3)
    except:
        logger().info("******* Recovering the DUT using reset **********")
        wifi_dut.interfaces.wifi.reset()
        time.sleep(20)
    logger().info(
        "\n ---------------------------- Cleaning UP of DUT is Completed -------------------"
    )


class BleThread_connection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, ble_mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_mode = ble_mode

    def run(self):
        if self.ble_mode == "ble_master":
            logger().info(f"this is ble thread, Start DUT as a master")
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None
            logger().info(f"Start ble client")
            try:
                bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                    bt_dut_address=bt_dut_address
                )
                assert bt_client_address is not None
                time.sleep(1)
                logger().info(f"Start scanning and connect to ble client")
                self.wifi_dut.interfaces.wifi.ble_start_scanning(
                    ble_client_address=bt_client_address, timeout=30
                )
                timeout = 120
                logger().info(f"connect")
                self.wifi_dut.interfaces.wifi.ble_connect(
                    ble_remote_dev_address=bt_client_address, timeout=timeout
                )
                time.sleep(60)
                logger().info(f"Get the state of the dut")
                state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert (
                        state_int == BLEDeviceState.Connected
                ), "unable to connect to the given address"
                logger().info(f"Disconnect")
                self.wifi_dut.interfaces.wifi.ble_disconnect(
                    ble_remote_dev_address=bt_client_address
                )
                time.sleep(60)
                logger().info(f"Get the state of the dut")
                state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert not state_int == BLEDeviceState.Connected, "unable to disconnect"
                logger().info(f"*****BLE sniffer validation is pending*******")
            except Exception as e:
                logger().info(
                    "*************** Exception block for stop advertising and stop scanning"
                )
                self.wifi_dut.interfaces.wifi.ble_stop_advertising()
                self.ble_client.interfaces.bluetooth.stop_scanning()
                raise e

        if self.ble_mode == "ble_slave":
            logger().info(f" this is ble thread, start DUT as a slave")
            logger().info(f"Set up DUT for BLE advertising")
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None, "failed to initiate ble in dut"
            try:
                self.wifi_dut.interfaces.wifi.ble_start_advertising()
                logger().info(f"Begin Scanning for BLE devices")
                bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(
                    bt_dut_address=bt_dut_address,
                )
                assert (
                        bt_client_address is not None
                ), "failed to initiate ble in remote device"
                logger().info("keeping the time sleep to complete smp scan")
                time.sleep(4)
                self.ble_client.interfaces.bluetooth.stop_scanning()
                dut_ble_address = self.wifi_dut.interfaces.wifi.ble_address
                logger().info(f"dut_ble_address: {dut_ble_address}")
                logger().info(f"See that we found our device")
                found_devices = self.ble_client.interfaces.bluetooth.get_devices()
                logger().info(f"{found_devices}")
                assert self.wifi_dut.interfaces.wifi.ble_address in found_devices
                logger().info(f"connect")
                self.ble_client.interfaces.bluetooth.connect(bt_dut_address)
                logger().info(f"fetching the connection status after 60 secs of sleep")
                time.sleep(60)
                logger().info(f"Get the state of the dut")
                state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert (
                        state_int == BLEDeviceState.Connected
                ), f"unable to connect to the given address"
                self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                time.sleep(60)
                logger().info(f"To check the ble disconnection after 60secs")
                logger().info(f"Get the state of the dut")
                state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert not state_int == BLEDeviceState.Connected, "unable to disconnect"
                logger().info(f"*****BLE sniffer validation is pending*******")
            except Exception as e:
                logger().info(
                    "*************** Exception block for stop advertising and stop scanning"
                )
                self.wifi_dut.interfaces.wifi.ble_stop_advertising()
                self.ble_client.interfaces.bluetooth.stop_scanning()
                raise e


def ApWirelessOff(wifi_access_point, wait_time):
    time.sleep(wait_time)
    logger().info(f"Disabling Wireless in AP")
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(10)
    logger().info(f"Enabling Wireless in AP")
    wifi_access_point.interfaces.wifi.start_ap()


def ble_master_slave(wifi_dut, ble_client, ble_mode):
    if ble_mode == "ble_master":
        logger().info(f"this is ble thread, Start DUT as a master")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert ble_dut_address is not None
        logger().info(f"Start ble client")
        try:
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=ble_dut_address
            )
            assert ble_client_address is not None
            time.sleep(1)
            logger().info(f"Start scanning and connect to ble client")
            wifi_dut.interfaces.wifi.ble_start_scanning(
                ble_client_address=ble_client_address, timeout=30
            )
            timeout = 120
            logger().info(f"connect")
            wifi_dut.interfaces.wifi.ble_connect(
                ble_remote_dev_address=ble_client_address, timeout=timeout
            )
            time.sleep(60)
            logger().info(f"Get the state of the dut")
            state = wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert (
                    state_int == BLEDeviceState.Connected
            ), "unable to connect to the given address"
            return ble_client_address, ble_dut_address
        except Exception as e:
            logger().info(
                "*************** Exception block for stop advertising and stop scanning"
            )
            ble_client.interfaces.bluetooth.stop_advertising()
            wifi_dut.interfaces.wifi.ble_stop_scanning()
            raise e

    if ble_mode == "ble_slave":
        ble_client.interfaces.bluetooth.close()
        time.sleep(2)
        logger().info(f"Set up DUT for BLE advertising")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert ble_dut_address is not None, "failed to initiate ble in dut"
        try:
            wifi_dut.interfaces.wifi.ble_start_advertising()
            logger().info(f"Begin Scanning for BLE devices")
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=ble_dut_address,
            )
            assert (
                    ble_client_address is not None
            ), "failed to initiate ble in remote device"
            logger().info("keeping the time sleep to complete smp scan")
            time.sleep(4)
            ble_client.interfaces.bluetooth.stop_scanning()
            logger().info(f"See that we found our device")
            found_devices = ble_client.interfaces.bluetooth.get_devices()
            logger().info(f"{found_devices}")
            dut_ble_address = wifi_dut.interfaces.wifi.ble_address
            logger().info(f"dut_ble_address: {dut_ble_address}")
            assert wifi_dut.interfaces.wifi.ble_address in found_devices
            logger().info(f"ble connect")
            conn_params = {
                "min_conn_interval": 40,
                "max_conn_interval": 40,
                "conn_latency": 0,
                "supervision_timeout": 200,
            }

            ble_client.interfaces.bluetooth.connect(
                dev_addr=ble_dut_address,
                min_conn_interval=conn_params["min_conn_interval"],
                max_conn_interval=conn_params["max_conn_interval"],
                conn_latency=conn_params["conn_latency"],
                supervision_timeout=conn_params["supervision_timeout"],
            )

            logger().info(f"fetching the connection status after 60 secs of sleep")
            time.sleep(60)
            logger().info(f"Get the state of the dut")
            state = wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert (
                    state_int == BLEDeviceState.Connected
            ), "unable to connect to the given address"
            return ble_client_address, ble_dut_address
        except Exception as e:
            logger().info(
                "*************** Exception block for stop advertising and stop scanning"
            )
            wifi_dut.interfaces.wifi.ble_stop_advertising()
            ble_client.interfaces.bluetooth.stop_scanning()
            raise e


def http_pkt_check(
        wifi_sniffer,
        logger,
        decryption_key: str,
        dut_mac_address,
        capture_filename,
) -> Dict[str, int]:
    current_time = time.time()
    http_capture_list = []
    updated_capture_file = (
            "filter_"
            + capture_filename
            + "_"
            + str(datetime.fromtimestamp(current_time).strftime("%H_%M_%S"))
    )
    file_name = f"./reports/{updated_capture_file}.pcap"
    local_capture_file = file_name
    wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
    packet_filter1 = f"(wlan.addr == {dut_mac_address})"
    wifi_sniffer.interfaces.capture.shell(
        f"tshark -nr {wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter1}' -T fields -e "
        f"frame.number -w "
        f"{wlan_filter_file}"
    )
    with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
        sftp.get(wlan_filter_file, local_capture_file)
    for packet in wifi_sniffer.interfaces.capture.iter_packets(
            decrypt_packets=True,
            encryption_type="WPA-PWD",
            decryption_key=decryption_key,
            capture_file_filter=local_capture_file,
    ):
        for layer in packet.layers:
            layer_name = layer.layer_name.lower()
            if layer_name == "http":
                http_layer = str(layer)
                http_capture_list.append(tuple([http_layer, packet.sniff_timestamp]))
                logger().info(f"http layer {http_layer}")
    return http_capture_list


def check_connection_status(wifi_dut, ble=False, wlan=False):
    if ble:
        logger().info("Checking connection status of BLE")
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
        logger().info("DUT is not disconnected from BLE")

    if wlan:
        logger().info("Checking connection status of Wi-Fi")
        events = wifi_dut.interfaces.wifi.get_async_events()
        disconnect_events = [
            event
            for event in events
            if event.event_type == RS9116AsyncEventType.Disconnect
        ]
        count_disconnect = set()
        if len(disconnect_events):
            count_disconnect.add(str(disconnect_events[0]))
            logger().info(f"Disconnect Events:{count_disconnect}")
            assert False, f"DUT is not connected to Wi-Fi"
        assert len(disconnect_events) == 0
        logger().info(
            f"DUT is not disconnected from Wi-Fi during traffic run for long duration"
        )


def wifi_join(wifi_dut, wifi_access_point, tcp_ip_bypass=False):
    status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    assert status, "Unable to connect to ap"
    logger().info(f"wifi_join status: {status}")
    time.sleep(5)

    ip_fail = 1
    if not tcp_ip_bypass:
        for count in range(1, 4):
            try:
                result = wifi_dut.interfaces.wifi.start_ip()
                assert isinstance(
                    result, wifi_dut.interfaces.wifi.IPConfig
                ), f"Failed to get IP address. Result = {result}"
                device_ip = wifi_dut.interfaces.wifi.ip.ip.decode("utf-8")
                ip_fail = 0
                break
            except:
                logger().info(
                    f"Get IP address through dhcp process is failed. retry count -> {count}"
                )
                time.sleep(1)
        assert ip_fail == 0, "ip setting in DUT has failed"
    if tcp_ip_bypass:
        ip_fail = 0
        try:
            result = wifi_dut.interfaces.wifi.start_ip()
            logger().info(f"result value {result}")
        except Exception as e:
            if '0XFFFC' or '0xfffc' in str(e):
                logger().info('******* Error found 0xFFFC**********')
                ip_fail = 1
        assert ip_fail == 1, "Since 0xFFFC error occured IP CONFIGURATION FAILED"

    wifi_ps = wifi_dut.interfaces.wifi.power_save(
        RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave
    )
    assert wifi_ps, "Unable to enable wifi powersave"
    bt_ps = wifi_dut.interfaces.wifi.bt_power_save(
        RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave
    )
    assert bt_ps, "Unable to enable Bt powersave"
    if not tcp_ip_bypass:
        logger().info(f"DUT ip {device_ip}")
        logger().info("pinging to dut.....")
        status = ping(device_ip, ping_count)
        assert status == 1, "DUT not responding for ping request......"
        logger().info("ping to DUT is successful....")
        return device_ip


class Ble_continuous_advertise_and_connection_thread(ThreadBase):
    def __init__(self, wifi_dut, ble_client, ble_mode, connect=True):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_mode = ble_mode
        self.connect = connect

    def run(self):
        if self.ble_mode == "ble_master":
            logger().info(f"this is ble thread, Start DUT as a master")
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None
            logger().info(f"Start ble client")
            try:
                bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                    bt_dut_address=bt_dut_address
                )
                assert bt_client_address is not None
                time.sleep(1)
                logger().info(f"Start scanning and connect to ble client")
                self.wifi_dut.interfaces.wifi.ble_start_scanning(
                    ble_client_address=bt_client_address, timeout=30
                )
                timeout = 120
                if self.connect:
                    logger().info(f"connect")
                    self.wifi_dut.interfaces.wifi.ble_connect(
                        ble_remote_dev_address=bt_client_address, timeout=timeout
                    )
                if self.connect:
                    logger().info(f"Get the state of the dut")
                    state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                    state_int = int(state) if state.isdigit() else -1
                    assert (
                            state_int == BLEDeviceState.Connected
                    ), "unable to connect to the given address"
                    logger().info(f"Disconnect")
                    self.wifi_dut.interfaces.wifi.ble_disconnect(
                        ble_remote_dev_address=bt_client_address
                    )
                    time.sleep(60)
                    logger().info(f"Get the state of the dut")
                    state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                    state_int = int(state) if state.isdigit() else -1
                    assert (
                        not state_int == BLEDeviceState.Connected
                    ), "unable to disconnect"
            except Exception as e:
                logger().info(
                    "*************** Exception block for stop advertising and stop scanning"
                )
                self.wifi_dut.interfaces.wifi.ble_stop_advertising()
                self.ble_client.interfaces.bluetooth.stop_scanning()
                raise e
                time.sleep(60)

        if self.ble_mode == "ble_slave":
            logger().info(f" this is ble thread, start DUT as a slave")
            logger().info(f"Set up DUT for BLE advertising")
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None, "failed to initiate ble in dut"
            try:
                self.wifi_dut.interfaces.wifi.ble_start_advertising()
                logger().info(f"Begin Scanning for BLE devices")
                for i in range(1, 5):
                    bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(
                        bt_dut_address=bt_dut_address,
                    )
                    assert (
                            bt_client_address is not None
                    ), "failed to initiate ble in remote device"
                    logger().info("keeping the time sleep to complete smp scan")
                    time.sleep(4)
                    # self.ble_client.interfaces.bluetooth.stop_scanning()
                    logger().info(f"See that we found our device")
                    dut_ble_address = self.wifi_dut.interfaces.wifi.ble_address
                    logger().info(f"dut_ble_address: {dut_ble_address}")
                    device_found = False
                    sw = Stopwatch()
                    while sw.elapsed_sec < 30:
                        found_devices = self.ble_client.interfaces.bluetooth.get_devices()
                        if (
                                self.wifi_dut.interfaces.wifi.ble_address in found_devices
                                and found_devices[dut_ble_address]
                                == self.wifi_dut.interfaces.wifi.ble_advertising_data
                        ):
                            device_found = True
                            logger().info(f"ble_scan_list:\n{found_devices}")
                            break
                    self.ble_client.interfaces.bluetooth.stop_scanning()
                    if device_found:
                        break
                assert device_found
                logger().info(f"See that we found our device:'{dut_ble_address}'")
                logger().info(f"connect")
                if self.connect:
                    conn_params = {
                        "min_conn_interval": 40,
                        "max_conn_interval": 40,
                        "conn_latency": 0,
                        "supervision_timeout": 500,
                    }
                    time.sleep(20)

                    self.ble_client.interfaces.bluetooth.connect(
                        dev_addr=dut_ble_address,
                        min_conn_interval=conn_params["min_conn_interval"],
                        max_conn_interval=conn_params["max_conn_interval"],
                        conn_latency=conn_params["conn_latency"],
                        supervision_timeout=conn_params["supervision_timeout"],
                    )
                    logger().info(
                        f"fetching the connection status after 60 secs of sleep"
                    )
                    time.sleep(60)
                    logger().info(f"Get the state of the dut")
                    state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                    state_int = int(state) if state.isdigit() else -1
                    assert (
                            state_int == BLEDeviceState.Connected
                    ), f"unable to connect to the given address"
                    self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                    time.sleep(60)
                    logger().info(f"To check the ble disconnection after 60secs")
                    logger().info(f"Get the state of the dut")
                    state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                    state_int = int(state) if state.isdigit() else -1
                    assert (
                        not state_int == BLEDeviceState.Connected
                    ), "unable to disconnect"
            except Exception as e:
                logger().info(
                    "*************** Exception block for stop advertising and stop scanning"
                )
                self.wifi_dut.interfaces.wifi.ble_stop_advertising()
                self.ble_client.interfaces.bluetooth.stop_scanning()
                raise e


class wifi_ScanThread(ThreadBase):
    def __init__(
            self,
            wifi_dut,
            wifi_access_point,
            wifi_sniffer,
            channel_2_4_list=[],
            channel_5_list=[],
            select_channel_all_2_4=[],
            select_channel_all_5=[],
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.channel_2_4_list = channel_2_4_list
        self.channel_5_list = channel_5_list
        self.select_channel_all_2_4 = select_channel_all_2_4
        self.select_channel_all_5 = select_channel_all_5

    def run(self):
        logger().info("Setting DUT in wlan power save...")
        self.wifi_dut.interfaces.wifi.power_save(
            RS9116PowerSaveModes.PowerSaveMode2,
            RS9116PowerSaveProcedureTypes.FastPowerSave,
        )
        logger().info("Setting DUT in bt power save...")
        self.wifi_dut.interfaces.wifi.bt_power_save(
            RS9116PowerSaveModes.PowerSaveMode2,
            RS9116PowerSaveProcedureTypes.FastPowerSave,
        )
        logger().info(f"thread for scan functionality")
        channel_bitmap_2_4 = 0
        channel_bitmap_5 = 0
        if len(self.channel_2_4_list):
            logger().info("selective channel 2.4")
            channel_list = self.channel_2_4_list
            scan_expected_time = 0
            for count in channel_list:
                channel_bitmap_2_4 += 1 << (count - 1)
                scan_expected_time += 100
            channel_bitmap_5 = 0
            scan_feature_extend = 0
            for channel in channel_list:
                logger().info(f"initiates the access point with channel given in list")
                self.wifi_access_point.interfaces.wifi.start_ap(channel=channel)
                validation = True
                logger().info("configuring the Sniffer with the channel")
                self.wifi_sniffer.interfaces.capture.configure_interface(
                    channel=self.wifi_access_point.interfaces.wifi.channel
                )
                logger().info(
                    "start capturing with Sniffer by giving the test case name as filename"
                )
                self.wifi_sniffer.interfaces.capture.start_capture(
                    capture_file="sta scan + ble connection as a slave_selective_channels_2_4"
                )
                logger().info(f"Fetches the DUT mac address")
                dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
                logger().info(f"Device mac address: {dut_mac_address}")
                logger().info(
                    f"enables the scan in DUT with the given channel bitmap value"
                )
                with TimeMeasurer() as t:
                    ap_mac = self.wifi_dut.interfaces.wifi.scan_selective_channel(
                        channel=0,
                        ssid=None,
                        scan_bitmap_2_4=channel_bitmap_2_4,
                        scan_feature=scan_feature_extend,
                    )
                logger().info(f"ap_mac {ap_mac}")
                logger().info(f"Scan in {t.duration} seconds")
                assert t.duration < 0.6
                assert len(ap_mac) >= 1
                channel_selected = 0
                for count in ap_mac:
                    for device_channel in channel_list:
                        if count.rf_channel == device_channel:
                            channel_selected = channel_selected + 1
                logger().info(f"Validating Broadcast Probe request")
                packet_filter1 = (
                    f"wlan_radio.channel == {self.wifi_access_point.interfaces.wifi.channel} and "
                    f"wlan.sa == {dut_mac_address} and wlan.fc.type_subtype == 0x0004 "
                    f"and wlan.da == ff:ff:ff:ff:ff:ff"
                )

                time.sleep(2)
                self.wifi_sniffer.interfaces.capture.stop_capture()
                result = self.wifi_sniffer.interfaces.capture.sniffer_validation(
                    validation, packet_filter1
                )["packet_count"]
                logger().info(f"result of probe request is {result} ")
                if result:
                    flag = False
                    logger().info(f"found Probe req(Broadcast) in channel:{channel}'")
                else:
                    flag = True
                if flag:
                    ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
                    logger().info(f"AP bssid {ap_bssid}")
                    with TimeMeasurer() as t:
                        scan_results = self.wifi_dut.interfaces.wifi.scan(
                            channel=channel, ssid=None
                        )
                        assert len(scan_results) >= 1, "Scan failed"
                        logger().info(scan_results)
                    if ap_bssid.lower() in str(scan_results):
                        logger().info(
                            f"found ap bssid in scan_results for channel {channel}"
                        )
                    else:
                        assert False, "Unable to find ap in scan results"
                    logger().info(f"Scan in {t.duration} seconds")
                assert channel_selected == len(ap_mac)

        if len(self.channel_5_list):
            channel_list = self.channel_5_list
            default = {
                0: 36,
                1: 40,
                2: 44,
                3: 48,
                20: 149,
                21: 153,
                22: 157,
                23: 161,
                24: 165,
            }
            dict = {}
            for channel in channel_list:
                for key, val in default.items():
                    if channel == val:
                        dict[key] = channel
            logger().info("selective channel 5G")
            logger().info(f"channel list of 5G  {channel_list}")
            scan_expected_time = 0
            for count in dict:
                channel_bitmap_5 += 1 << (count)
                scan_expected_time += 100
            scan_feature_extend = 0
            for channel in channel_list:
                logger().info(f"initiates the access point with channel given in list")
                self.wifi_access_point.interfaces.wifi.start_ap(channel=channel)
                with TimeMeasurer() as t:
                    validation = True
                    logger().info("configuring the Sniffer with the channel")
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel
                    )
                    logger().info(
                        "start capturing with Sniffer by giving the test case name as filename"
                    )
                    self.wifi_sniffer.interfaces.capture.start_capture(
                        capture_file="sta scan + ble connection as a slave_selective_channels_5"
                    )
                    logger().info("Setting DUT in wlan power save...")
                    self.wifi_dut.interfaces.wifi.power_save(
                        RS9116PowerSaveModes.PowerSaveMode2, 1
                    )
                    logger().info("Setting DUT in bt power save...")
                    self.wifi_dut.interfaces.wifi.bt_power_save(
                        RS9116PowerSaveModes.PowerSaveMode2, 1
                    )
                    logger().info(
                        f"enables the scan in DUT with the given channel bitmap value"
                    )
                    with TimeMeasurer() as t:
                        ap_mac = self.wifi_dut.interfaces.wifi.scan_selective_channel(
                            channel=0,
                            ssid=None,
                            scan_bitmap_5=channel_bitmap_5,
                            scan_feature=scan_feature_extend,
                        )
                    logger().info(f"scan in {t.duration} seconds")
                    assert t.duration < 0.7
                    logger().info(ap_mac)
                    assert len(ap_mac) >= 1
                    channel_selected = 0
                    for count in ap_mac:
                        for device_channel in channel_list:
                            if count.rf_channel == device_channel:
                                channel_selected = channel_selected + 1

                    logger().info(f"Validating Broadcast Probe request")
                    packet_filter1 = f"wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff"
                    time.sleep(5)
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    logger().info("Validating Broadcast Probe request")
                    result = self.wifi_sniffer.interfaces.capture.sniffer_validation(
                        validation, packet_filter1
                    )["packet_count"]
                    logger().info(f"result of probe request is {result} ")
                    if result:
                        flag = False
                        logger().info(
                            f"found Probe req(Broadcast) in channel:{channel}'"
                        )
                    else:
                        flag = True
                    if flag:
                        ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
                        logger().info(f"AP bssid {ap_bssid}")
                        with TimeMeasurer() as t:
                            scan_results = self.wifi_dut.interfaces.wifi.scan(
                                channel=channel, ssid=None
                            )
                            assert len(scan_results) >= 1, "Scan failed"
                            logger().info(scan_results)
                        if ap_bssid.lower() in str(scan_results):
                            logger().info(
                                f"found ap bssid in scan_results for channel {channel}"
                            )
                        else:
                            assert False, "Unable to find ap in scan results"
                        logger().info(f"Scan in {t.duration} seconds")

        if len(self.select_channel_all_2_4):
            channel_list = self.select_channel_all_2_4
            for channel in channel_list:
                logger().info(f"initiates the access point with channel given in list")
                self.wifi_access_point.interfaces.wifi.start_ap(channel=channel)
                validation = True
                logger().info("configuring the Sniffer with the channel")
                self.wifi_sniffer.interfaces.capture.configure_interface(
                    channel=self.wifi_access_point.interfaces.wifi.channel
                )
                logger().info(
                    "start capturing with Sniffer by giving the test case name as filename"
                )
                self.wifi_sniffer.interfaces.capture.start_capture(
                    capture_file="sta scan + ble connection as a slave_selective_channels_2_4"
                )
                logger().info(f"Fetches the DUT mac address")
                dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
                logger().info(f"Device mac address: {dut_mac_address}")
                logger().info(
                    f"enables the scan in DUT with the given channel bitmap value"
                )
                with TimeMeasurer() as t:
                    scan_results = self.wifi_dut.interfaces.wifi.scan(
                        channel=0, ssid=None
                    )
                    assert len(scan_results) >= 1, "Scan failed"
                    logger().info(scan_results)
                logger().info(f"Scan in {t.duration} seconds")
                assert 1.1 < t.duration < 1.5

                logger().info(f"Validating Broadcast Probe request")
                packet_filter1 = (
                    f"wlan_radio.channel == {self.wifi_access_point.interfaces.wifi.channel} and "
                    f"wlan.sa == {dut_mac_address} and wlan.fc.type_subtype == 0x0004 "
                    f"and wlan.da == ff:ff:ff:ff:ff:ff"
                )

                time.sleep(2)
                self.wifi_sniffer.interfaces.capture.stop_capture()
                result = self.wifi_sniffer.interfaces.capture.sniffer_validation(
                    validation, packet_filter1
                )["packet_count"]
                logger().info(f"result of probe request is {result} ")
                if result:
                    flag = False
                    logger().info(f"found Probe req(Broadcast) in channel:{channel}'")
                else:
                    flag = True
                if flag:
                    ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
                    logger().info(f"AP bssid {ap_bssid}")
                    with TimeMeasurer() as t:
                        scan_results = self.wifi_dut.interfaces.wifi.scan(
                            channel=channel, ssid=None
                        )
                        assert len(scan_results) >= 1, "Scan failed"
                        logger().info(scan_results)
                    if ap_bssid.lower() in str(scan_results):
                        logger().info(
                            f"found ap bssid in scan_results for channel {channel}"
                        )
                    else:
                        assert False, "Unable to find ap in scan results"
                    logger().info(f"Scan in {t.duration} seconds")

        if len(self.select_channel_all_5):
            channel_list = self.select_channel_all_5
            for channel in channel_list:
                logger().info(f"initiates the access point for all channels")
                self.wifi_access_point.interfaces.wifi.start_ap(channel=channel)
                validation = True
                logger().info("configuring the Sniffer with the channel")
                self.wifi_sniffer.interfaces.capture.configure_interface(
                    channel=self.wifi_access_point.interfaces.wifi.channel
                )
                logger().info(
                    "start capturing with Sniffer by giving the test case name as filename"
                )
                self.wifi_sniffer.interfaces.capture.start_capture(
                    capture_file="sta scan + ble connection as a slave_selective_channels_2_4"
                )
                logger().info(f"Fetches the DUT mac address")
                dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
                logger().info(f"Device mac address: {dut_mac_address}")
                logger().info(
                    f"enables the scan in DUT with the given channel bitmap value"
                )
                with TimeMeasurer() as t:
                    scan_results = self.wifi_dut.interfaces.wifi.scan(
                        channel=0, ssid=None
                    )
                    assert len(scan_results) >= 1, "Scan failed"
                    logger().info(scan_results)
                logger().info(f"Scan in {t.duration} seconds")
                assert 1.1 < t.duration < 1.5

                logger().info(f"Validating Broadcast Probe request")
                packet_filter1 = (
                    f"wlan_radio.channel == {self.wifi_access_point.interfaces.wifi.channel} and "
                    f"wlan.sa == {dut_mac_address} and wlan.fc.type_subtype == 0x0001 "
                    f"and wlan.da == ff:ff:ff:ff:ff:ff"
                )

                time.sleep(2)
                self.wifi_sniffer.interfaces.capture.stop_capture()
                result = self.wifi_sniffer.interfaces.capture.sniffer_validation(
                    validation, packet_filter1
                )["packet_count"]
                logger().info(f"result of probe_request capture {result}")
                if result:
                    flag = False
                    logger().info(f"found Probe req(Broadcast) in channel:{channel}'")
                else:
                    flag = True
                if flag:
                    ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
                    logger().info(f"AP bssid {ap_bssid.lower()}, {channel}")
                    with TimeMeasurer() as t:
                        scan_results = self.wifi_dut.interfaces.wifi.scan(
                            channel=channel, ssid=None
                        )
                        assert len(scan_results) >= 1, "Scan failed"
                        logger().info(scan_results)
                        logger().info(f"type of scan_results {type(scan_results)}")
                    if ap_bssid.lower() in str(scan_results):
                        logger().info(
                            f"found ap bssid in scan_results for channel {channel}"
                        )
                    else:
                        assert False, "Unable to find ap in scan results"
                    logger().info(f"Scan in {t.duration} seconds")


class ScanThread(ThreadBase):
    def __init__(
            self,
            wifi_dut,
            wifi_access_point,
            wifi_sniffer,
            channel_2_4_list,
            channel_5_list,
            select_channel_all,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.channel_2_4_list = channel_2_4_list
        self.channel_5_list = channel_5_list
        self.select_channel_all = select_channel_all

    def run(self):
        logger().info("Setting DUT in wlan power save...")
        self.wifi_dut.interfaces.wifi.power_save(
            RS9116PowerSaveModes.PowerSaveMode8,
            RS9116PowerSaveProcedureTypes.FastPowerSave,
        )
        logger().info("Setting DUT in bt power save...")
        self.wifi_dut.interfaces.wifi.bt_power_save(
            RS9116PowerSaveModes.PowerSaveMode8,
            RS9116PowerSaveProcedureTypes.FastPowerSave,
        )
        logger().info(f"thread for scan functionality")
        channel_bitmap_2_4 = 0
        channel_bitmap_5 = 0
        if len(self.channel_2_4_list):
            channel_list = self.channel_2_4_list
            scan_expected_time = 0
            for count in channel_list:
                channel_bitmap_2_4 += 1 << (count - 1)
                scan_expected_time += 100
            channel_bitmap_5 = 0
            scan_feature_extend = 0
            for channel in channel_list:
                logger().info(f"initiates the access point with channel given in list")
                self.wifi_access_point.interfaces.wifi.start_ap(channel=channel)
                validation = True
                logger().info("configuring the Sniffer with the channel")
                self.wifi_sniffer.interfaces.capture.configure_interface(
                    channel=self.wifi_access_point.interfaces.wifi.channel
                )
                logger().info(
                    "start capturing with Sniffer by giving the test case name as filename"
                )
                self.wifi_sniffer.interfaces.capture.start_capture(
                    capture_file="sta scan + ble connection as a slave_selective_channels_2_4"
                )
                logger().info(f"Fetches the DUT mac address")
                dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
                logger().info(f"Device mac address: {dut_mac_address}")
                logger().info(
                    f"enables the scan in DUT with the given channel bitmap value"
                )
                with TimeMeasurer() as t:
                    ap_mac = self.wifi_dut.interfaces.wifi.scan_selective_channel(
                        channel=0,
                        ssid=None,
                        scan_bitmap_2_4=channel_bitmap_2_4,
                        scan_feature=scan_feature_extend,
                    )
                    logger().info(ap_mac)
                logger().info(f"Scan in {t.duration} seconds")
                assert t.duration < 0.6
                assert len(ap_mac) >= 1
                channel_selected = 0
                for count in ap_mac:
                    for device_channel in channel_list:
                        if count.rf_channel == device_channel:
                            channel_selected = channel_selected + 1
                logger().info(f"Validating Broadcast Probe request")
                packet_filter1 = (
                    f"wlan_radio.channel == {self.wifi_access_point.interfaces.wifi.channel} and "
                    f"wlan.sa == {dut_mac_address} and wlan.fc.type_subtype == 0x0004 "
                    f"and wlan.da == ff:ff:ff:ff:ff:ff"
                )

                time.sleep(2)
                self.wifi_sniffer.interfaces.capture.stop_capture()
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                    validation, packet_filter1
                )[
                    "packet_count"
                ], "Unable to find Broadcast Probe request packet in sniffer"
                assert channel_selected == len(ap_mac)

        if len(self.channel_5_list):
            channel_list = self.channel_5_list
            logger().info(f" {channel_list}")
            scan_expected_time = 0
            for count in channel_list:
                channel_bitmap_5 += 1 << (count - 1)
                scan_expected_time += 100
            scan_feature_extend = 0
            for channel in channel_list:
                logger().info(f"initiates the access point with channel given in list")
                self.wifi_access_point.interfaces.wifi.start_ap(
                    channel=channel_list[channel]
                )
                with TimeMeasurer() as t:
                    validation = True
                    logger().info("configuring the Sniffer with the channel")
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel
                    )
                    logger().info(
                        "start capturing with Sniffer by giving the test case name as filename"
                    )
                    self.wifi_sniffer.interfaces.capture.start_capture(
                        capture_file="sta scan + ble connection as a slave_selective_channels_5"
                    )
                    logger().info("Setting DUT in wlan power save...")
                    self.wifi_dut.interfaces.wifi.power_save(
                        RS9116PowerSaveModes.PowerSaveMode8, 1
                    )
                    logger().info("Setting DUT in bt power save...")
                    self.wifi_dut.interfaces.wifi.bt_power_save(
                        RS9116PowerSaveModes.PowerSaveMode8, 1
                    )
                    logger().info(
                        f"enables the scan in DUT with the given channel bitmap value"
                    )
                    ap_mac = self.wifi_dut.interfaces.wifi.scan_selective_channel(
                        channel=0,
                        ssid=None,
                        scan_bitmap_5=channel_bitmap_5,
                        scan_feature=scan_feature_extend,
                    )
                    logger().info(ap_mac)
                    assert len(ap_mac) >= 1
                    channel_selected = 0
                    for count in ap_mac:
                        for device_channel in channel_list:
                            if count.rf_channel == device_channel:
                                channel_selected = channel_selected + 1

                    logger().info(f"Validating Broadcast Probe request")
                    packet_filter1 = f"wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff"
                    time.sleep(5)
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    logger().info("Validating Broadcast Probe request")
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                        validation, packet_filter1
                    )[
                        "packet_count"
                    ], "Unable to find Broadcast Probe request packet in sniffer"
                assert t.duration < 25
                logger().info(f"Scan in {t.duration} seconds")

        if self.select_channel_all:
            validation = True
            logger().info("configuring the Sniffer with the channel")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel
            )

            logger().info(
                "start capturing with Sniffer by giving the test case name as filename"
            )
            self.wifi_sniffer.interfaces.capture.start_capture(
                capture_file="sta scan + ble connection as a slave_allchannels"
            )
            with TimeMeasurer() as t:
                logger().info("Setting DUT in wlan power save...")
                self.wifi_dut.interfaces.wifi.power_save(
                    RS9116PowerSaveModes.PowerSaveMode8, 1
                )
                logger().info("Setting DUT in bt power save...")
                self.wifi_dut.interfaces.wifi.bt_power_save(
                    RS9116PowerSaveModes.PowerSaveMode8, 1
                )
                time.sleep(5)
                logger().info(f"enables the scan in dut on channel 0")
                logger().info(f"Scan for the AP's")
                ap_mac = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
                packet_filter1 = (
                    f"wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff"
                )
                logger().info(ap_mac)
                assert len(ap_mac) >= 1
                logger().info(f"Validating Broadcast Probe request")
            assert t.duration < 20
            time.sleep(5)
            self.wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("Validating Broadcast Probe request")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                validation, packet_filter1
            )[
                "packet_count"
            ], "Unable to find Broadcast Probe request packet in sniffer"


class httpgetThread(ThreadBase):
    def __init__(
            self,
            wifi_dut,
            wifi_access_point,
            http_server,
            index_path,
            wifi_sniffer,
            capture_filename,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.http_server = http_server
        self.index_path = index_path
        self.wifi_sniffer = wifi_sniffer
        self.capture_filename = capture_filename

    def run(self):
        logger().info(
            f" *********thread used for http get functionality****************"
        )
        validation = True
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        self.wifi_sniffer.interfaces.capture.start_capture(
            capture_file="http_get + ble connection as a slave"
        )
        logger().info(f"this thread is used for wifi join")
        logger().info(f"Scan for the AP's")
        ap_mac = self.wifi_dut.interfaces.wifi.scan(
            ssid=None, channel=self.wifi_access_point.interfaces.wifi.channel
        )
        ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        logger().info(f"This API Enables the DHCP in DUT")
        result = self.wifi_dut.interfaces.wifi.start_ip()
        logger().info(f"{result}")
        assert isinstance(
            result, self.wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        logger().info("DUT to power save in Wifi+bluetooth mode")
        logger().info("enabling wifi power save")
        enable_wifi_ps = self.wifi_dut.interfaces.wifi.power_save(2, 1)
        assert enable_wifi_ps, "failed to enable"
        logger().info("enabling bt power save")
        enable_bt_ps = self.wifi_dut.interfaces.wifi.bt_power_save(2, 1)
        assert enable_bt_ps, "failed to enable"
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        logger().info(
            f"Validate Probe req(Broadcast/Unicast), authentication ,association, eapol"
        )
        packet_filter1 = (
            f"!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or "
            f"(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or "
            f"(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})"
        )
        logger().info(f"Validating the power management bit")
        packet_filter2 = f"wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}"
        logger().info(f"To verify the dhcp packets")
        packet_filter3 = f"wlan_radio.channel == {self.wifi_access_point.interfaces.wifi.channel} or dhcp && (wlan.addr == {dut_mac_address})"
        time.sleep(2)
        for i in range(0, iter_count):
            self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
            logger().info("This API used to get the http data from the server")
            status, content = self.wifi_dut.interfaces.http.http_get(
                self.http_server.interfaces.http, self.index_path
            )
            logger().info(status)
            logger().info(content)
        time.sleep(5)
        decryption_key = f"{self.wifi_access_point.interfaces.wifi.passphrase}:{self.wifi_access_point.interfaces.wifi.ssid}"
        http_pkt = http_pkt_check(
            self.wifi_sniffer,
            logger,
            decryption_key,
            dut_mac_address,
            self.capture_filename,
        )
        assert http_pkt, "Unable to find http packet"
        self.wifi_dut.interfaces.wifi.leave()
        self.wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Validating Probe req(Broadcast/Unicast)")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            validation, packet_filter1
        )["packet_count"], "Unable to find Probe req(Broadcast/Unicast) in sniffer"
        logger().info(" Validate association request")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            validation, packet_filter2
        )["packet_count"], "Unable to find association request pakcets in sniffer "
        logger().info(" Validate association response")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            validation, packet_filter3
        )["packet_count"], "Unable to find association response in sniffer "


class httppostThread(ThreadBase):
    def __init__(
            self,
            wifi_dut,
            wifi_access_point,
            http_server,
            index_path,
            wifi_sniffer,
            capture_filename,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.http_server = http_server
        self.index_path = index_path
        self.wifi_sniffer = wifi_sniffer
        self.capture_filename = capture_filename

    def run(self):
        logger().info(
            " *********thread used for http post functionality**************** "
        )
        validation = True
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        self.wifi_sniffer.interfaces.capture.start_capture(
            # capture_file="testcase for http post download with ble"
            capture_file=self.capture_filename
        )
        logger().info(f"this thread is used for wifi join")
        logger().info(f"Scan for the AP's")
        self.wifi_dut.interfaces.wifi.scan(ssid=None)
        ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        self.wifi_dut.interfaces.wifi.start_ip()
        time.sleep(2)
        logger().info("DUT to power save in Wifi+bluetooth mode")
        logger().info("enabling wifi power save")
        enable_wifi_ps = self.wifi_dut.interfaces.wifi.power_save(2, 1)
        assert enable_wifi_ps, "failed to enable"
        logger().info("enabling bt power save")
        enable_bt_ps = self.wifi_dut.interfaces.wifi.bt_power_save(2, 1)
        assert enable_bt_ps, "failed to enable"
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
        time.sleep(5)
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        time.sleep(2)
        logger().info(
            f"Validate Probe req(Broadcast/Unicast), authentication ,association, eapol"
        )
        packet_filter1 = (
            f"!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or "
            f"(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or "
            f"(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})"
        )
        logger().info(f"Validating the power management bit")
        packet_filter2 = f"wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}"
        logger().info(f"To verify the dhcp packets")
        packet_filter3 = f"wlan_radio.channel == {self.wifi_access_point.interfaces.wifi.channel} or dhcp && (wlan.addr == {dut_mac_address})"
        time.sleep(2)
        for i in range(0, iter_count):
            self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
            logger().info("API used to post the http data")
            status, content = self.wifi_dut.interfaces.http.http_post(
                self.http_server.interfaces.http,
                "cgi-bin/cgi_example.py",
                post_data="hellothisiaatestcaseforget",
            )
            assert status, "failed to post http data"
            assert content, "failed to post http data"
            logger().info(status)
            logger().info(content)
        time.sleep(10)
        logger().info("Initiating WLAN Disconnect")
        self.wifi_dut.interfaces.wifi.leave()
        self.wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("http packet check")
        decryption_key = f"{self.wifi_access_point.interfaces.wifi.passphrase}:{self.wifi_access_point.interfaces.wifi.ssid}"
        http_pkt = http_pkt_check(
            self.wifi_sniffer,
            logger,
            decryption_key,
            dut_mac_address,
            self.capture_filename,
        )
        assert http_pkt, "Unable to find http packet"
        logger().info("Validating Probe req(Broadcast/Unicast)")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            validation, packet_filter1
        )["packet_count"], "Unable to find Probe req(Broadcast/Unicast) in sniffer"
        logger().info(" Validate association request")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            validation, packet_filter2
        )["packet_count"], "Unable to find association request pakcets in sniffer "
        logger().info(" Validate association response")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            validation, packet_filter3
        )["packet_count"], "Unable to find association response in sniffer "


class WifiDeeppowersave(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, wifi_sniffer=None, testcase=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase

    def run(self):
        logger().info("Setting DUT in wlan power save...")
        self.wifi_dut.interfaces.wifi.power_save(
            RS9116PowerSaveModes.PowerSaveMode8,
            RS9116PowerSaveProcedureTypes.FastPowerSave,
        )
        logger().info("Setting DUT in bt power save...")
        self.wifi_dut.interfaces.wifi.bt_power_save(
            RS9116PowerSaveModes.PowerSaveMode8,
            RS9116PowerSaveProcedureTypes.FastPowerSave,
        )
        validation = True

        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        self.wifi_sniffer.interfaces.capture.start_capture(
            "sta_deeppowersave +  ble connection "
        )
        time.sleep(10)
        logger().info(f"use the corresponding hex file when using gpio and msg based")
        logger().info(f"this thread is used for wifi join")
        with TimeMeasurer() as t:
            logger().info(f"Scan for the AP's")
            self.wifi_dut.interfaces.wifi.scan(
                ssid=None, channel=self.wifi_access_point.interfaces.wifi.channel
            )
            ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP bssid {ap_bssid}")
            logger().info(f"Join Wi-Fi Access Point")
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
            logger().info(f"This API Enables the DHCP in DUT")
            device_ip = None
            for ip_count in range(5):
                try:
                    result = self.wifi_dut.interfaces.wifi.start_ip()
                    assert isinstance(result,
                                      self.wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {result}"
                    device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
                    break
                except Exception as err:
                    logger().info(f"IP setting in DUT is failed...retry_count:{ip_count + 1}\nException:{err}")
                    time.sleep(120)
            assert device_ip, "Failed to fetch DUT ip address"
            # result = self.wifi_dut.interfaces.wifi.start_ip()
            # assert isinstance(
            #     result, self.wifi_dut.interfaces.wifi.IPConfig
            # ), f"Failed to get IP address. Result = {result}"
            # device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode("utf-8")
            logger().info(f"Fetches the DUT mac address")
            dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"Device mac address: {dut_mac_address}")
            time.sleep(5)
            logger().info(
                f"Validate Probe req(Broadcast/Unicast), authentication ,association, eapol"
            )
            packet_filter1 = (
                f"!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or "
                f"(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or "
                f"(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})"
            )
            logger().info(f"Initiate ping from third party wifi-client to DUT")
            status = ping(device_ip, ping_count)
            assert status == 1, "DUT not responding for ping request......"
            logger().info("ping to DUT is successful....")
        logger().info(f"Associated and ping, Scan in {t.duration} seconds")
        self.wifi_sniffer.interfaces.capture.stop_capture()
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            validation, packet_filter1
        )["packet_count"], (
            "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet "
            "in sniffer"
        )


def packet_check(
        wifi_sniffer,
        logger,
        decryption_key: str,
        dut_mac_address,
        ap_bssid,
        print_layers: list,
        capture_filename,
        mode=0,
) -> list:
    current_time = time.time()
    updated_capture_file = (
            "filter_"
            + capture_filename
            + "_"
            + str(datetime.fromtimestamp(current_time).strftime("%H_%M_%S"))
    )
    file_name = f"./reports/{updated_capture_file}.pcap"
    local_capture_file = file_name
    result = []
    wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
    packet_filter1 = f"(wlan.addr == {dut_mac_address}) && (wlan.addr == {ap_bssid})"
    wifi_sniffer.interfaces.capture.shell(
        f"tshark -nr {wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter1}' -T fields -e "
        f"frame.number -w "
        f"{wlan_filter_file}"
    )
    with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
        sftp.get(wlan_filter_file, local_capture_file)
    for packet in wifi_sniffer.interfaces.capture.iter_packets(
            decrypt_packets=True,
            encryption_type="WPA-PWD",
            decryption_key=decryption_key,
            capture_file_filter=local_capture_file,
    ):

        for layer in packet.layers:
            layer_name = layer.layer_name.lower()
            if layer_name == "tls":
                filtered_packet = str(packet)
                filtered_packet = filtered_packet.split("Layer ")
                tls_layer_pkt = ""
                ra_address = ""
                ta_address = ""
                logger().info(
                    f"DUT_MAC_ADDRESS: {dut_mac_address},AP_BSSID: {ap_bssid}"
                )
                for layerp in filtered_packet:
                    if (
                            re.search(".*Receiver address:", layerp)
                            and re.search(".*Transmitter address:", layerp)
                    ) or (re.search(".*TLS:", layerp)):
                        if re.search(".*TLS:", layerp):
                            tls_layer_pkt = layerp
                        if re.search(".*Receiver address:", layerp) and re.search(
                                ".*Transmitter address:", layerp
                        ):
                            Received = re.compile(
                                r"Receiver address: (([0-9a-fA-F]:?){12})"
                            )
                            receiver_address = re.search(Received, layerp).group()
                            ra_address = (re.search(Received, layerp).group(1)).lower()
                            Transmit = re.compile(
                                r"Transmitter address: (([0-9a-fA-F]:?){12})"
                            )
                            Transmitter_address = re.search(Transmit, layerp).group()
                            ta_address = (re.search(Transmit, layerp).group(1)).lower()
                            dut_mac_address_mod = dut_mac_address.lower()
                            ap_bssid_mod = ap_bssid.lower()

                        if (
                                (
                                        ra_address == dut_mac_address_mod
                                        or ra_address == ap_bssid_mod
                                )
                                and (
                                        ta_address == dut_mac_address_mod
                                        or ta_address == ap_bssid_mod
                                )
                        ) and tls_layer_pkt:
                            logger().info(
                                f"{Transmitter_address}>>>>>>{receiver_address}"
                            )
                            logger().info(f"TLS HANDSHAKE PACKET: {tls_layer_pkt}")
                            result.append(str(tls_layer_pkt))
    return result


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode
                    | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.Default
                       | RS9116BTFeatureBitMap.A2DPProfileEnable
                       | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "band": 0,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "disassociated",
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
def test_scantime_all_channels_2_4g_ble_advertise_C20207(
        wifi_dut, wifi_access_point, wifi_sniffer, ble_client
):
    channel_2_4_list = []
    channel_5_list = []
    select_channel_all_5 = []
    select_channel_all_2_4 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    ble_mode = "ble_slave"
    scan_obj = wifi_ScanThread(
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        channel_2_4_list,
        channel_5_list,
        select_channel_all_2_4,
        select_channel_all_5,
    )
    ble_obj = Ble_continuous_advertise_and_connection_thread(
        wifi_dut, ble_client, ble_mode, connect=False
    )
    try:
        scan_obj.start()
        time.sleep(1)
        ble_obj.start()
        scan_obj.wait_for_exit()
        ble_obj.wait_for_exit()
    finally:
        clean_up_method(wifi_dut, ble_client)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode
                    | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.Default
                       | RS9116BTFeatureBitMap.A2DPProfileEnable
                       | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "band": 0,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "disassociated",
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
def test_threading_selective_channels_2_4_C20208(
        wifi_dut, wifi_access_point, wifi_sniffer, ble_client
):
    channel_2_4_list = [1, 6, 11]
    channel_5_list = []
    select_channel_all_5 = []
    select_channel_all_2_4 = []
    ble_mode = "ble_slave"
    scan_obj = wifi_ScanThread(
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        channel_2_4_list,
        channel_5_list,
        select_channel_all_2_4,
        select_channel_all_5,
    )
    ble_obj = Ble_continuous_advertise_and_connection_thread(
        wifi_dut, ble_client, ble_mode, connect=True
    )
    try:
        scan_obj.start()
        time.sleep(5)
        ble_obj.start()
        scan_obj.wait_for_exit()
        ble_obj.wait_for_exit()
    finally:
        clean_up_method(wifi_dut, ble_client)


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
                              | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "region_code": RS9116RegionCode.US,
        "band": 1,
    },
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "disassociated",
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
def test_scantime_selective_channels_5g_ble_advertise_bypass_C20209(
        wifi_dut, wifi_access_point, wifi_sniffer, ble_client
):
    channel_2_4_list = []
    channel_5_list = []
    select_channel_all_5 = [36, 40, 44, 48, 149, 153, 157, 161, 165]
    select_channel_all_2_4 = []
    ble_mode = "ble_slave"
    scan_obj = wifi_ScanThread(
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        channel_2_4_list,
        channel_5_list,
        select_channel_all_2_4,
        select_channel_all_5,
    )
    ble_obj = Ble_continuous_advertise_and_connection_thread(
        wifi_dut, ble_client, ble_mode, connect=False
    )
    try:
        scan_obj.start()
        time.sleep(1)
        ble_obj.start()
        scan_obj.wait_for_exit()
        ble_obj.wait_for_exit()
    finally:
        clean_up_method(wifi_dut, ble_client)


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
                              | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "region_code": RS9116RegionCode.US,
        "band": 1,
    },
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "disassociated",
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
def test_scantime_selective_channels_5g_ble_advertise_bypass_C20210(
        wifi_dut, wifi_access_point, wifi_sniffer, ble_client
):
    channel_2_4_list = []
    channel_5_list = [36, 40, 44]
    select_channel_all_5 = []
    select_channel_all_2_4 = []
    ble_mode = "ble_slave"
    scan_obj = wifi_ScanThread(
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        channel_2_4_list,
        channel_5_list,
        select_channel_all_2_4,
        select_channel_all_5,
    )
    ble_obj = Ble_continuous_advertise_and_connection_thread(
        wifi_dut, ble_client, ble_mode, connect=False
    )
    try:
        scan_obj.start()
        time.sleep(1)
        ble_obj.start()
        scan_obj.wait_for_exit()
        ble_obj.wait_for_exit()
    finally:
        clean_up_method(wifi_dut, ble_client)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
                              | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "band": RS9116Band.Default,
        "region_code": RS9116RegionCode.US,
    },
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "security": "WPA2",
        "passphrase": "thisisapassword",
        "standard": "11n",
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "disassociated",
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
def test_sta_ble_rejoin_deauth_C20219(
        wifi_dut, wifi_access_point, wifi_sniffer, ble_client
):
    try:
        ble_mode = "ble_slave"
        testcase = "rejoin_deauth + ble connection"
        logger().info(f"Starting ble connection in {ble_mode} mode")
        ble_client_address, ble_dut_address = ble_master_slave(
            wifi_dut, ble_client, ble_mode
        )
        logger().info(f"ble_dut_address: {ble_dut_address}")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        device_ip = wifi_join(wifi_dut, wifi_access_point)
        logger().info("pinging to dut.....")
        status = ping(device_ip, ping_count)
        assert status == 1, "DUT not responding for ping request......"
        logger().info("ping to DUT is successful....")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {bssid}")
        logger().info(f"validate QOS data frame with more data bit set to '1'")
        packet_filter = (
            f" (wlan.fc.moredata == 1) and ((wlan.fc.type_subtype == 0x0028) and "
            f"(wlan.ra == {dut_mac_address}) and (wlan.ta == {bssid}))"
        )
        logger().info("Validating more data bit in QOS data frames")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(True, packet_filter)[
            "packet_count"
        ], "Sniffer validation failed for QOS data frame with more data bit 1"
        wifi_access_point.interfaces.wifi.start_ap(security="OPEN")

        logger().info("Wait for 10 sec for DUT to get disconnected from Wi-Fi")
        time.sleep(10)

        wifi_access_point.interfaces.wifi.config["passphrase"] = "thisisapassword"
        wifi_access_point.interfaces.wifi.config["standard"] = "11n"
        wifi_access_point.interfaces.wifi.start_ap(security="WPA2")
        logger().info("Start pinging to dut.....")
        status = ping(device_ip, ping_count)
        assert status == 1, "DUT not responding for ping request......"
        logger().info("ping to DUT is successful....")
    finally:
        clean_up_method(wifi_dut, ble_client)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
                              | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "band": RS9116Band.Default,
        "region_code": RS9116RegionCode.US,
    },
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={"security": "WPA2", "passphrase": "thisisapassword", "standard": "11n"},
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "disassociated",
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
def test_connect_disconnect_ap_after_ble_slave_connection_C20220(
        wifi_dut, wifi_access_point, utf_constants, wifi_sniffer, ble_client
):
    ping_count = utf_constants.get('ping_count')
    ble_mode = "ble_slave"
    testcase = "connect_disconnect_ap_ble_connection"
    logger().info(f"ble mode: {ble_mode}")
    logger().info(f"Starting ble connection in {ble_mode} mode")
    try:
        ble_client_address, ble_dut_address = ble_master_slave(
            wifi_dut, ble_client, ble_mode
        )
        logger().info(f"ble_dut_address: {ble_dut_address}")

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        device_ip = wifi_join(wifi_dut, wifi_access_point)
        logger().info("pinging to dut.....")
        status = ping(device_ip, ping_count)
        assert status == 1, "DUT not responding for ping request......"
        logger().info("ping to DUT is successful....")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {bssid}")

        # validate NULL data frame with PM bit set to '1'
        packet_filter1 = (
            f" (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and "
            f"(wlan.sa == {dut_mac_address}) and (wlan.da == {bssid}))"
        )
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Validation for NULL packet with pm bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(True, packet_filter1)[
            "packet_count"
        ], "Sniffer validation failed for NULL data frame with PM bit 1"

        logger().info("Disconnecting DUT and AP")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Reconnect DUT and AP after 10 sec")
        time.sleep(10)
        logger().info("Joining back after disconnecting and checking for ping ")
        device_ip = wifi_join(wifi_dut, wifi_access_point)
        logger().info("pinging to dut.....")
        status = ping(device_ip, ping_count)
        assert status == 1, "DUT not responding for ping request......"
        logger().info("ping to DUT is successful....")

        logger().info(
            "Checking the connection status of wlan after issuing wlan_connect"
        )
        check_connection_status(wifi_dut, ble=False, wlan=True)
    finally:
        clean_up_method(wifi_dut, ble_client)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
                               | RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "disassociated",
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi={"channel": 4})
def test_sta_ssl_ble_slave_C20232(
        wifi_dut, ble_client, wifi_sniffer, wifi_access_point, ssl_server
):
    ble_mode = "ble_slave"
    testcase = "connect_disconnect_ap_ble_connection"
    logger().info(f"ble mode: {ble_mode}")
    try:
        ble_client_address, ble_dut_address = ble_master_slave(
            wifi_dut, ble_client, ble_mode
        )
        logger().info(f"ble_dut_address: {ble_dut_address}")
        pkt_count = ssl_server.interfaces.ssl.config["no_of_pkts"]
        buffer_length = ssl_server.interfaces.ssl.config["buffer_length"]
        port1 = ssl_server.interfaces.ssl.config["device_port1"]
        bytes_sent = pkt_count * buffer_length

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        wifi_join(wifi_dut, wifi_access_point)

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {bssid}")

        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port1)

        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(
            protocol=SocketOptions.SSL_ENABLE
        )
        assert sock == 0, f"socket id received is wrong, expected is 0"
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(
            sock,
            SocketOptions.SOL_SOCKET,
            SocketOptions.SO_SSL_ENABLE,
            SocketOptions.SSL_ENABLE,
        )
        wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(
            sock, ssl_server.interfaces.ssl, server_port=port1
        )

        socket = 1
        ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)

        if ssl_server.interfaces.ssl.config["type"] == "ssl.server.ssl_linux":
            if ssl_server.interfaces.ssl.socket_connection_status(socket):
                wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
                time.sleep(10)
                bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
                assert bytes_sent == bytes_received, (
                    f"Number of bytes sent by DUT and received on the remote "
                    f"peer not matched on socket {socket} "
                )
        # Close socket 1
        wifi_dut.interfaces.wifi.close_socket(sock)
        ssl_server.interfaces.ssl.stop_server()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        # PS Polls with Power Management Bit set to 1 should be sent from the device
        packet_filter1 = (
            f"wlan.ta == {bssid} && wlan.da == {dut_mac_address} && wlan.fc.moredata==1"
        )

        # Data validating
        packet_filter2 = (
            f"(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)"
        )

        validation = True
        # Validating dhcp packet
        logger().info(f"Validating DHCP frames from AP & DUT")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"decryption_key : {decryption_key}")
        dhcp_list = wifi_sniffer.interfaces.capture.get_dhcp_list(
            dut_mac_address, decryption_key, ["dhcp"]
        )
        logger().info(f"dhcp_list : {dhcp_list}")
        assert dhcp_list, "DHCP packets not found"

        logger().info("QOS data Packets should be observed with More data Bit set to 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            validation, packet_filter1
        )["packet_count"], "Sniffer validation failed for QOS data Packets"

        logger().info(
            "Validating PS Poll frames are sent from the device with power management bit"
        )
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            validation, packet_filter2
        )["packet_count"], "Sniffer validation failed for ps-poll frame with PM bit 1"

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"DECRYPTION KEY-->{decryption_key}")
        ssl_pkt = packet_check(
            wifi_sniffer,
            logger,
            decryption_key,
            dut_mac_address,
            bssid,
            ["tls"],
            testcase,
        )

        assert (
            message for message in ssl_pkt if "Client Hello" in ssl_pkt
        ), "Unable to find 'Client Hello' message"
        assert (
            message for message in ssl_pkt if "Server Hello" in ssl_pkt
        ), "Unable to find 'Server Hello' message"
        assert (
            message for message in ssl_pkt if "Client Key Exchange" in ssl_pkt
        ), "Unable to find 'Client Key Exchange' message"
        assert (
            message for message in ssl_pkt if "Change Cipher Spec" in ssl_pkt
        ), "Unable to find 'Change Cipher Spec' message"
    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e

    finally:
        clean_up_method(wifi_dut, ble_client)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode
                    | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid
                          | RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.Default
                       | RS9116BTFeatureBitMap.A2DPProfileEnable
                       | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,
        "band": 0,
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index_long_crlf.html"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi={"channel": 3})
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "disassociated",
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
def test_threading_httpgetfunctionality_ble_C20339(
        wifi_dut, wifi_access_point, http_server, index_path, wifi_sniffer, ble_client
):
    capture_filename = "test_threading_httpgetfunctionality_ble_C20339"
    ble_mode = "ble_slave"
    httpget_obj = httpgetThread(
        wifi_dut,
        wifi_access_point,
        http_server,
        index_path,
        wifi_sniffer,
        capture_filename,
    )
    ble_obj = Ble_continuous_advertise_and_connection_thread(
        wifi_dut, ble_client, ble_mode, connect=True
    )
    try:
        ble_obj.start()
        time.sleep(5)
        httpget_obj.start()
        httpget_obj.wait_for_exit()
        ble_obj.wait_for_exit()

    finally:
        clean_up_method(wifi_dut, ble_client)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode
                    | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.Default
                       | RS9116BTFeatureBitMap.A2DPProfileEnable
                       | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,
        "band": 0,
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index_long_crlf.html"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_access_point", wifi={"channel": 3})
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "disassociated",
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
def test_threading_httppostfunctionality_ble_C20236(
        wifi_dut, wifi_access_point, http_server, index_path, wifi_sniffer, ble_client
):
    ble_mode = "ble_slave"
    capture_filename = "test_threading_httppostfunctionality_ble_C20236"
    httppost_obj = httppostThread(
        wifi_dut,
        wifi_access_point,
        http_server,
        index_path,
        wifi_sniffer,
        capture_filename,
    )
    ble_obj = Ble_continuous_advertise_and_connection_thread(
        wifi_dut, ble_client, ble_mode, connect=True
    )
    try:
        ble_obj.start()
        time.sleep(5)
        httppost_obj.start()
        ble_obj.wait_for_exit()
        httppost_obj.wait_for_exit()
    finally:
        clean_up_method(wifi_dut, ble_client)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode
                    | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.Default
                       | RS9116BTFeatureBitMap.A2DPProfileEnable
                       | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "band": 0,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "disassociated",
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
def test_scantime_all_channels_2_4g_ble_advertise_bypass_C20248(
        wifi_dut, wifi_access_point, wifi_sniffer, ble_client
):
    channel_2_4_list = []
    channel_5_list = []
    select_channel_all_5 = []
    select_channel_all_2_4 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    ble_mode = "ble_slave"
    scan_obj = wifi_ScanThread(
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        channel_2_4_list,
        channel_5_list,
        select_channel_all_2_4,
        select_channel_all_5,
    )
    ble_obj = Ble_continuous_advertise_and_connection_thread(
        wifi_dut, ble_client, ble_mode, connect=False
    )
    try:
        scan_obj.start()
        time.sleep(1)
        ble_obj.start()
        scan_obj.wait_for_exit()
        ble_obj.wait_for_exit()
    finally:
        clean_up_method(wifi_dut, ble_client)


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
                              | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "region_code": RS9116RegionCode.US,
        "band": 0,
    },
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "disassociated",
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
def test_scantime_selective_channels_2_4g_ble_advertise_bypass_C20249(
        wifi_dut, wifi_access_point, wifi_sniffer, ble_client
):
    channel_2_4_list = [1, 6, 11]
    channel_5_list = []
    select_channel_all_5 = []
    select_channel_all_2_4 = []
    ble_mode = "ble_slave"
    scan_obj = wifi_ScanThread(
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        channel_2_4_list,
        channel_5_list,
        select_channel_all_2_4,
        select_channel_all_5,
    )
    ble_obj = Ble_continuous_advertise_and_connection_thread(
        wifi_dut, ble_client, ble_mode, connect=False
    )
    try:
        scan_obj.start()
        time.sleep(1)
        ble_obj.start()
        scan_obj.wait_for_exit()
        ble_obj.wait_for_exit()
    finally:
        clean_up_method(wifi_dut, ble_client)


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
                              | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "region_code": RS9116RegionCode.US,
        "band": 1,
    },
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "disassociated",
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
def test_scantime_selective_channels_5g_ble_advertise_bypass_C20250(
        wifi_dut, wifi_access_point, wifi_sniffer, ble_client
):
    channel_2_4_list = []
    channel_5_list = []
    select_channel_all_5 = [36, 40, 44, 48, 149, 153, 157, 161, 165]
    select_channel_all_2_4 = []
    ble_mode = "ble_slave"
    scan_obj = wifi_ScanThread(
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        channel_2_4_list,
        channel_5_list,
        select_channel_all_2_4,
        select_channel_all_5,
    )
    ble_obj = Ble_continuous_advertise_and_connection_thread(
        wifi_dut, ble_client, ble_mode, connect=False
    )
    try:
        scan_obj.start()
        time.sleep(1)
        ble_obj.start()
        scan_obj.wait_for_exit()
        ble_obj.wait_for_exit()
    finally:
        clean_up_method(wifi_dut, ble_client)


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config("wifi_access_point", wifi={"ssid": "test_C20251", "channel": 36})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
                              | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "region_code": RS9116RegionCode.US,
        "band": 1,
    },
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "disassociated",
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
def test_scantime_selective_channels_5g_ble_advertise_bypass_C20251(
        wifi_dut, wifi_access_point, wifi_sniffer, ble_client
):
    channel_2_4_list = []
    channel_5_list = [36, 40, 44]
    select_channel_all_5 = []
    select_channel_all_2_4 = []
    ble_mode = "ble_slave"
    scan_obj = wifi_ScanThread(
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        channel_2_4_list,
        channel_5_list,
        select_channel_all_2_4,
        select_channel_all_5,
    )
    ble_obj = Ble_continuous_advertise_and_connection_thread(
        wifi_dut, ble_client, ble_mode, connect=False
    )
    try:
        scan_obj.start()
        time.sleep(1)
        ble_obj.start()
        scan_obj.wait_for_exit()
        ble_obj.wait_for_exit()
    finally:
        clean_up_method(wifi_dut, ble_client)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
                              | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "region_code": RS9116RegionCode.US,
        "band": RS9116Band.Default,
    },
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={"security": "WPA2", "passphrase": "thisisapassword", "standard": "11n"},
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "disassociated",
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
def test_wlan_disconnection_functionality_after_ble_connection_C20261(
        wifi_dut, wifi_access_point, utf_constants, wifi_sniffer, ble_client
):
    validation = True
    ble_mode = "ble_slave"
    testcase = "wlan_disconnection_functionality_after_ble_connection"
    logger().info(f"ble mode: {ble_mode}")
    logger().info(f"Starting ble connection in {ble_mode} mode")
    try:
        ble_client_address, ble_dut_address = ble_master_slave(
            wifi_dut, ble_client, ble_mode
        )
        logger().info(f"ble_dut_address: {ble_dut_address}")

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        device_ip = wifi_join(wifi_dut, wifi_access_point)
        assert device_ip, "Unable to fetch dhcp ip"

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {bssid}")

        logger().info(
            "waiting for 60 seconds to check the connection status of STA and BLE"
        )
        time.sleep(60)

        check_connection_status(wifi_dut, wlan=True)

        logger().info("Issue Disconnection from DUT to AP")
        wifi_dut.interfaces.wifi.leave()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = f"((wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0) || eapol) and ((wlan.addr == {bssid} && wlan.fc.type_subtype == 1) || eapol)"
        packet_filter2 = (
            f" (dhcp) && (wlan.addr == {bssid}) && (wlan.addr == {dut_mac_address})"
        )
        packet_filter3 = (
            f" (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x001a) and (wlan.ta == {dut_mac_address}) "
            f"and (wlan.ra == {bssid}))"
        )
        packet_filter4 = (
            f" (wlan.fc.moredata == 1) and ((wlan.fc.type_subtype == 0x0028) and (wlan.ra == {dut_mac_address}) "
            f"and (wlan.ta == {bssid}))"
        )
        packet_filter5 = f"((wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype == 10 || wlan.fc.type_subtype == 12))"

        logger().info(f"Validate association request and association response packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            validation, packet_filter1
        )[
            "packet_count"
        ], "Unable to find association request and association response packets"

        # Validating dhcp packet
        logger().info(f"Validating DHCP frames from AP & DUT")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"decryption_key : {decryption_key}")
        dhcp_list = wifi_sniffer.interfaces.capture.get_dhcp_list(
            dut_mac_address, decryption_key, ["dhcp"]
        )
        logger().info(f"dhcp_list : {dhcp_list}")
        assert dhcp_list, "DHCP packets not found"

        # validate NULL data frame with PM bit set to '1'
        logger().info(
            "Validating PS Poll frames are sent from the device with power management bit"
        )
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            validation, packet_filter3
        )["packet_count"], "Sniffer validation failed for ps-poll frame with PM bit 1"

        logger().info("Validating more data bit in QOS data frames")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            validation, packet_filter4
        )[
            "packet_count"
        ], "Sniffer validation failed for QOS data frame with more data bit 1"

        # Validating Disassociation or Deauth frame
        logger().info("Validating disassoc or deauth frame")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            validation, packet_filter5
        ), "Unable to find de-auth or disassoc packets in sniffer"
    finally:
        clean_up_method(wifi_dut, ble_client)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode
                    | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.Default
                       | RS9116BTFeatureBitMap.A2DPProfileEnable
                       | RS9116BTFeatureBitMap.A2DPSourceRoleEnable,
        "band": 0,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "disassociated",
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
def test_threading_sta_deeppowersave_ble_C20274(
        wifi_dut, wifi_access_point, wifi_sniffer, ble_client
):
    ble_mode = "ble_slave"
    try:
        wifidp_obj = WifiDeeppowersave(wifi_dut, wifi_access_point, wifi_sniffer)
        ble_obj = Ble_continuous_advertise_and_connection_thread(
            wifi_dut, ble_client, ble_mode, connect=True
        )
        wifidp_obj.start()
        time.sleep(1)
        ble_obj.start()
        wifidp_obj.wait_for_exit()
        ble_obj.wait_for_exit()
    finally:
        clean_up_method(wifi_dut, ble_client)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
                              | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "band": RS9116Band.Default,
        "region_code": RS9116RegionCode.US,
    },
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={"security": "WPA2", "passphrase": "thisisapassword", "standard": "11n", },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "disassociated",
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
def test_sta_rejoin_maximum_retry_with_ble_C20259_case1(
        wifi_dut, wifi_access_point, wifi_sniffer, ble_client, switch, utf_constants
):
    try:
        logger().info("******* Infinite retry there should not be any rejoin error Positive case assert if any rejoin "
                      "error *********")
        iter_count = utf_constants.get('iter_count')
        ble_mode = "ble_slave"
        testcase = "rejoin_deauth + ble connection"
        logger().info(f"Starting ble connection in {ble_mode} mode")
        ble_client_address, ble_dut_address = ble_master_slave(
            wifi_dut, ble_client, ble_mode
        )
        logger().info(f"ble_dut_address: {ble_dut_address}")
        logger().info("configuring the Sniffer with the channel")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40,
                                        first_time_retry=0)
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap_bssid : {ap_bssid}")

        wifi_join(wifi_dut, wifi_access_point, tcp_ip_bypass=True)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        for i in range(1, iter_count):
            logger().info(f"\n\n ****** Turn on switch and turn off for iteration   ****** {i}")
            switch.interfaces.pdu_switch.turn_off(delay=60)
            sw = Stopwatch()
            rejoin_msg = 0
            end_time = 500
            while sw.elapsed_sec <= end_time:
                events = wifi_dut.interfaces.wifi.get_async_events()
                if len(events):
                    for event in events:
                        if event.event_type == RS9116AsyncEventType.RejoinError:
                            rejoin_msg = 1
                            logger().info(
                                "******** Rejoin error found from DUT, which is expected as per the test step ********")
                if rejoin_msg:
                    break
            switch.interfaces.pdu_switch.turn_on(delay=60)
            if rejoin_msg:
                try:
                    wifi_dut.interfaces.wifi.leave()
                    wifi_join(wifi_dut, wifi_access_point, tcp_ip_bypass=True)
                except:
                    pass
    finally:
        switch.interfaces.pdu_switch.turn_on(delay=60)
        clean_up_method(wifi_dut, ble_client)


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
                              | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "band": RS9116Band.Default,
        "region_code": RS9116RegionCode.US,
    },
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={"security": "WPA2", "passphrase": "thisisapassword", "standard": "11n", },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "disassociated",
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
def test_sta_rejoin_maximum_retry_with_ble_C20259_case2(
        wifi_dut, wifi_access_point, wifi_sniffer, ble_client, switch, utf_constants
):
    try:
        logger().info(" ************ Negative case rejoin error should come after 50 retry asserting id there is no rejoin error *****")
        iter_count = utf_constants.get('iter_count')
        ble_mode = "ble_slave"
        testcase = "rejoin_deauth + ble connection"
        logger().info(f"Starting ble connection in {ble_mode} mode")
        ble_client_address, ble_dut_address = ble_master_slave(
            wifi_dut, ble_client, ble_mode
        )
        logger().info(f"ble_dut_address: {ble_dut_address}")
        logger().info("configuring the Sniffer with the channel")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=50, scan_interval=4, beacon_missedcount=40,
                                        first_time_retry=0)
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap_bssid : {ap_bssid}")

        wifi_join(wifi_dut, wifi_access_point, tcp_ip_bypass=True)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        for i in range(1, iter_count):
            logger().info(f"\n\n ****** Turn on switch and turn off for iteration   ****** {i}")
            switch.interfaces.pdu_switch.turn_off(delay=60)
            sw = Stopwatch()
            rejoin_msg = 0
            end_time = 500
            while sw.elapsed_sec <= end_time:
                events = wifi_dut.interfaces.wifi.get_async_events()
                if len(events):
                    for event in events:
                        if event.event_type == RS9116AsyncEventType.RejoinError:
                            rejoin_msg = 1
                            logger().info(
                                "******** Rejoin error found from DUT, which is expected as per the test step ********")
                if rejoin_msg:
                    break
            switch.interfaces.pdu_switch.turn_on(delay=60)
            assert rejoin_msg == 1, "No rejoin error observed even after 50 maximum retry "
            if rejoin_msg:
                try:
                    wifi_dut.interfaces.wifi.leave()
                    wifi_join(wifi_dut, wifi_access_point, tcp_ip_bypass=True)
                except:
                    pass

    finally:
        switch.interfaces.pdu_switch.turn_on(delay=60)
        clean_up_method(wifi_dut, ble_client)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
                              | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "band": RS9116Band.Default,
        "region_code": RS9116RegionCode.US,
    },
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={"security": "WPA2", "passphrase": "thisisapassword", "standard": "11n", "channel": 4},
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "disassociated",
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
def test_sta_ble_rejoin_deauth_C20260(
        wifi_dut, wifi_access_point, wifi_sniffer, ble_client, utf_constants
):
    try:
        iter_count = utf_constants.get("iter_count")
        ble_mode = "ble_slave"
        testcase = "rejoin_deauth + ble connection"
        logger().info(f"Starting ble connection in {ble_mode} mode")
        ble_client_address, ble_dut_address = ble_master_slave(
            wifi_dut, ble_client, ble_mode
        )
        logger().info(f"ble_dut_address: {ble_dut_address}")
        logger().info("configuring the Sniffer with the channel")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=50, scan_interval=4, beacon_missedcount=40,
                                        first_time_retry=0)
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap_bssid : {ap_bssid}")

        wifi_join(wifi_dut, wifi_access_point, tcp_ip_bypass=True)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        for i in range(1, iter_count):
            testcase = ""
            testcase = testcase + f"_iteration_{i}"
            wifi_sniffer.interfaces.capture.configure_interface(
                channel=wifi_access_point.interfaces.wifi.channel
            )
            wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
            logger().info(f"\n\n ****** Access point is going to turn off  ****** {i}")
            ApWirelessOff(wifi_access_point, wait_time=60)

            logger().info("Stop sniffer capture")
            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter = f"wlan.bssid == {ap_bssid} && (wlan.fc.type_subtype == 0x000c || wlan.fc.type_subtype == " \
                            f"0x000a) "

            assert wifi_sniffer.interfaces.capture.sniffer_validation(
                True, packet_filter
            )["packet_count"], f"Unable to find deauth or disassoc for iteration {i}"

    finally:
        clean_up_method(wifi_dut, ble_client)
