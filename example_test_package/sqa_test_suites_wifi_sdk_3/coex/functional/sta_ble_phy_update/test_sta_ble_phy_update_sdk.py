import pytest
import time
import re
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xBTFeatureBitMap, Si91xBLEFeatureBitMap, \
    Si91xBLECustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xJoinFeatureBitMap
from utf.utils.thread_base import ThreadBase
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf_wiseconnect_3.tests.devices.si91x import Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.utils.stopwatch import Stopwatch
import string
import random
from utf.utf_config import UtfConfig
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from random import choices
from utf.interfaces.bluetooth import BLEDeviceState

"""
    Setup requirement:
        1. Soc board
        2. Raspberry PI4
        3. Access Point with TWT Support(Third Party AP's)
        4. Sniffer(NUC device)

    Test Steps:
        1. Configure the two DUT's with the PHY rate values
        2. Initiates the connection b/w two DUT's.
        3. Fetches the PHY rate values after the connection.
        4. Validates the PHY rates 
        5. Enable the wlan and bt power save mode in dut
        6. Initiate ping from the dut
        7. Validate IPERF, HTTP and SSL Functionality

    Author: Saurabh Sharma

"""


# Define logger
def logger():
    return get_logger(__name__)


class WifiJoinThread(ThreadBase):
    dut_addr = None

    def __init__(
            self,
            wifi_sniffer=None,
            wifi_dut=None,
            wifi_access_point=None,
            wifi_client=None,
            net_perf_client=None,
            protocol=None,
            test_type=None,
            sl_collections=None,
            ping_count=None,
            sniffer_filter=None,
            switch=None,
            pmk_enable=False,
            tcp_ip_bypass=False,
            enc="ccmp",
            timeout=30,
            utf_constants=None,
            traffic_type="TX",
            host_ip=None,
            http_server=None,
            index_path=None,
            ssl_server=None,
            https=0

    ):
        super().__init__()
        # Define all the parameters

        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client
        self.test_type = test_type
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.sniffer_filter = sniffer_filter
        self.switch = switch
        self.pmk_enable = pmk_enable
        self.device_ip = None
        self.dut_mac_address = None
        self.ap_mac_address = None
        self.tcp_ip_bypass = tcp_ip_bypass
        self.enc = enc
        self.timeout = timeout
        self.utf_constants = utf_constants
        self.traffic_type = traffic_type
        self.host_ip = host_ip
        self.http_server = http_server
        self.index_path = index_path
        self.ssl_server = ssl_server
        self.https = https

        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def run(self):
        try:
            if self.test_type == '537937' or self.test_type == '537938':
                logger().info("Method to run http download")
                self.sl_collections.http_file_download(
                    wifi_dut=self.wifi_dut, http_server=self.http_server, index_path=self.index_path,
                    device_ip=self.dut_addr['device_ip'], https=self.https)

            if self.test_type == '537935' or self.test_type == '537936':
                self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f".... Remote device ip :{self.host_ip} ....")
                logger().info(f'**** {WifiJoinThread.dut_addr["device_ip"]} ****')
                self.sl_collections.run_traffic(
                    wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client, protocol=self.protocol,
                    device_ip=WifiJoinThread.dut_addr["device_ip"], host_ip=self.host_ip,
                    traffic_type=self.traffic_type,
                    timeout=self.timeout)

            if self.test_type == '537939' or self.test_type == '537940':
                local_port = 5001

                """ ***** Open ssl server socket in remote device(Raspberry pi or static device) ***** """
                self.ssl_server.interfaces.ssl.start_server(port=local_port, ip_version=4)
                self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f".... Remote device ip :{self.host_ip} ....")
                sock = self.wifi_dut.interfaces.wifi.socket()
                logger().info(f" ******************* Sock ID {sock} ******************** ")

                """ ***** Enable ssl option for socket opened ***** """
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(
                    socket_fd=sock, option_level="SOL_TCP", option_name="TCP_ULP", option_val="tls_1_2")

                self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=self.dut_addr['device_ip'],
                                                   server_port=local_port, timeout=15)

                logger().info(" ***** DUT is connecting to server socket ***** ")
                connect_status = False
                for count in range(5):
                    try:
                        self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=self.host_ip,
                                                                       server_port=local_port)
                        connect_status = True
                        break
                    except:
                        logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                        time.sleep(10)
                assert connect_status, "Socket connection failed in DUT"
                logger().info(" ***** Socket connection is successful ***** ")

                if self.test_type == '537939':
                    sw = Stopwatch()
                    while sw.elapsed_sec < 30:
                        buffer_length = 100
                        tx_buffer = "".join(choices(string.ascii_uppercase + string.digits, k=buffer_length))

                        logger().info(f"DATA TRANSFER -----DUT SENDING DATA ON SOCKET ID")
                        data_length = len(tx_buffer)
                        self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=tx_buffer)
                        data_receive = self.ssl_server.interfaces.ssl.data_recv_content(socket_no=sock + 1,
                                                                                        buffer_size=data_length)
                        logger().info(f"Data received on remote socket opened is {data_receive}")
                        assert tx_buffer == data_receive.decode(), "Data sent by DUT and received on server is matching"

                if self.test_type == '537940':
                    sw = Stopwatch()
                    while sw.elapsed_sec < 30:
                        buffer_length = 50
                        tx_buffer = "".join(choices(string.ascii_uppercase + string.digits, k=buffer_length))
                        pkt_count = 1
                        self.ssl_server.interfaces.ssl.send_data(1, pkt_count, msg_length=50, message=tx_buffer)
                        buffer_rx = self.wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock,
                                                                                       async_timeout=120)

                        assert tx_buffer == buffer_rx, (
                            f"buffer length sent by remote peer and received on the socket id"
                            f" {sock} opened in the DUT is not matched ")

                logger().info(f" ***************** Closing Socket From DUT Side **************** ")
                self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                self.ssl_server.interfaces.ssl.stop_server()

        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

    def join_to_ap(self):

        if not self.wifi_dut.interfaces.wifi.associated:
            self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
            WifiJoinThread.dut_addr = self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, power_save=False,
                associated=self.wifi_dut.interfaces.wifi.associated, retry_count=3, ping_after_power_save=True,
                ping_count=self.ping_count, pmk_enable=self.pmk_enable, tcp_ip_bypass=self.tcp_ip_bypass,
                enc=self.enc
            )
            if not self.tcp_ip_bypass:
                self.device_ip = WifiJoinThread.dut_addr["device_ip"]
            self.dut_mac_address = WifiJoinThread.dut_addr["dut_mac_address"]
            logger().info(
                f"*****************DUT_MAC_ADDR : {self.dut_mac_address}*********************"
            )
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap_bssid : {self.ap_mac_address}")
            return self.dut_addr

    def set_power_save(self):
        if self.power_save:

            self.wifi_dut.interfaces.wifi.set_performance_profile(
                mode="power_save_low_latency"
            )
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(
                psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave,
            )
        else:
            logger().info("skipping power save beacause power save flag set to be false in harness")

    def run_http_download(self):
        logger().info("Method to run http download")
        self.sl_collections.http_file_download(
            wifi_dut=self.wifi_dut, http_server=self.http_server, index_path=self.index_path,
            device_ip=self.dut_addr['device_ip'], https=self.https)


class BleThreadFunctionality(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, sl_collections=None, test_case=None, enable_set_smp=1,
                 ble_dut=None, ble_pairing=0, utf_constants=None, ble_dut_address=None, ble_client_address=None,
                 ble_clients=None, char_uid=None, char_path=None, service_uid=None, remote_wiseconnect3=None,
                 write_handle=None, data=None, tx_phy=1, rx_phy=1, coded_phy=2, address=None, set_smp=0):

        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = ble_dut_address
        self.ble_client_address = ble_client_address
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.ble_dut = ble_dut
        self.ble_pairing = ble_pairing
        self.utf_constants = utf_constants
        self.ble_clients = ble_clients
        self.char_uid = char_uid
        self.char_path = char_path
        self.service_uid = service_uid
        self.remote_wiseconnect3 = remote_wiseconnect3
        self.write_handle = write_handle
        self.tx_phy = tx_phy
        self.rx_phy = rx_phy
        self.coded_phy = coded_phy
        self.data = data
        self.address = address
        self.set_smp = set_smp
        self.enable_set_smp = enable_set_smp

        """ **************** Set up DUT for BLE advertising **************** """
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=self.set_smp)
        assert (self.ble_dut_address is not None), "Unable to fetch bluetooth address from DUT"
        logger().info(f" BLE DUT ADDRESS : {self.ble_dut_address}")
        time.sleep(5)

        logger().info(" ======= start ble remote secondary DUT")
        address = self.remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=self.enable_set_smp)
        self.ble_client_address = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', address).group(0)
        assert self.ble_client_address, "failed to initiate ble in remote dut"
        logger().info(f" BLE CLIENT ADDRESS : {self.ble_client_address}")

    def run(self):
        try:
            if self.test_case == '537939':
                CUSTOM_UUID = '0x2a1e'

                self.remote_wiseconnect3.interfaces.wifi.ble_add_service(uid=0x1809)
                self.remote_wiseconnect3.interfaces.wifi.ble_add_char_serv_att(uid=0x2a1e)
                self.remote_wiseconnect3.interfaces.wifi.ble_add_char_val_att(uid=0x2a1e)

            if self.test_case in [537935, 537936, 537937, 537938, 537940]:
                self.service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
                self.char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
                CUSTOM_NOTIFY_UUID = '0x1aa1'

                self.wifi_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
                self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1)
                self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1)

            if self.test_case in [537935, 537939]:
                self.remote_wiseconnect3.interfaces.wifi.ble_start_advertising()

                logger().info("******************** start scanning in dut ********************")
                self.ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=self.ble_client_address,
                                                                     timeout=100)
                self.ble_dut.interfaces.bluetooth.ble_stop_scanning()

                logger().info(f".... initiating ble connection ....")
                self.ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=self.ble_client_address)

                logger().info("..... checking for ble connection stability ......")
                time.sleep(60)

                state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

                state = self.remote_wiseconnect3.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "Remote DUT BLE device is not in connected state"

            if self.test_case in [537936, 537937, 537938, 537940]:
                self.wifi_dut.interfaces.wifi.ble_start_advertising()

                self.remote_wiseconnect3.interfaces.wifi.ble_start_scanning(
                    ble_client_address=self.ble_dut_address, timeout=100)
                self.remote_wiseconnect3.interfaces.wifi.ble_stop_scanning()

                logger().info(f".... initiating ble connection ....")
                self.remote_wiseconnect3.interfaces.wifi.ble_connect(
                    ble_remote_dev_address=self.ble_dut_address, ble_conn_interval_min=45,
                    ble_conn_interval_max=45)

                logger().info("..... checking for ble connection stability ......")
                time.sleep(60)

                state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

                state = self.remote_wiseconnect3.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "Remote DUT BLE device is not in connected state"

            if self.test_case in [537935, 537936, 537937, 537938, 537940]:
                logger().info(f"******************** get all profiles ********************")
                uuids = self.remote_wiseconnect3.interfaces.wifi.ble_get_profiles_async(
                    ble_remote_dev_address=self.ble_dut_address)
                logger().info(f"******************** Profiles are {uuids} ********************")

                logger().info(" ******************** Resolving Profile ********************")
                start_handle, end_handle, data = self.remote_wiseconnect3.interfaces.wifi.ble_get_profile_async(
                    ble_remote_dev_address=self.ble_dut_address, uuid=int(str(uuids[0]), 16))

                logger().info(f"start_handle:{start_handle} end_handle:{end_handle} data:{data}")
                assert start_handle is not None, "failed to fetch the start handle.."
                assert end_handle is not None, "failed to fetch end handle.."

                char_uuids, write_handles, char_properties = self.remote_wiseconnect3.interfaces.wifi.ble_get_char_services_async(
                    ble_remote_dev_address=self.ble_dut_address,
                    start_handle=int(start_handle, 16),
                    end_handle=int(end_handle, 16),
                    async_timeout=60)
                logger().info(
                    f"characteristics uuids :{char_uuids}  write_handles{write_handles} : Characteristics_properties"
                    f"{char_properties}")

                index = char_uuids.index(CUSTOM_NOTIFY_UUID)
                logger().info(f"UUID's are:{char_uuids}")
                logger().info(f"write_handles:{write_handles}")
                logger().info(f"index:{index}")
                assert char_properties[index].isdigit(), "Character property found is not an integer"

                self.write_handle = int(write_handles[index], 16)
                logger().info(f"write_handle:{self.write_handle}")
                assert self.write_handle > 0, "Unable to get write handle for configured service"

                self.remote_wiseconnect3.interfaces.wifi.ble_set_att_value(
                    ble_remote_dev_address=self.ble_dut_address, handle=(self.write_handle + 1), enable_notify=1)

                if self.test_case == '537935' or self.test_case == '537940':
                    self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
                        ble_remote_dev_address=self.ble_client_address, buffer_mode=0, buffer_count=2)
                if self.test_case == '537936':
                    self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
                        ble_remote_dev_address=self.ble_client_address, buffer_mode=1, buffer_count=2)

            if self.test_case == '537939':
                logger().info(f"******************** get all profiles ********************")
                uuids = self.wifi_dut.interfaces.wifi.ble_get_profiles_async(
                    ble_remote_dev_address=self.ble_client_address)
                logger().info(f"******************** Profiles are {uuids} ********************")

                logger().info(" ******************** Resolving Profile ********************")
                start_handle, end_handle, data = self.wifi_dut.interfaces.wifi.ble_get_profile_async(
                    ble_remote_dev_address=self.ble_client_address, uuid=int(str(uuids[0]), 16))

                logger().info(f"start_handle:{start_handle} end_handle:{end_handle} data:{data}")
                assert start_handle is not None, "failed to fetch the start handle.."
                assert end_handle is not None, "failed to fetch end handle.."

                char_uuids, write_handles, char_properties = self.wifi_dut.interfaces.wifi.ble_get_char_services_async(
                    ble_remote_dev_address=self.ble_client_address,
                    start_handle=int(start_handle, 16),
                    end_handle=int(end_handle, 16),
                    async_timeout=60)
                logger().info(
                    f"characteristics uuids :{char_uuids}  write_handles{write_handles} : Characteristics_properties"
                    f"{char_properties}")

                index = char_uuids.index(CUSTOM_UUID)
                logger().info(f"UUID's are:{char_uuids}")
                logger().info(f"write_handles:{write_handles}")
                logger().info(f"index:{index}")
                assert char_properties[index].isdigit(), "Character property found is not an integer"

                self.write_handle = int(write_handles[index], 16)
                logger().info(f"write_handle:{self.write_handle}")
                assert self.write_handle > 0, "Unable to get write handle for configured service"

                self.wifi_dut.interfaces.wifi.ble_set_att_value(
                    ble_remote_dev_address=self.ble_client_address, handle=(self.write_handle + 1), enable_notify=1)

                self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
                    ble_remote_dev_address=self.ble_client_address, buffer_mode=0, buffer_count=2)

        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

    def ble_data_transfer_tx(self):
        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            self.wifi_dut.interfaces.wifi.ble_notify_custom_value(
                ble_remote_dev_address=self.ble_client_address, data=self.data, data_address=self.address)
            time.sleep(1)
            events = self.remote_wiseconnect3.interfaces.wifi.get_async_events()
            for event in events:
                if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                    logger().info(f"************** BLE EVENT DATA IS : {event.event_data} **************")
                    if self.test_case == 537935 or self.test_case == 537940:
                        received_data = re.findall(r"(\b[A-Z0-9]{20}\b)", event.event_data)
                        logger().info(f"******* Received Data on DUT : {received_data} ********")
                        assert received_data == [self.data], "data mismatched"
                    if self.test_case == '537936':
                        received_data_max = re.findall(r"(\b[A-Z0-9]{237}\b)", event.event_data)
                        logger().info(f"******* Received Data on DUT : {received_data_max} ********")
                        # assert received_data_max == [self.data], "data mismatched"

        time.sleep(5)
        self.remote_wiseconnect3.interfaces.wifi.ble_set_att_value(
            ble_remote_dev_address=self.ble_client_address, handle=(self.write_handle + 1), enable_notify=0)

        logger().info("******************** ble_remove_service ***********************")
        self.wifi_dut.interfaces.wifi.ble_remove_service()

    def ble_data_transfer_rx(self):
        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            self.remote_wiseconnect3.interfaces.wifi.ble_notify_custom_value(
                ble_remote_dev_address=self.ble_dut_address, data=self.data, data_address=self.address)
            time.sleep(1)
            events = self.wifi_dut.interfaces.wifi.get_async_events()
            for event in events:
                if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                    logger().info(f"************** BLE EVENT DATA IS : {event.event_data} **************")
                    received_data = re.findall(r"(\b[A-Z0-9]{20}\b)", event.event_data)
                    logger().info(f"******* Received Data on DUT : {received_data} ********")
                    assert received_data == [self.data], "data mismatched"

        self.ble_dut.interfaces.bluetooth.ble_set_att_value(
            ble_remote_dev_address=self.ble_client_address, handle=(self.write_handle + 1), enable_notify=0)

    def set_phy_update(self):
        self.ble_dut.interfaces.bluetooth.ble_set_phy(
            remote_dev_addr=self.ble_client_address, tx_phy=self.tx_phy, rx_phy=self.rx_phy, coded_phy=self.coded_phy)
        time.sleep(120)
        self.ble_dut.interfaces.bluetooth.ble_read_phy(remote_dev_addr=self.ble_client_address)

    def ble_disconnect(self):
        logger().info(".... disconnecting from remote device ....")
        self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
        self.ble_client.interfaces.bluetooth.close()

    def ble_cleanup(self):
        self.sl_collections.cleanup_ble(
            ble_dut=self.wifi_dut, ble_client=self.ble_client, ble_client_address=self.ble_client_address)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_ble_tx_with_1m_phy_and_iperf_c537935(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, utf_constants, ble_client, protocol, net_perf_client, remote_wiseconnect3):
    """Verify CoEx functionality when BLE Tx as Central with PHY Rates (Tx=1Mbps Rx=1Mbps with LR=125) while
    WLAN UDP Tx data traffic"""

    ble_obj = None
    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f".... Remote device ip :{host_ip} ....")

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  wifi_client=wifi_client, sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                  utf_constants=utf_constants, ping_count=ping_count, protocol=protocol,
                                  net_perf_client=net_perf_client, host_ip=host_ip, traffic_type="TX",
                                  test_type='537935')

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, set_smp=1,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         remote_wiseconnect3=remote_wiseconnect3, data=data, tx_phy=1, rx_phy=1,
                                         coded_phy=2, test_case=537935, address=address2, enable_set_smp=0)

        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.set_phy_update()
        wifi_obj.start()
        time.sleep(5)
        ble_obj.ble_data_transfer_tx()
        wifi_obj.wait_for_exit()
        logger().info("..... stop capturing with Sniffer ......")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.memory_free(address2)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        ble_obj.ble_cleanup()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT |
                                   Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT |
                                   Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_ble_rx_with_phy_and_iperf_c537936(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, utf_constants, ble_client, protocol, net_perf_client, remote_wiseconnect3):
    """Verify CoEx functionality when BLE Tx as peripheral(DLE ON) with PHY Rates (Tx=1Mbps Rx=1Mbps with LR=500) while
     WLAN UDP Rx data is running"""
    ble_obj = None
    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f".... Remote device ip :{host_ip} ....")

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  wifi_client=wifi_client, sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                  utf_constants=utf_constants, ping_count=ping_count, protocol=protocol,
                                  net_perf_client=net_perf_client, host_ip=host_ip, traffic_type="RX",
                                  test_type='537936')

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, set_smp=0,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         remote_wiseconnect3=remote_wiseconnect3, tx_phy=1, rx_phy=1,
                                         coded_phy=1, data=data, test_case=537936, address=address2, enable_set_smp=1)

        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.set_phy_update()
        wifi_obj.start()
        time.sleep(5)
        ble_obj.ble_data_transfer_tx()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        logger().info("..... stop capturing with Sniffer ......")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.memory_free(address2)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        ble_obj.ble_cleanup()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"10MB.htm"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_ble_phy_with_http_download_c537937(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, utf_constants, ble_client, remote_wiseconnect3, http_server, index_path):
    """Verify CoEx functionality when BLE Tx as Peripheral with PHY Rates (Tx=2Mbps Rx=2Mbps with LR=125) while file
    download through WLAN HTTP"""
    ble_obj = None
    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f".... Remote device ip :{host_ip} ....")

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  wifi_client=wifi_client, sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                  utf_constants=utf_constants, ping_count=ping_count, host_ip=host_ip, https=0,
                                  http_server=http_server, index_path=index_path, test_type='537937')

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, set_smp=0,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         remote_wiseconnect3=remote_wiseconnect3, tx_phy=2, rx_phy=2,
                                         coded_phy=2, data=data, test_case=537937, address=address2, enable_set_smp=1)

        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.set_phy_update()
        wifi_obj.start()
        time.sleep(30)
        ble_obj.ble_data_transfer_tx()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        logger().info("..... stop capturing with Sniffer ......")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.memory_free(address2)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        ble_obj.ble_cleanup()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"10MB.htm"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_ble_phy_with_https_download_c537938(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, utf_constants, ble_client, remote_wiseconnect3, http_server, index_path):
    """Verify CoEx functionality when BLE Tx as Peripheral(DLE ON) with PHY Rates (Tx=2Mbps Rx=2Mbps with LR=500)
    while file download through WLAN HTTPS"""

    ble_obj = None
    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f".... Remote device ip :{host_ip} ....")

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  wifi_client=wifi_client, sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                  utf_constants=utf_constants, ping_count=ping_count, host_ip=host_ip, https=1,
                                  http_server=http_server, index_path=index_path, test_type='537938')

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, set_smp=0,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         remote_wiseconnect3=remote_wiseconnect3, tx_phy=2, rx_phy=2,
                                         coded_phy=1, data=data, test_case=537938, enable_set_smp=1, address=address2)

        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.set_phy_update()
        wifi_obj.start()
        time.sleep(30)
        ble_obj.ble_data_transfer_tx()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        logger().info("..... stop capturing with Sniffer ......")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.memory_free(address2)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        ble_obj.ble_cleanup()


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_ble_phy_with_ssl_tx_c537939(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, utf_constants, ble_client, remote_wiseconnect3, ssl_server):
    """Verify CoEx functionality when BLE Rx as Central with PHY Rates (TX=LR ,Rx=LR with LR=500) while WLAN SSL Tx"""
    ble_obj = None
    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))

        logger().info(f".... Input data is :{data} ....")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f".... Remote device ip :{host_ip} ....")

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  wifi_client=wifi_client, sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                  utf_constants=utf_constants, ping_count=ping_count, host_ip=host_ip,
                                  ssl_server=ssl_server, test_type='537939')

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, ble_pairing=1,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         remote_wiseconnect3=remote_wiseconnect3, tx_phy=4, rx_phy=4,
                                         coded_phy=1, data=data, test_case=537939, address=address2)

        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.set_phy_update()
        wifi_obj.start()
        time.sleep(60)
        ble_obj.ble_data_transfer_rx()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        logger().info("..... stop capturing with Sniffer ......")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.memory_free(address2)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        ble_obj.ble_cleanup()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_ble_phy_with_ssl_rx_c537940(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, utf_constants, ble_client, remote_wiseconnect3, ssl_server):
    """Verify CoEx functionality when BLE Tx as Peripheral with PHY Rates (TX=LR ,Rx=LR with LR=125) while WLAN SSL
    Rx """
    ble_obj = None
    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f".... Remote device ip :{host_ip} ....")

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  wifi_client=wifi_client, sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                  utf_constants=utf_constants, ping_count=ping_count, host_ip=host_ip,
                                  ssl_server=ssl_server, test_type='537940')

        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, set_smp=0,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         remote_wiseconnect3=remote_wiseconnect3, tx_phy=4, rx_phy=4,
                                         coded_phy=2, data=data, test_case=537940, address=address2, enable_set_smp=1)

        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.set_phy_update()
        wifi_obj.start()
        time.sleep(30)
        ble_obj.ble_data_transfer_tx()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        logger().info("..... stop capturing with Sniffer ......")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.memory_free(address2)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        ble_obj.ble_cleanup()
