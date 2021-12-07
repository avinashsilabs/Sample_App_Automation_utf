# import pytest
from interfaces.wifi import WlanError

from utils.iperf.Iperf_constants import IperfConstants
import pytest
from utils.logger import get_logger

from integration_tests.common import logger
from interfaces.iperf.fixtures import IPerfFixture, iperf

from utils.iperf.Iperf_constants import IperfConstants
from utils.thread_base import ThreadBase
import time
from interfaces.cli.rs_sapi_commands import RSSAPICommands
from interfaces.bluetooth import BTSocketRole
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-RS9116
        1. Configuration of DUT in 2G : BGN
        2. Association of Third party AP's 
        3. Get the valid IP address
        4. verify throughput after DUT and AP association using Iperf
        5. verify throughput(using Iperf) after DUT and AP association with BT connect.
        6. verify throughput(using Iperf) after DUT and AP association with BLE connect.
        7. verify throughput(using Iperf) after DUT and AP association with BT connect data transfer.
        8. verify throughput(using Iperf) after DUT and AP association with BLE connect data transfer.

    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""


class wifiJoinThread(ThreadBase):
    def __init__(self, wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1):
        super().__init__()
        self.wifi_networked_dut = wifi_networked_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.run_iperf = run_iperf1

    def run(self):
        iperf = IPerfFixture(
            'test1',
            self.run_iperf,
            self.wifi_access_point,
            self.wifi_networked_dut,
            self.wifi_client,
        )
        time.sleep(5)
        iperf.run()
        logger().info("this is IPerf END")
        # mac_address = self.wifi_networked_dut.interfaces.wifi.get_mac_address()
        # logger().info(f"Actual MAC_Address: {mac_address}")


# This Thread is used to run the dut on slave mode
class BtSppConnectThread(ThreadBase):
    def __init__(self, wifi_dut, bt_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client

    def run(self):
        self.logger.info('this is bt run')
        # BT as slave and connect to remote BT[raspi]
        bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address is not None
        time.sleep(2)
        bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address is not None
        time.sleep(2)



class BtSppDataTransferThread(ThreadBase):
    def __init__(self, wifi_dut, bt_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client
        self.mode = mode

        if self.mode == "bt_slave":
            send_text = "yAbdcUK0tAOSMhCT4d6U"
            rec_text = "H2D7yZKRhKULU9Xil5Yv" * 10

            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_slave_spp()
            assert bt_dut_address is not None
            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
            assert bt_client_address is not None

            with self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server) as bt_server_socket:
                # SPP Connection
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    bt_server_socket.create_server()
                    connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address)
                    assert connected
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
                time.sleep(35)

                # Send data from bt_client to dut
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    sent = bt_server_socket.send(rec_text)  # SQA Agent is programmed to send back data
                    assert sent
                    data = bt_server_socket.recv()
                    assert data is not None
                    assert data.decode() == rec_text
                    time.sleep(5)

                # Send data from dut to bt_client
                self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                data = bt_server_socket.recv()
                assert data is not None
                assert data.decode() == send_text

                # Ping dut
                assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)

                # Close connection
                self.wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
                bt_server_socket.close()

        if self.mode == "bt_master":
            # while not self.stop_requested:
            send_text = "sA0L9b1xEgGuUqN5YOlx"
            rec_text = "H2D7yZKRhKULU9Xil5Yv"

            bt_dut_address, pin_code = self.wifi_dut.interfaces.wifi.start_bt_master_spp()
            assert bt_dut_address is not None

            bt_client_address = self.bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
            assert bt_client_address is not None

            with self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
                # SPP Connection
                with self.wifi_dut.interfaces.wifi.run_bt_task():
                    bt_client_socket.create_client()
                    self.wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                    addr = bt_client_socket.accept(timeout=120)
                    assert addr == bt_dut_address

                    # Send data from bt_client to dut
                    time.sleep(35)
                    with self.wifi_dut.interfaces.wifi.run_bt_task():
                        sent = bt_client_socket.send(
                            rec_text
                        )  # Dut is programmed to send back data
                        assert sent
                        data = bt_client_socket.recv()
                        assert data is not None
                        assert data.decode() == rec_text

                    # Send data from dut to bt_client
                    self.wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                    data = bt_client_socket.recv()
                    assert data is not None
                    assert data.decode() == send_text

                    # Ping dut
                    assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                        dest_addr=bt_dut_address
                    )

                # Close connection
                self.wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
                bt_client_socket.close()

# this thread used for sta+ble as a slave
class BleThread_connection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode

    def run(self):
        self.logger.info('this is BLE run')
        time.sleep(5)
        if ( self.mode == "ble_master"):
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None

            # Start ble client
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None

            # Start scanning and connect to ble client
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=15)

            timeout = 120
            self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

            # Disconnect
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

        if ( self.mode == "ble_slave"):

        # Set up DUT for BLE advertising
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None
            self.wifi_dut.interfaces.wifi.ble_start_advertising()

        # Begin Scanning for BLE devices
            time.sleep(3)
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None
            time.sleep(3)
            self.ble_client.interfaces.bluetooth.stop_scanning()

        # See that we found our device
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            time.sleep(3)
            assert self.wifi_dut.interfaces.wifi.ble_address in found_devices
            assert (
                found_devices[self.wifi_dut.interfaces.wifi.ble_address]
                == self.wifi_dut.interfaces.wifi.ble_advertising_data
            )
            self.ble_client.interfaces.bluetooth.connect(bt_dut_address)
            time.sleep(40)

            self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)

class Ble_Data_Transfer(ThreadBase):
    def __init__(self, wifi_dut, ble_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client

    def run(self):
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
        data1 = "LzY0"
        data2 = "K09x"
        data3 = "Mx3Y"

        # Set up BLE Server on DUT
        bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        self.wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
        self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)

        # Start advertising
        self.wifi_dut.interfaces.wifi.ble_start_advertising()

        # Begin Scanning for BLE devices
        bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert bt_client_address is not None
        # time.sleep(5)
        self.ble_client.interfaces.bluetooth.stop_scanning()

        # See that we found our device
        found_devices = self.ble_client.interfaces.bluetooth.get_devices()
        assert self.wifi_dut.interfaces.wifi.ble_address in found_devices
        assert (
                found_devices[self.wifi_dut.interfaces.wifi.ble_address]
                == self.wifi_dut.interfaces.wifi.ble_advertising_data
        )

        # connecting to dut
        self.ble_client.interfaces.bluetooth.connect(bt_dut_address)
        time.sleep(2)

        # resolving charecteristic
        bus = self.ble_client.interfaces.bluetooth.bus
        servs, chars = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics(bus)
        assert len(servs) > 0
        assert len(chars) > 0

        char, char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(bus,
                                                                                                    services=servs,
                                                                                                    service_uid=service_uid,
                                                                                                    char_uid=char_uid)
        assert char is not None
        assert len(char_props) > 0

        # read value - Notifications not enabled
        result = self.ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
        assert result == data1

        # subscribe to notifications
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(characteristic=char)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char,
                                                                                     char_uid=char_uid)
        # time.sleep(0.5)
        time.sleep(35)

        # notify only
        self.wifi_dut.interfaces.wifi.ble_notify_value()

        # write/read new value - Notifications enabled
        self.ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(characteristic=char, data=data2)
        time.sleep(0.1)
        result = self.ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
        assert result == data2

        # write value - Notifications enabled
        self.ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(characteristic=char, data=data3)

        # auto notify
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char,
                                                                                     char_uid=char_uid)
        self.wifi_dut.interfaces.wifi.ble_start_notify_value(interval_ms=500, count=2)
        time.sleep(1)

        # subscribe to notifications
        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(characteristic=char)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        time.sleep(0.5)

        # notify only - disabled notifications - should raise exception
        with pytest.raises(WlanError) as exc_info:
            self.wifi_dut.interfaces.wifi.ble_notify_value()
        assert exc_info.value.error_code == 0x21

        # assert received notifications
        notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
        logger().info(notifications)
        assert len(notifications) == 6
        assert notifications[0] == data1
        assert notifications[1] == data2
        assert notifications[2] == data2
        assert notifications[3] == data3
        assert notifications[4] == data3
        assert notifications[5] == data3

        # disconnecting from dut
        self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)



#STA standlone Test cases

@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.CLIENT_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
def test_throughput_wifi_alone_udp_rx(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1, bt_client):

    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1):
     time.sleep(15)

@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.SERVER_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
def test_throughput_wifi_alone_udp_tx(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1, bt_client):

    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1):
     time.sleep(15)

@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.CLIENT_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
def test_throughput_wifi_alone_tcp_rx(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1, bt_client):

    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1):
     time.sleep(15)

@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.SERVER_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
def test_throughput_wifi_alone_tcp_tx(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1, bt_client):

    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1):
     time.sleep(15)


#STA + BT Connected Test cases

@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.CLIENT_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
def test_throughput_wifi_bt_tcp_rx(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1, bt_client):
    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), \
            BtSppConnectThread(wifi_dut, bt_client):
        time.sleep(15)


@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.SERVER_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
def test_throughput_wifi_bt_udp_tx(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1, bt_client):
    with BtSppConnectThread(
            wifi_dut, bt_client), wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1):
        time.sleep(18)


@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.SERVER_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
def test_throughput_wifi_bt_tcp_tx(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1, bt_client):
    with BtSppConnectThread(
            wifi_dut, bt_client), wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1):
        time.sleep(18)


@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.CLIENT_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
def test_throughput_wifi_bt_udp_rx(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1, bt_client):
    with BtSppConnectThread(
            wifi_dut, bt_client), wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1):
        time.sleep(18)

#STA + BT Data transfer Test cases

@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.CLIENT_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
def test_throughput_wifi_bt_data_tcp_rx(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1, bt_client):
    mode = "bt_slave"
    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1),\
            BtSppDataTransferThread(wifi_dut, bt_client, mode):
         time.sleep(15)
#
#
@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.SERVER_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
def test_throughput_wifi_bt_data_udp_tx(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1, bt_client):
    mode = "bt_slave"
    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1),\
        BtSppDataTransferThread(wifi_dut, bt_client, mode):
     time.sleep(15)
#
#
@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.SERVER_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
def test_throughput_wifi_bt_data_tcp_tx(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1, bt_client):
    mode = "bt_slave"
    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1),\
        BtSppDataTransferThread(wifi_dut, bt_client, mode):
     time.sleep(15)
#
#
@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.CLIENT_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
def test_throughput_wifi_bt_data_udp_rx(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1, bt_client):
    mode = "bt_slave"
    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1),\
        BtSppDataTransferThread(wifi_dut, bt_client, mode):
     time.sleep(15)

# STA + BLE CONNECTED Test cases
@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.SERVER_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
def test_threading_sta_ble_dut_tcp_tx(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1,
                                      ble_client):
    mode = "ble_slave"
    # mode = "ble_master"
    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), \
            BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(10)

# Will verify later due to some intermittent failure
# @pytest.mark.parametrize('run_iperf1', [
#     {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.CLIENT_MODE,
#                                         IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP}
#      }])
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": 0,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#         "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
#             OpenMode | RS9116FeatureBitMap.PSKSecurity,
#         "band": 2
#     }
# )
# def test_threading_sta_ble_dut_tcp_rx(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1,
#                                       ble_client):
#     mode = "ble_slave"
#     # mode = "ble_master"
#     with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), \
#             BleThread_connection(wifi_dut, ble_client, mode):
#         time.sleep(10)

# @pytest.mark.parametrize('run_iperf1', [
#     {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.CLIENT_MODE,
#                                         IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP}
#      }])
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": 0,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#         "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
#             OpenMode | RS9116FeatureBitMap.PSKSecurity,
#         "band": 2
#     }
# )
# def test_threading_sta_ble_dut_udp_rx(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1,
#                                       ble_client):
#     mode = "ble_slave"
#     # mode = "ble_master"
#     with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), \
#             BleThread_connection(wifi_dut, ble_client, mode):
#         time.sleep(10)

@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.SERVER_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
def test_threading_sta_ble_dut_udp_tx(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1,
                                      ble_client):
    mode = "ble_slave"
    # mode = "ble_master"
    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), \
            BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(10)

@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.SERVER_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
def test_threading_sta_ble_data_udp_tx(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1,
                                      ble_client):

    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), \
            Ble_Data_Transfer(wifi_dut, ble_client):
        time.sleep(25)

@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.CLIENT_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
def test_threading_sta_ble_data_udp_rx(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1,
                                      ble_client):

    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), \
            Ble_Data_Transfer(wifi_dut, ble_client):
        time.sleep(15)

@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.SERVER_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
def test_threading_sta_ble_data_tcp_tx(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1,
                                      ble_client):

    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), \
            Ble_Data_Transfer(wifi_dut, ble_client):
        time.sleep(20)

@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.CLIENT_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
def test_threading_sta_ble_data_tcp_rx(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1,
                                      ble_client):

    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), \
            Ble_Data_Transfer(wifi_dut, ble_client):
        time.sleep(15)
