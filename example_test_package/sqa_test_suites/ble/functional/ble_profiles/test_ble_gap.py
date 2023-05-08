import pytest
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, \
    RS9116ExtCustomFeatureBitMap, RS9116CustomFeatureBitMap, RS9116PowerSaveProcedureTypes
from utf.utils.logger import get_logger
from utf.interfaces.wifi import WlanError
import time
import datetime
from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer


def logger():
    return get_logger(__name__)


time_lapse = 60 * 48

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4

    Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. Initiates the DUT in master Spp mode for the capability
        3. Initiates the client in slave spp with capability enables
        4. Opens Bt socket and connects to the remote client.
        5. Verifies ping after the connection.

    Author: RaviNemali
"""

'''=================== Ble-gap IO test cases ===================== '''




class ble_adv(ThreadBase):
    def __init__(self, ble_client, bt_dut_address, peer_address, bt_client_address):
        super().__init__()
        self.ble_client = ble_client
        self.bt_dut_address = bt_dut_address
        self.peer_address = peer_address
        self.bt_client_address = bt_client_address

    def run(self):
        logger().info(f"remote address:*********{self.peer_address}*******")
        time.sleep(5)

        bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
            bt_dut_address=self.bt_dut_address,
            hci_adv_params="0xA0 0x00 "
                           "0xA0 0x00 "
                           "0x01 "
                           "0x00 "
                           "0x00 "
                           f"{self.peer_address} "
                           "0x07 "
                           "0x00"
        )
        assert bt_client_address, "failed to initiate ble in remote device"

        logger().info(f"ble client add..{bt_client_address}")
        time.sleep(5)


class DutBleScanning():

    def start_scan(self, wifi_dut, ble_client, ble_dut, ble_scan_type):
        logger().info(f"Start DUT")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_start()

        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
        assert ble_client_address, "Unable to get ble_client_address"

        logger().info(f"\n\n Start scanning and connect to ble client \n\n")
        result = wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address,
                                                             ble_scan_type=ble_scan_type, timeout=120)

        logger().info(f"\n\n ****Enabling Wlan and BLE power save**** \n\n")
        # # Enables the wlan power save in DUT
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
        # # Enables the bt power save in DUT
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, 'failed to enable wlan power save'
        assert enable_bt_ps, 'failed to enable bt power save'

        logger().info(f"\n\n scan result '{result}\n\n")
        assert result, "no bt device found"
        logger().info(f"Stopping ble-client advertising")
        ble_client.interfaces.bluetooth.stop_advertising()
        time.sleep(2)
        logger().info("stop scanning")
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(2)
        ble_client.interfaces.bluetooth.close()
        time.sleep(2)

    def connect_as_master(self, ble_dut, timeout=None, bt_client_address=None, retries: int = 0):
        connect_time = None
        def connect():
            logger().info(f"Initiating connection this can take up to {timeout} seconds....")
            connect_time = datetime.datetime.now(
                ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address,
                                                         ble_conn_interval_min=200, ble_conn_interval_max=200,
                                                         ble_supervision_timeout=3000,
                                                         timeout=timeout))
            logger().info(f"connect_time:  {connect_time}")
            time.sleep(30)
            logger().info(f"\n\n *****Successfully connected with Remote : {bt_client_address}*****\n\n")
            return connect_time

        retries += 1
        while True:
            try:
                connect_time = connect()
            except Exception as err:
                if "Authentication Failed" in str(err):
                    raise Exception("Connection failed with Authentication Error")
                if "0x4e3e" in str(err):
                    logger().info(f"Found 4e3e exception...! retrying connect command.. {retries}")
                    connect()
                retries -= 1
                if retries <= 0:
                    if err is None:
                        raise
                    raise err
            return connect_time


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_io_cap_displayonly_C19851(ble_dut, ble_client):
    logger().info("Initiate ble service in DUT")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, initialize_ble=True)
    assert bt_dut_address, "failed to initiate ble in dut"

    logger().info("Set DUT in advertise mode")
    ble_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"
    time.sleep(5)

    logger().info("Start smp scan from the remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address, "failed to initiate ble in remote device"
    time.sleep(5)
    logger().info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Check the dut is listed...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert ble_dut.interfaces.bluetooth.ble_address in found_devices

    logger().info("Connect to the dut with mac address..")

    connect_time = datetime.datetime.now()
    connect_state = ble_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
    logger().info(f"connect_time  {connect_time}")
    assert connect_state, "unable to connect to the given address"
    time.sleep(30)
    ble_dut.interfaces.bluetooth.ble_advertising = False

    # checking if the connection exists to disconnect
    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("Disconnecting the bt host....")
        disconnect_time = datetime.datetime.now(
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address))
        logger().info(f"disconnect_time  {disconnect_time}")
        assert "unable to disconnect since the connection never existed"

        ble_client.interfaces.bluetooth.close()
        time.sleep(5)
        logger().info(f"connection existed for {disconnect_time - connect_time}")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv"])
def test_ble_io_cap_display_yesno_C19852(ble_dut, ble_client):
    logger().info("Initiate ble service in DUT")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=1, initialize_ble=True)
    assert bt_dut_address, "failed to initiate ble in dut"

    logger().info("Set DUT in advertise mode")
    ble_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"
    time.sleep(5)

    logger().info("Start smp scan from the remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address, "failed to initiate ble in remote device"
    time.sleep(5)
    logger().info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Check the dut is listed...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert ble_dut.interfaces.bluetooth.ble_address in found_devices

    logger().info("Connect to the dut with mac address..")
    connect_time = datetime.datetime.now()
    connect_state = ble_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
    logger().info(f"connect_time  {connect_time}")
    assert connect_state, "unable to connect to the given address"
    time.sleep(30)
    ble_dut.interfaces.bluetooth.ble_advertising = False
    # checking if the connection exists to disconnect
    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("Disconnecting the bt host....")
        disconnect_time = datetime.datetime.now(
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address))
        logger().info(f"disconnect_time  {disconnect_time}")
        assert "unable to disconnect since the connection never existed"
        logger().info(f"connection existed for {disconnect_time - connect_time}")
    ble_client.interfaces.bluetooth.close()
    time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv"])
def test_ble_io_cap_keyboard_only_C19853(ble_dut, ble_client):
    logger().info("Initiate ble service in DUT")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=2, initialize_ble=True)
    assert bt_dut_address, "failed to initiate ble in dut"

    logger().info("Set DUT in advertise mode")
    ble_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"
    time.sleep(5)

    logger().info("Start smp scan from the remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address, "failed to initiate ble in remote device"
    time.sleep(5)
    logger().info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Check the dut is listed...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert ble_dut.interfaces.bluetooth.ble_address in found_devices

    logger().info("Connect to the dut with mac address..")
    connect_time = datetime.datetime.now()
    connect_state = ble_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
    logger().info(f"connect_time  {connect_time}")
    assert connect_state, "unable to connect to the given address"
    time.sleep(30)
    ble_dut.interfaces.bluetooth.ble_advertising = False
    # checking if the connection exists to disconnect
    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("Disconnecting the bt host....")
        disconnect_time = datetime.datetime.now(
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address))
        logger().info(f"disconnect_time  {disconnect_time}")
        assert "unable to disconnect since the connection never existed"
        logger().info(f"connection existed for {disconnect_time - connect_time}")
    ble_client.interfaces.bluetooth.close()
    time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv"])
def test_ble_io_cap_No_input_output_C19854(ble_dut, ble_client):
    logger().info("Initiate ble service in DUT")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=3, initialize_ble=True)
    assert bt_dut_address, "failed to initiate ble in dut"

    logger().info("Set DUT in advertise mode")
    ble_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"
    time.sleep(5)

    logger().info("Start smp scan from the remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address, "failed to initiate ble in remote device"
    time.sleep(5)
    logger().info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("Check the dut is listed...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert ble_dut.interfaces.bluetooth.ble_address in found_devices

    logger().info("Connect to the dut with mac address..")
    connect_time = datetime.datetime.now()
    connect_state = ble_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
    logger().info(f"connect_time  {connect_time}")
    assert connect_state, "unable to connect to the given address"
    time.sleep(30)
    ble_dut.interfaces.bluetooth.ble_advertising = False

    # checking if the connection exists to disconnect
    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("Disconnecting the bt host....")
        disconnect_time = datetime.datetime.now(
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address))
        logger().info(f"disconnect_time  {disconnect_time}")
        assert "unable to disconnect since the connection never existed"
        logger().info(f"connection existed for {disconnect_time - connect_time}")

    ble_client.interfaces.bluetooth.close()
    time.sleep(10)


'''======================= Ble-gap IO test cases dut as initiator ====================='''


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "ble_disconnect", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_io_cap_displayonly_C19855(ble_dut, ble_client):

    logger().info("Initiating ble service in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=0, initialize_ble=True)
    assert bt_dut_address, "failed to initiate ble in dut"

    logger().info("Starting the advertisement in ble client")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address, "failed to initiate ble in remote device"
    time.sleep(5)

    logger().info("Check connection status of BLE before initiating connection to make sure DUT is not connected t"
                  "o remote device")
    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    if state_int == BLEDeviceState.Connected:
        logger().info("DUT is disconnected to BLE")
        ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

    logger().info("dut start scanning.....")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=120)

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"
    time.sleep(5)
    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    time.sleep(2)
    ble_obj = DutBleScanning()
    connect_time = ble_obj.connect_as_master(ble_dut, timeout=120, bt_client_address=bt_client_address)
    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if state_int > 0:
        logger().info("Disconnecting the bt host....")
        disconnect_time = datetime.datetime.now(
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address))
        logger().info(f"disconnect_time  {disconnect_time}")
        assert "unable to disconnect since the connection never existed"
        logger().info(f"connection existed for {disconnect_time - connect_time}")

    ble_client.interfaces.bluetooth.close()
    time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_disconnect", "wifi_powersave_disable", "bt_powersave_disable",
                                         "ble_stop_scan"])
def test_ble_io_cap_display_yesno_C19856(ble_dut, ble_client):
    logger().info("Initiating ble service in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=1, initialize_ble=True)
    assert bt_dut_address, "failed to initiate ble in dut"

    logger().info("Starting the advertisement in ble client")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address, "failed to initiate ble in remote device"
    time.sleep(5)

    logger().info("Check connection status of BLE before initiating connection to make sure DUT is not connected t"
                  "o remote device")
    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    if state_int == BLEDeviceState.Connected:
        logger().info("DUT is disconnected to BLE")
        ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
        time.sleep(2)

    logger().info("dut start scanning.....")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=120)

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"
    time.sleep(5)

    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    time.sleep(2)

    ble_obj = DutBleScanning()
    connect_time = ble_obj.connect_as_master(ble_dut, timeout=120, bt_client_address=bt_client_address)

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("Disconnecting the bt host....")
        disconnect_time = datetime.datetime.now(
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address))
        logger().info(f"disconnect_time  {disconnect_time}")
        assert "unable to disconnect since the connection never existed"

        ble_client.interfaces.bluetooth.close()
        time.sleep(5)
        logger().info(f"connection existed for {disconnect_time - connect_time}")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,

    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "ble_disconnect", "wifi_powersave_disable", "bt_powersave_disable",
                                         ])
def test_ble_io_cap_keyboard_only_C19857(ble_dut, ble_client):
    logger().info("Initiating ble service in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=2, initialize_ble=True)
    assert bt_dut_address, "failed to initiate ble in dut"

    logger().info("Starting the advertisement in ble client")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address, "failed to initiate ble in remote device"
    time.sleep(5)

    logger().info("Check connection status of BLE before initiating connection to make sure DUT is not connected t"
                  "o remote device")
    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    if state_int == BLEDeviceState.Connected:
        logger().info("DUT is disconnected to BLE")
        ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
        time.sleep(2)

    logger().info("dut start scanning.....")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=120)

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"
    time.sleep(5)

    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    time.sleep(1)

    ble_obj = DutBleScanning()
    connect_time = ble_obj.connect_as_master(ble_dut, timeout=120, bt_client_address=bt_client_address)

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("Disconnecting the bt host....")
        disconnect_time = datetime.datetime.now(
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address))
        logger().info(f"disconnect_time  {disconnect_time}")
        assert "unable to disconnect since the connection never existed"

        ble_client.interfaces.bluetooth.close()
        time.sleep(5)
        logger().info(f"connection existed for {disconnect_time - connect_time}")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_disconnect", "wifi_powersave_disable", "bt_powersave_disable",
                                         "ble_stop_scan"])
def test_ble_io_cap_no_input_output_C19858(ble_dut, ble_client):
    try:
        ble_obj = DutBleScanning()
        logger().info("Initiating ble service in dut")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_start(capability=3, initialize_ble=True)
        assert bt_dut_address, "failed to initiate ble in dut"

        logger().info("Starting the advertisement in ble client")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
        assert bt_client_address, "failed to initiate ble in remote dut"
        time.sleep(5)

        logger().info("Check connection status of BLE before initiating connection to make sure DUT is not connected t"
                  "o remote device")
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        if state_int == BLEDeviceState.Connected:
           logger().info("DUT is disconnected to BLE")
           ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)
           time.sleep(2)

        logger().info("dut start scanning.....")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=120)

        logger().info("enabling the power save modes ")
        enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, "failed to enable wifi power save"
        enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps, "failed to enable bt power save"
        time.sleep(5)

        logger().info("stop scanning")
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(2)

        connect_time = ble_obj.connect_as_master(ble_dut, timeout=120, bt_client_address=bt_client_address)

        ble_client.interfaces.bluetooth.stop_advertising()
        time.sleep(5)

        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"state_int==============>>,  {state_int}")
        if state_int > 0:
           logger().info("Disconnecting the bt host....")
           disconnect_time = datetime.datetime.now(
               ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address))
           logger().info(f"disconnect_time  {disconnect_time}")
           assert "unable to disconnect since the connection never existed"
           ble_client.interfaces.bluetooth.close()
           time.sleep(5)
           logger().info(f"connection existed for {disconnect_time - connect_time}")
    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise
    finally:
        ble_client.interfaces.bluetooth.close()


"""============================ Ble-gap dut scan for adv types ============================================="""


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_scan_connectable_undirected_adv_C19805(ble_dut, ble_client):
    logger().info("start ble...")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "failed to initiate ble in dut"
    logger().info("start ble client...")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
        bt_dut_address=bt_dut_address,
        hci_adv_params="0xA0 0x00 "  # Advertising_Interval_Min
                       "0xA0 0x00 "  # Advertising_Interval_Max
                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                       "0x00 "  # Own_Address_Type
                       "0x00 "  # Peer_Address_Type
                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                       "0x07 "  # Advertising_Channel_Map
                       "0x00"  # Advertising_Filter_Policy
    )
    assert bt_client_address, "failed to initiate ble in remote device"
    logger().info(f"ble client addr..{bt_client_address}")
    time.sleep(5)
    logger().info("Start scanning....")
    result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"
    time.sleep(5)

    scan_results = result.splitlines()
    logger().info(f"scan_results: **********{scan_results}**********")
    scan_status = False
    for line in scan_results:
        line = str(line)
        logger().info("checking for remote device Advertisement type and BD address")
        if "rsi_ble_simple_central_on_adv_report_event" in line:
            logger().info(f"**************Advertise report :{line}**********")
            if (bt_client_address in line) and ("report_type:0" in line):
                logger().info("Advertisement type found 0x0 in adv report")
                scan_status = True
                break
    assert scan_status, "no bt device found with adv type 0x0"

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    time.sleep(5)

    ble_client.interfaces.bluetooth.close()
    time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_scan_connectable_directed_adv_C19806(ble_dut, ble_client):
    logger().info("start ble...")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "unable to fetch bd address"
    logger().info("start ble client...")
    logger().info(f"bt_dut_address {bt_dut_address}")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    time.sleep(1)
    assert bt_client_address, "failed to initiate ble in remote device"
    logger().info(f"ble client add..{bt_client_address}")
    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)
    ble_client.interfaces.bluetooth.close()

    mac_list = bt_dut_address.split(":")
    mac_list.reverse()
    mac_list = ["0x" + s for s in mac_list]
    peer_address = " ".join(mac_list)
    logger().info(f"peer_address {peer_address}")
    ble_obj = ble_adv(ble_client, bt_dut_address, peer_address, bt_client_address)
    ble_obj.start()

    logger().info("Start scanning....")
    result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    logger().info(f" scan result '{result}")

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    scan_results = result.splitlines()
    logger().info(f"scan_results: **********{scan_results}**********")
    scan_status = False
    for line in scan_results:
        line = str(line)
        logger().info("checking for remote device Advertisement type and BD address")
        if "rsi_ble_simple_central_on_adv_report_event" in line:
            logger().info(f"**************Advertise report :{line}**********")
            if (bt_client_address in line) and ("report_type:1" in line):
                logger().info("Advertisement type found 0x01 in adv report")
                scan_status = True
                break
    assert scan_status, "no bt device found with adv type 0x01"

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    time.sleep(5)

    ble_client.interfaces.bluetooth.close()
    time.sleep(10)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_scan_non_connectable_undirected_adv_C19807(ble_dut, ble_client):
    logger().info("start ble...")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "failed to start ble in dut"
    logger().info("start ble client...")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
        bt_dut_address=bt_dut_address,
        hci_adv_params="0xA0 0x00 "
                       "0xA0 0x00 "
                       "0x03 "
                       "0x00 "
                       "0x00 "
                       "0x00 0x00 0x00 0x00 0x00 0x00 "
                       "0x07 "
                       "0x00"
    )
    assert bt_client_address, "failed to initiate ble in remote device"
    logger().info(f"ble client add..{bt_client_address}")
    time.sleep(5)
    logger().info("Start scanning....")
    result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info(f" scan result '{result}")
    scan_results = result.splitlines()
    logger().info(f"scan_results: **********{scan_results}**********")
    scan_status = False
    for line in scan_results:
        line = str(line)
        logger().info("checking for remote device Advertisement type and BD address")
        if "rsi_ble_simple_central_on_adv_report_event" in line:
            logger().info(f"**************Advertise report :{line}**********")
            if (bt_client_address in line) and ("report_type:3" in line):
                logger().info("Advertisement type found 0x03 in adv report")
                scan_status = True
                break
    assert scan_status, "no bt device found with adv type 0x03"

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    time.sleep(5)
    ble_client.interfaces.bluetooth.close()
    time.sleep(10)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_scannable_undirected_adv_C19808(ble_dut, ble_client):
    logger().info("start ble...")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "failed to start ble in dut"
    logger().info("start ble client...")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
        bt_dut_address=bt_dut_address,
        hci_adv_params="0xA0 0x00 "
                       "0xA0 0x00 "
                       "0x02 "
                       "0x00 "
                       "0x00 "
                       "0x00 0x00 0x00 0x00 0x00 0x00 "
                       "0x07 "
                       "0x00"
    )
    assert bt_client_address, "failed to initiate ble in remote device"
    logger().info(f"ble client add..{bt_client_address}")
    time.sleep(5)
    logger().info("Start scanning....")
    result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    scan_results = result.splitlines()
    logger().info(f"scan_results: **********{scan_results}**********")
    scan_status = False
    for line in scan_results:
        line = str(line)
        logger().info("checking for remote device Advertisement type and BD address")
        if "rsi_ble_simple_central_on_adv_report_event" in line:
            logger().info(f"**************Advertise report :{line}**********")
            if (bt_client_address in line) and ("report_type:2" in line):
                logger().info("Advertisement type found 0x02 in adv report")
                scan_status = True
                break
    assert scan_status, "no bt device found with adv type 0x02"

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    time.sleep(5)
    ble_client.interfaces.bluetooth.close()
    time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable",
                                         "bt_powersave_disable"])
def test_ble_adv_state_in_scan_C19840(ble_dut, ble_client):
    logger().info("start ble...")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "failed to initiate ble in dut"
    logger().info("start ble client...")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
        bt_dut_address=bt_dut_address,
        hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                       "0x40 0x00 "  # Advertising_Interval_Max
                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                       "0x00 "  # Own_Address_Type
                       "0x00 "  # Peer_Address_Type
                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                       "0x07 "  # Advertising_Channel_Map
                       "0x00"  # Advertising_Filter_Policy
    )
    assert bt_client_address, "failed to initiate ble in remote device"
    logger().info(f"ble client add..{bt_client_address}")
    time.sleep(1)
    logger().info("Start scanning....")
    result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    time.sleep(3)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"
    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()

    logger().info("verifying client addr is available in scan list...")
    assert str(bt_client_address) in str(result), "failed to find client bt addr in scan list...."
    logger().info("found BT client address")
    ble_dut.interfaces.bluetooth.ble_start_advertising()
    time.sleep(3)

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    ble_client.interfaces.bluetooth.close()
    time.sleep(5)
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address, "failed to initiate ble in remote device"
    time.sleep(5)
    ble_client.interfaces.bluetooth.stop_scanning()

    found_devices = ble_client.interfaces.bluetooth.get_devices()
    logger().info(f"scan results from remote device:*********{found_devices}*****************")
    assert ble_dut.interfaces.bluetooth.ble_address in found_devices, "dut is not listed in scan results"

    logger().info("Stop DUT advertising")
    ble_dut.interfaces.bluetooth.ble_stop_advertising()
    time.sleep(5)

    ble_client.interfaces.bluetooth.close()
    time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', "ble_stop_adv"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv"])
def test_ble_dut_slave_connect_C19832(ble_dut, ble_client):
    logger().info("set dut in adv mode...")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "failed to initiate ble in dut"
    ble_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("start ble scan from remote le device...")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address, "failed to initiate ble in remote device"
    time.sleep(5)
    ble_client.interfaces.bluetooth.stop_scanning()

    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert ble_dut.interfaces.bluetooth.ble_address in found_devices
    assert (
            found_devices[ble_dut.interfaces.wifi.ble_address]
            == ble_dut.interfaces.bluetooth.ble_advertising_data
    )
    logger().info("connect to dut from remote le device....")
    ble_client.interfaces.bluetooth.connect(bt_dut_address)
    assert bt_dut_address, "unable to connect to the given address"
    time.sleep(30)

    ble_dut.interfaces.bluetooth.ble_advertising = False

    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("disconnecting the dut..")
        ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
        assert "unable to disconnect since the connection never existed"
    ble_client.interfaces.bluetooth.close()
    time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', "ble_stop_adv"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv"])
def test_directed_connectable_adv_C19802(ble_dut, ble_client, bt_logs):
    logger().info("start ble in dut....")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "failed to initiate ble in dut"
    logger().info("advertising Dut")
    ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=129)  # high duty cycle
    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address, "unable to fetch dut bd address..."
    time.sleep(5)

    logger().info("stop bt advertising...")
    ble_dut.interfaces.bluetooth.ble_stop_advertising()
    ble_client.interfaces.bluetooth.stop_scanning()

    found_devices = ble_client.interfaces.bluetooth.get_devices()
    logger().info("checking dut,listed in scan")
    assert ble_dut.interfaces.bluetooth.ble_address in found_devices
    assert (
            found_devices[ble_dut.interfaces.bluetooth.ble_address]
            == ble_dut.interfaces.bluetooth.ble_advertising_data
    )
    bt_logs.device_characteristics(ble_dut.interfaces.bluetooth.ble_address)
    assert 'Connectable directed - ADV_IND (0x81)' in bt_logs.device_adv_type, "device not in connectable directed mode"
    logger().info("found dut with connectable directed mode")
    ble_client.interfaces.bluetooth.close()
    time.sleep(5)


" ============ ble-gap pdu length test cases ====================== "


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_scan_resp_8_bytes_C19821(ble_dut, ble_client):
    logger().info("start ble dut....")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "failed to initiate ble in dut"

    # pdu name -- No PDU name as address itself satisfies the 8 bytes
    logger().info("start ble client with pdu length 8 bytes....")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
        bt_dut_address=bt_dut_address,
        hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                       "0x40 0x00 "  # Advertising_Interval_Max
                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                       "0x00 "  # Own_Address_Type
                       "0x00 "  # Peer_Address_Type
                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                       "0x07 "  # Advertising_Channel_Map
                       "0x00"  # Advertising_Filter_Policy
        , scan_resp_name_params="0x00 0x09 0x09 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
                                "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
                                "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "

    )
    assert bt_client_address, "failed to initiate ble in remote device"
    time.sleep(1)
    logger().info("Start ble scanning...")
    result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"
    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result), "failed to find client bt addr in scan list...."
    logger().info("found BT client address")

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    time.sleep(5)

    ble_client.interfaces.bluetooth.close()
    time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_scan_resp_20_bytes_C19822(ble_dut, ble_client):
    logger().info("start ble dut....")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "failed to initiate ble in dut"

    # pdu name -- automateaa
    logger().info("start ble client with pdu length 8 bytes....")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
        bt_dut_address=bt_dut_address,
        hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                       "0x40 0x00 "  # Advertising_Interval_Max
                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                       "0x00 "  # Own_Address_Type
                       "0x00 "  # Peer_Address_Type
                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                       "0x07 "  # Advertising_Channel_Map
                       "0x00"  # Advertising_Filter_Policy
        , scan_resp_name_params="0x0c 0x0b 0x09 0x61 0x75 0x74 0x6f 0x6d 0x61 0x74 0x65 0x61 "
                                "0x61 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
                                "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
    )
    assert bt_client_address, "failed to initiate ble in remote device"
    time.sleep(1)
    logger().info("Start ble scanning...")
    result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result), "failed to find client bt addr in scan list...."
    logger().info("found BT client address")

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    time.sleep(5)

    ble_client.interfaces.bluetooth.close()
    time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_scan_resp_30_bytes_C19823(ble_dut, ble_client):
    logger().info("start ble dut....")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "failed to initiate ble in dut"

    # pdu name -- automateaaaaaaaaaaaa
    logger().info("start ble client with pdu length 30 bytes....")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
        bt_dut_address=bt_dut_address,
        hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                       "0x40 0x00 "  # Advertising_Interval_Max
                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                       "0x00 "  # Own_Address_Type
                       "0x00 "  # Peer_Address_Type
                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                       "0x07 "  # Advertising_Channel_Map
                       "0x00"  # Advertising_Filter_Policy
        , scan_resp_name_params="0x16 0x15 0x09 0x61 0x75 0x74 0x6f 0x6d 0x61 0x74 "
                                "0x65 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 "
                                "0x61 0x61 0x61 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "

    )
    assert bt_client_address, "failed to initiate ble in remote device"
    time.sleep(1)
    logger().info("Start ble scanning...")
    result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result), "failed to find client bt addr in scan list...."
    logger().info("found BT client address")

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    time.sleep(5)

    ble_client.interfaces.bluetooth.close()
    time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_scan_resp_39_bytes_C19824(ble_dut, ble_client):
    logger().info("start ble dut....")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "failed to initiate ble in dut"

    # pdu name -- automateaaaaaaaaaaaaaaaaaaaaa
    logger().info("start ble client with pdu length 30 bytes....")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
        bt_dut_address=bt_dut_address,
        hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                       "0x40 0x00 "  # Advertising_Interval_Max
                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                       "0x00 "  # Own_Address_Type
                       "0x00 "  # Peer_Address_Type
                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                       "0x07 "  # Advertising_Channel_Map
                       "0x00"  # Advertising_Filter_Policy
        , scan_resp_name_params="0x1F 0x1E 0x09 0x61 0x75 0x74 0x6f 0x6d 0x61 0x74 0x65 0x61 "
                                "0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 "
                                "0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x00 0x00 "

    )
    assert bt_client_address, "failed to initiate ble in remote device"
    time.sleep(1)
    logger().info("Start ble scanning...")
    result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result), "failed to find client bt address in scan list...."
    logger().info("found BT client address")

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    time.sleep(5)

    ble_client.interfaces.bluetooth.close()
    time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_adv_report_C19848(ble_dut, ble_client):
    logger().info("start ble...")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "failed to initiate ble in dut"
    logger().info("start ble client...")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    time.sleep(1)
    assert bt_client_address, "failed to initiate ble in remote device"
    logger().info(f"ble client add..{bt_client_address}")
    time.sleep(1)
    logger().info("Start scanning....")
    result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=120)
    logger().info(f" scan result '{result}")
    assert result, "no bt device found"

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("verifying client addr, is available in scan list...")
    assert str(bt_client_address) in str(result), "failed to find client bt addr in scan list...."
    logger().info("found BT client address")

    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)

    logger().info("stop scanning")
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    time.sleep(5)

    ble_client.interfaces.bluetooth.close()
    time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_continuous_scan_C19819(ble_dut, ble_client):
    with TimeMeasurer() as t:
        ble_scan_window = 32  # 0x20 in hexadecimal
        ble_scan_interval = 32  # 0x20 in hexadecimal
        logger().info("start ble in dut")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "ble initialization failed in dut"
        t_end = time.time() + 60 * 30
        while time.time() < t_end:
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
            assert ble_client_address, f"ble initialization failed in remote device"

            time.sleep(5)
            ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address,
                                                            ble_scan_interval=int(ble_scan_interval / 0.625),
                                                            ble_scan_window=int(ble_scan_window / 0.625), timeout=300)
            time.sleep(2)

            logger().info(f" ============== Enable PSP in DUT")
            enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
            assert enable_wifi_ps, "failed to enable wifi power save"
            enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
                power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
            )
            assert enable_bt_ps, "failed to enable bt power save"

            ble_dut.interfaces.bluetooth.ble_stop_scanning()
            ble_client.interfaces.bluetooth.stop_advertising()
            ble_client.interfaces.bluetooth.close()
    logger().info(f"time taken for test {t.duration}")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_continuous_scan_C19820(ble_dut, ble_client):
    with TimeMeasurer() as t:
        ble_scan_window = 32  # 0x0020 in hexadecimal
        ble_scan_interval = 160  # 0x00A0 in hexadecimal
        logger().info("start ble in dut")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "ble initialization failed in dut"
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
        assert ble_client_address, f"ble initialization failed in remote device"

        time.sleep(5)
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address,
                                                        ble_scan_interval=int(ble_scan_interval / 0.625),
                                                        ble_scan_window=int(ble_scan_window / 0.625), timeout=120)
        scan_duration_in_min = 5
        time.sleep(60 * scan_duration_in_min)
        logger().info(f" ============== Enable PSP in DUT")
        enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
            power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, "failed to enable wifi power save"
        enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode2,
            power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave
        )
        assert enable_bt_ps, "failed to enable bt power save"

        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        ble_client.interfaces.bluetooth.stop_advertising()
        ble_client.interfaces.bluetooth.close()
    logger().info(f"time taken for test {t.duration}")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable",
                                         "ble_disconnect"])
def test_ble_power_save_connected_state_as_a_slave_C19831(wifi_dut, ble_client):
    # Set up DUT for BLE advertising
    logger().info("Initiate ble service in DUT")
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address, "unable to fetch dut bd address...."

    logger().info("start ble scan in rd_1")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address, "ble initialization failed in remote device_1"
    time.sleep(2)

    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=120)
    time.sleep(10)

    logger().info(f"found BT client address of {bt_client_address}")

    logger().info("Connect to the dut with mac address..")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=30)
    assert bt_client_address, "unable to connect to the given address"
    time.sleep(30)

    logger().info("enabling the power save modes ")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.MaxPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.MaxPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"
    time.sleep(5)

    logger().info(f"Connection interval in power meter or logic analyzer, Currently this provision is not available")
    ble_client.interfaces.bluetooth.close()

    time.sleep(5)
    logger().info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()
    time.sleep(2)


# Written by himaja
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_BLE_continuousscanning_for_48_hours_C19829(wifi_dut, ble_client):
    # for the time being we are advetising with only one client need to add 9 other devices to do the ask
    logger().info("start ble in dut")
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address, "ble initialization failed in dut"
    logger().info("start ble scan in rd_1")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address, "ble initialization failed in remote device_1"
    time.sleep(2)
    scan_results = wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address,
                                                               ble_scan_interval=int(500 / 0.625),
                                                               ble_scan_window=int(400 / 0.625), timeout=120)
    time.sleep(60 * time_lapse)
    # Enables the wifi power save in dut
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # Enables the bt power save in dut
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
    logger().info(f" scan result '{scan_results}")
    assert scan_results, "ble devices not found"
    logger().info(f"Currently we are supporting this "
                  f"Check weather the DUT is able receive adverse report in 3 channel are not using sniffer")
    logger().info(f"found BT client address of {bt_client_address}")
    wifi_dut.interfaces.wifi.ble_stop_scanning()
    ble_client.interfaces.bluetooth.stop_advertising()
    time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_thePowersavemode2_functionality_of_DUT_C19859(wifi_dut, ble_client):
    logger().info("start ble in dut")
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address, "ble initialization failed in dut"
    logger().info("start ble scan in rd_1")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address, "ble initialization failed in remote device_1"
    time.sleep(2)
    scan_results = wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address,
                                                               ble_scan_interval=int(500 / 0.625),
                                                               ble_scan_window=int(400 / 0.625),
                                                               timeout=120)
    time.sleep(10)
    # Enables the wifi power save in dut
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # Enables the bt power save in dut
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
    logger().info(f" scan result '{scan_results}")
    assert scan_results, "ble devices not found"
    logger().info(f"Currently we are supporting this "
                  f"Check weather the DUT is able receive adverse report in 3 channel are not using sniffer")
    logger().info(f"found BT client address of {bt_client_address}")


# written by Benazeer K
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_c19838_verify_ble_passive_scanning_on_dut(wifi_dut, ble_dut, ble_client):
    # test case to verify BLE Passive Scan on DUT
    with BleLogs(start_collecting_logs=True,
                 bt_log_path=f"reports/test_C19838_verify_ble_passive_scanning_on_dut.log_{int(time.time())}"):
        ble_obj = DutBleScanning()
        ble_obj.start_scan(wifi_dut, ble_client, ble_dut, ble_scan_type=0)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_c19837_verify_ble_active_scanning_on_dut(wifi_dut, ble_dut, ble_client):
    # test case to verify BLE Passive Scan on DUT
    with BleLogs(start_collecting_logs=True,
                 bt_log_path=f"reports/test_C19837_verify_ble_active_scanning_on_dut.log_{int(time.time())}"):
        ble_obj = DutBleScanning()
        ble_obj.start_scan(wifi_dut, ble_client, ble_dut, ble_scan_type=1)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_c19835_c19836_ble_conn_discon_verification(wifi_dut, ble_client):
    with BleLogs(start_collecting_logs=True,
                 bt_log_path=f"reports/test_c19835_c19836_ble_conn_discon_verification.log_{int(time.time())}"):
        # Start DUT
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        logger().info(f"Configuring Remote LE device in Undirected connectable advertising mode")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
            bt_dut_address=bt_dut_address,
            hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                           "0x40 0x00 "  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x07 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy
            , scan_resp_name_params="0x0f 0x0e 0x09 0x75 0x74 0x66 0x5f 0x77 0x69 "
                                    "0x66 0x69 0x5f 0x74 0x65 0x73 " \
                                    "0x74 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
                                    "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00"
        )
        assert bt_client_address is not None

        logger().info("Start scanning and connect to ble client")
        result = wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=120)

        logger().info("Enabling Wlan and BLE power save ")
        # # Enables the wlan power save in DUT
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
        # # Enables the bt power save in DUT
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, 'failed to enable wlan power save'
        assert enable_bt_ps, 'failed to enable bt power save'

        logger().info(f" scan result '{result}")
        assert result, "no bt device found"

        timeout = 120
        logger().info(f"Initiating connection this can take upto {timeout} seconds....")
        wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

        logger().info("Check connection status of BLE")
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
        logger().info("DUT is not disconnected from BLE")

        ## Disconnect
        wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)


@pytest.mark.firmware_app("test_wlan_powersave_mode3_ulp")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_advertising"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
    },
)
@pytest.mark.test_wlan_powersave_mode3_ulp
def test_c19830_powersave3_dut_adv_mode(firmware_loader, wifi_dut, ble_dut, ble_client):
    # test case to verify BLE Passive Scan on DUT
    with BleLogs(start_collecting_logs=True,
                 bt_log_path=f"reports/test_c19830_powersave3_dut_adv_mode.log_{int(time.time())}"):
        set_local_name = "BLE_GAP_TESTPLAN"
        logger().info(f"Setting BLE local name {set_local_name}")
        wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
        status = wifi_dut.interfaces.wifi.bt_get_local_name()
        logger().info(f"getting the local name : {status}")
        assert set_local_name == status, "Set local name and get local name not matched "
        logger().info(f"DUT BLE start")
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()

        logger().info(f"start advertising")
        wifi_dut.interfaces.wifi.ble_start_advertising()

        logger().info("Enabling Wlan and BLE power save ")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, 'failed to enable wlan power save'
        assert enable_bt_ps, 'failed to enable bt power save'

        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert bt_client_address is not None
        time.sleep(10)
        device_found = False
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            found_devices = ble_client.interfaces.bluetooth.get_devices()
            logger().info(f"{found_devices}")
            if bt_dut_address in found_devices and \
                    found_devices[bt_dut_address] == wifi_dut.interfaces.wifi.ble_advertising_data:
                device_found = True
                break

        ble_client.interfaces.bluetooth.stop_scanning()
        assert device_found, "Unable to find the device in scan list"

        logger().info(f"\n\n Stopping dut advertising \n\n")
        wifi_dut.interfaces.bluetooth.ble_stop_advertising()
        time.sleep(2)

        ble_client.interfaces.bluetooth.close()
        time.sleep(2)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', "ble_stop_adv"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv"])
def test_verify_ble_scan_in_advertising_state_C19839(ble_dut, ble_clients):
   with BleLogs(start_collecting_logs=True,
                 bt_log_path=f"reports/test_ble_dut_master_remote_device_directed_connectable.logs_{int(time.time())}"):
    #initaite ble service in dut
    assert len(ble_clients) >= 2, f"MINIMUM 2 RASPI DEVICES NEEDED"
    ble_client1 = ble_clients[0]
    ble_client2 = ble_clients[1]
    logger().info("INITIATING BLE SERVICE IN DUT")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "FAILED TO INITIATE BLE IN DUT"

    #advertise from remote 1
    logger().info(" **** START ADVERTISING FROM REMOTE DEVICE 1 **** ")
    ble_client_address1 = ble_client1.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert ble_client_address1, "UNABLE TO GET BLE CLIENT ADDRESS"
    logger().info(f"ble_client_address1: {ble_client_address1}")
    time.sleep(5)

    logger().info(" **** START ADVERTISING FROM DUT **** ")
    ble_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info(" **** START SCANNING DUT FROM REMOTE DEVICE 2 **** ")
    bt_client_address2 = ble_client2.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address2, "FAILED TO INITIATE BLE IN REMOTE DEVICE 2"
    logger().info(f"bt_client_address2: {bt_client_address2}")

    time.sleep(5)
    ble_client2.interfaces.bluetooth.stop_scanning()

    #check if the dut is listed in scan results from remote device 2
    found_devices_list = ble_client2.interfaces.bluetooth.get_devices()
    logger().info(f"SCAN RESULTS FROM REMOTE DEVICE 2:*********{found_devices_list}*****************")
    assert ble_dut.interfaces.bluetooth.ble_address in found_devices_list, "DUT ISN'T LISTED IN SCAN RESULTS"
    logger().info("FOUND DUT BD ADDRESS IN SCAN RESULTS")

    #enable wlan power save and bt power save in dut
    logger().info(" **** ENABLING WLAN AND BT POWER SAVE **** ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, 'FAILED TO ENABLE WLAN POWER SAVE'
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2, RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, 'FAILED TO ENABLE BT POWER SAVE'


    #check for remote device 1 in dut scan results
    scan_results = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address1, timeout=30)
    logger().info(f" SCAN RESULT IS: '{scan_results}")
    assert str(ble_client_address1) in str(scan_results), "REMOTE DEVICE 1 ADDRESS ISN'T PRESENT IN DUT SCAN RESULTS"
    logger().info("SUCCESSFULLY FOUND REMOTE DEVICE 1 IN DUT SCAN RESULTS")

    #stop advertisement and scanning from dut
    logger().info("DISABLING ADVERTISEMENT AND SCANNING IN DUT")
    ble_dut.interfaces.bluetooth.ble_stop_advertising()
    ble_dut.interfaces.bluetooth.ble_stop_scanning()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose |
                              RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
                           RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_master_un_directed_connectable_c19833(ble_dut, ble_client, rs_helper_ble):
    with BleLogs(start_collecting_logs=True,
                 bt_log_path=f"reports/test_ble_dut_master_un_directed_connectable_c19833.logs_{int(time.time())}"):
        # Start DUT
        logger().info("start ble...")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "unable to fetch bd address"
        logger().info(f"Configuring Remote LE device in Undirected connectable advertising mode")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
            bt_dut_address=bt_dut_address,
            hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                           "0x40 0x00 "  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x07 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy
            , scan_resp_name_params="0x0f 0x0e 0x09 0x75 0x74 0x66 0x5f 0x77 0x69 "
                                    "0x66 0x69 0x5f 0x74 0x65 0x73 " \
                                    "0x74 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
                                    "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00"
        )
        assert bt_client_address is not None
        logger().info("Start scanning....")
        result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
        logger().info(f" scan result '{result}")
        logger().info("enabling the power save modes ")
        enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                 RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, "failed to enable wifi power save"
        enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                  RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps, "failed to enable bt power save"
        logger().info("stop scanning")
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(2)
        logger().info(f"DUT initiating BLE connection with ble_client device")
        rs_helper_ble.ble_connect_DUT_as_master(ble_dut=ble_dut, ble_remote=ble_client,
                                                ble_dut_address=bt_dut_address,
                                                ble_remote_address=bt_client_address, smp_flag=True)
        logger().info("Check connection status of BLE")
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
        logger().info("DUT is not disconnected from BLE")
        # Disconnect
        ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', 'ble_stop_scan'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_master_rd_directed_connectable_c19834(ble_dut, ble_client, rs_helper_ble):
    with BleLogs(start_collecting_logs=True,
                 bt_log_path=f"reports/test_ble_dut_master_remote_device_directed_connectable.logs_{int(time.time())}"):
        # Start DUT
        logger().info("start ble...")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "unable to fetch bd address"
        logger().info("start ble client...")
        logger().info(f"bt_dut_address {bt_dut_address}")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
        time.sleep(1)
        assert bt_client_address, "failed to initiate ble in remote device"
        logger().info(f"ble client add..{bt_client_address}")
        ble_client.interfaces.bluetooth.stop_advertising()
        time.sleep(5)
        ble_client.interfaces.bluetooth.close()

        mac_list = bt_dut_address.split(":")
        mac_list.reverse()
        mac_list = ["0x" + s for s in mac_list]
        peer_address = " ".join(mac_list)
        logger().info(f"peer_address {peer_address}")
        time.sleep(5)

        hci_adv_params = f"0x20 0x00 0x20 0x00 0x01 0x00 0x00 {peer_address} 0x07 0x00"
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
            bt_dut_address=bt_dut_address, hci_adv_params=hci_adv_params)
        assert bt_client_address, "failed to initiate ble in remote device"

        logger().info("Start scanning....")
        result = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
        logger().info(f" scan result '{result}")

        logger().info("enabling the power save modes ")
        enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                 RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, "failed to enable wifi power save"
        enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                  RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps, "failed to enable bt power save"

        logger().info("stop scanning")
        ble_dut.interfaces.bluetooth.ble_stop_scanning()

        time.sleep(1)
        ble_client.interfaces.bluetooth.hci_tool_manager.disable_advertisement()
        time.sleep(1)
        ble_client.interfaces.bluetooth.hci_tool_manager.set_advertising_parameters(hci_adv_params)
        time.sleep(1)
        ble_client.interfaces.bluetooth.hci_tool_manager.enable_advertisement()

        logger().info(f"DUT initiating BLE connection with ble_client device")
        rs_helper_ble.ble_connect_DUT_as_master(ble_dut=ble_dut, ble_remote=ble_client,
                                                ble_dut_address=bt_dut_address,
                                                ble_remote_address=bt_client_address, smp_flag=True)

        logger().info("Check connection status of BLE")
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
        logger().info("DUT is not disconnected from BLE")

        # Disconnect
        ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.
        ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp |
        RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init', 'ble_disconnect', "ble_stop_adv"])
@pytest.mark.end_state("wifi_dut", wifi=[ "ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_dut_slave_128_bit_uuid_c19847(ble_dut, ble_client):
    set_local_name = "BLE_GAP_TESTPLAN"
    logger().info(f"Setting BLE local name {set_local_name}")
    ble_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = ble_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")

    logger().info("set dut in adv mode...")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "failed to initiate ble in dut"

    ble_dut.interfaces.bluetooth.ble_uuid_32bit_to_128bit()
    time.sleep(2)
    ble_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info("enabling the power save modes ")
    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("start ble scan from remote le device...")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address, "failed to initiate ble in remote device"
    time.sleep(5)
    ble_client.interfaces.bluetooth.stop_scanning()

    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert ble_dut.interfaces.bluetooth.ble_address in found_devices
    assert (
            found_devices[ble_dut.interfaces.wifi.ble_address]
            == ble_dut.interfaces.bluetooth.ble_advertising_data
    )
    logger().info("connect to dut from remote le device....")
    ble_client.interfaces.bluetooth.connect(bt_dut_address)
    assert bt_dut_address, "unable to connect to the given address"
    time.sleep(30)

    ble_dut.interfaces.bluetooth.ble_advertising = False

    servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
    assert len(servs) > 0, "no services fetched"
    assert len(chars) > 0, "fetched characters are empty"

    logger().info(f"servs: {servs} \n chars:{chars}")
    service_uid = "00001801-0000-1000-8000-00805f9b34fb"
    char_uid = "0000-aabb-0000-1000-8000-0026bb765291"

    ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs, service_uid=service_uid,
                                                                        char_uid=char_uid)
    state = ble_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if state_int > 0:
        logger().info("disconnecting the dut..")
        ble_client.interfaces.bluetooth.disconnect(bt_dut_address)

    ble_client.interfaces.bluetooth.close()
    time.sleep(5)
