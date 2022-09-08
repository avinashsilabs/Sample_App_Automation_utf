import time
import pytest
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect.devices.rs911x import RS9116CoexMode,RS9116AsyncEventType,RS9116FeatureBitMap,RS9116TCPIPFeatureBitMap,\
    RS9116CustomFeatureBitMap,RS9116ExtCustomFeatureBitMap,RS9116ExtTCPIPFeatureBitMap,RS9116ConfigFeatureBitMap,RS9116PowerSaveModes,RS9116PowerSaveProcedureTypes
from utf.utils.logger import get_logger


def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4

    Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. Initiates the DUT in ble.
        3. Initiates the client in Rpi.
        4. makes le connection to remote peer rpi.
        5. configures the phy and validates the configured phy.

    Author: RaviNemali
"""

def ble_connection(ble_dut, ble_client):
    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    logger().info(" ======= start ble adv in remote device")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv()
    assert ble_client_address,"failed to initiate ble in remote device"

    time.sleep(1)
    logger().info(" ======= start scanning in dut")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address, timeout=50)
    time.sleep(5)

    enable_wifi_ps = ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    enable_bt_ps = ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"
    time.sleep(5)

    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=ble_client_address, timeout=timeout)

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected,"device is in disconnection state"
    rc, result = ble_client.interfaces.bluetooth.hci_tool_manager.read_phy(bt_dut_address)
    logger().info(result)
    return ble_client_address,bt_dut_address

def ble_phy_events(ble_dut,ble_client_address):
    events = ble_dut.interfaces.wifi.get_async_events()
    assert "BLE_PHY_UPDATE_COMPLETE" in [event.event_type for event in events], "phy update event not received"
    result = ble_dut.interfaces.bluetooth.ble_read_phy(ble_remote_dev_address=ble_client_address)
    logger().info(f"tx phy {result[0]}, rx phy {result[1]}")
    result = ble_dut.interfaces.bluetooth.ble_read_phy(ble_remote_dev_address=ble_client_address)
    logger().info(result)
    time.sleep(2)
    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=ble_client_address)
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
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.ble_client("bt_wiseconnect")
@pytest.mark.end_state("ble_dut", bluetooth=["bt_powersave_disable"])
def test_ble_phy_change_tx_1_rx_1_lr_125_C19932(ble_dut, ble_client):
    ble_client_address,bt_dut_address=ble_connection(ble_dut,ble_client)
    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(ble_remote_dev_address=ble_client_address, tx_phy=1, rx_phy=1,
                                                      coded_phy=2)
    assert result, "failed to set phy on dut"
    time.sleep(10)
    ble_phy_events(ble_dut,ble_client_address)

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
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.ble_client("bt_wiseconnect")
@pytest.mark.end_state("ble_dut", bluetooth=["bt_powersave_disable"])
def test_ble_phy_change_tx_1_rx_2_lr_125_C19933(ble_dut, ble_client):
    ble_client_address, bt_dut_address = ble_connection(ble_dut, ble_client)
    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(ble_remote_dev_address=ble_client_address, tx_phy=1, rx_phy=2,
                                                      coded_phy=2)
    assert result, "failed to set phy on dut"
    time.sleep(10)
    ble_phy_events(ble_dut, ble_client_address)

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
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.ble_client("bt_wiseconnect")
@pytest.mark.end_state("ble_dut", bluetooth=["bt_powersave_disable"])
def test_ble_phy_change_tx_1_rx_lr_125_C19934(ble_dut, ble_client):
    ble_client_address, bt_dut_address = ble_connection(ble_dut, ble_client)
    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(ble_remote_dev_address=ble_client_address, tx_phy=1, rx_phy=4,
                                                      coded_phy=2)
    assert result, "failed to set phy on dut"
    time.sleep(10)
    ble_phy_events(ble_dut, ble_client_address)

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
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.ble_client("bt_wiseconnect")
@pytest.mark.end_state("ble_dut", bluetooth=["bt_powersave_disable"])
def test_ble_phy_change_tx_2_rx_1_lr_125_C19935(ble_dut, ble_client):
    ble_client_address, bt_dut_address = ble_connection(ble_dut, ble_client)
    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(ble_remote_dev_address=ble_client_address, tx_phy=2, rx_phy=1,
                                                      coded_phy=2)
    assert result, "failed to set phy on dut"
    time.sleep(10)
    ble_phy_events(ble_dut, ble_client_address)

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
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.ble_client("bt_wiseconnect")
@pytest.mark.end_state("ble_dut", bluetooth=["bt_powersave_disable"])
def test_ble_phy_change_tx_2_rx_2_lr_125_C19936(ble_dut, ble_client):
    ble_client_address, bt_dut_address = ble_connection(ble_dut, ble_client)
    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(ble_remote_dev_address=ble_client_address, tx_phy=2, rx_phy=2,
                                                      coded_phy=2)
    assert result, "failed to set phy on dut"
    time.sleep(10)
    ble_phy_events(ble_dut, ble_client_address)

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
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.ble_client("bt_wiseconnect")
@pytest.mark.end_state("ble_dut", bluetooth=["bt_powersave_disable"])
def test_ble_phy_change_tx_2_rx_1_lr_125_C19937(ble_dut, ble_client):
    ble_client_address, bt_dut_address = ble_connection(ble_dut, ble_client)
    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(ble_remote_dev_address=ble_client_address, tx_phy=2, rx_phy=4,
                                                      coded_phy=2)
    assert result, "failed to set phy on dut"
    time.sleep(10)
    ble_phy_events(ble_dut, ble_client_address)

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
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.ble_client("bt_wiseconnect")
@pytest.mark.end_state("ble_dut", bluetooth=["bt_powersave_disable"])
def test_ble_phy_change_tx_rx_1_lr_125_C19938(ble_dut, ble_client):
    ble_client_address, bt_dut_address = ble_connection(ble_dut, ble_client)
    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(ble_remote_dev_address=ble_client_address, tx_phy=4, rx_phy=1,
                                                      coded_phy=2)
    assert result, "failed to set phy on dut"
    time.sleep(10)
    ble_phy_events(ble_dut, ble_client_address)

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
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.ble_client("bt_wiseconnect")
@pytest.mark.end_state("ble_dut", bluetooth=["bt_powersave_disable"])
def test_ble_phy_change_tx_rx_2_lr_125_C19939(ble_dut, ble_client):
    ble_client_address, bt_dut_address = ble_connection(ble_dut, ble_client)
    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(ble_remote_dev_address=ble_client_address, tx_phy=4, rx_phy=2,
                                                      coded_phy=2)
    assert result, "failed to set phy on dut"
    time.sleep(10)
    ble_phy_events(ble_dut, ble_client_address)

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
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.ble_client("bt_wiseconnect")
@pytest.mark.end_state("ble_dut", bluetooth=["bt_powersave_disable"])
def test_ble_phy_change_tx_rx_lr_125_C19940(ble_dut, ble_client):
    ble_client_address, bt_dut_address = ble_connection(ble_dut, ble_client)
    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(ble_remote_dev_address=ble_client_address, tx_phy=4, rx_phy=4,
                                                      coded_phy=2)
    assert result, "failed to set phy on dut"
    time.sleep(10)
    ble_phy_events(ble_dut, ble_client_address)

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
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.ble_client("bt_wiseconnect")
@pytest.mark.end_state("ble_dut", bluetooth=["bt_powersave_disable"])
def test_ble_phy_change_tx_1_rx_lr_500_C19941(ble_dut, ble_client):
    ble_client_address, bt_dut_address = ble_connection(ble_dut, ble_client)
    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(ble_remote_dev_address=ble_client_address, tx_phy=1, rx_phy=4,
                                                      coded_phy=1)
    assert result, "failed to set phy on dut"
    time.sleep(10)
    ble_phy_events(ble_dut, ble_client_address)

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
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.ble_client("bt_wiseconnect")
@pytest.mark.end_state("ble_dut", bluetooth=["bt_powersave_disable"])
def test_ble_phy_change_tx_2_rx_lr_500_C19942(ble_dut, ble_client):
    ble_client_address, bt_dut_address = ble_connection(ble_dut, ble_client)
    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(ble_remote_dev_address=ble_client_address, tx_phy=2, rx_phy=4,
                                                      coded_phy=1)
    assert result, "failed to set phy on dut"
    time.sleep(10)
    ble_phy_events(ble_dut, ble_client_address)

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
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.ble_client("bt_wiseconnect")
@pytest.mark.end_state("ble_dut", bluetooth=["bt_powersave_disable"])
def test_ble_phy_change_tx_rx_1_lr_500_C19943(ble_dut, ble_client):
    ble_client_address, bt_dut_address = ble_connection(ble_dut, ble_client)
    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(ble_remote_dev_address=ble_client_address, tx_phy=4, rx_phy=1,
                                                      coded_phy=1)
    assert result, "failed to set phy on dut"
    time.sleep(10)
    ble_phy_events(ble_dut, ble_client_address)

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
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.ble_client("bt_wiseconnect")
@pytest.mark.end_state("ble_dut", bluetooth=["bt_powersave_disable"])
def test_ble_phy_change_tx_rx_2_lr_500_C19944(ble_dut, ble_client):
    ble_client_address, bt_dut_address = ble_connection(ble_dut, ble_client)
    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(ble_remote_dev_address=ble_client_address, tx_phy=4, rx_phy=2,
                                                      coded_phy=1)
    assert result, "failed to set phy on dut"
    time.sleep(10)
    ble_phy_events(ble_dut, ble_client_address)


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
        "config_features": RS9116ConfigFeatureBitMap.Default| RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.ble_client("bt_wiseconnect")
@pytest.mark.end_state("ble_dut", bluetooth=["bt_powersave_disable"])
def test_ble_phy_change_tx_rx_lr_500_C19945(ble_dut, ble_client):
    ble_client_address, bt_dut_address = ble_connection(ble_dut, ble_client)
    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(ble_remote_dev_address=ble_client_address, tx_phy=4, rx_phy=4,
                                                      coded_phy=1)
    assert result, "failed to set phy on dut"
    time.sleep(10)
    ble_phy_events(ble_dut, ble_client_address)