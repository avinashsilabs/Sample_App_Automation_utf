import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode,
from utf.utils.logger import get_logger
import time
from utf.interfaces.bluetooth import BLEDeviceState

def logger():
    return get_logger(__name__)

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

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
def test_ble_phy_change_C19932(ble_dut, ble_client):
    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    logger().info("start ble adv in remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv()
    assert bt_client_address,"failed to initiate ble in remote device"

    time.sleep(1)
    logger().info("start scanning in dut")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected,"device is in disconnection state"

    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(tx_phy=1,rx_phy=1,coded_phy=125)
    assert result,"failed to set phy on dut"

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

def test_ble_phy_change_C19933(ble_dut, ble_client):
    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    logger().info("start ble adv in remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv()
    assert bt_client_address,"failed to initiate ble in remote device"

    time.sleep(1)
    logger().info("start scanning in dut")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected,"device is in disconnection state"

    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(tx_phy=1,rx_phy=2,coded_phy=125)
    assert result,"failed to set phy on dut"

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

def test_ble_phy_change_C19934(ble_dut, ble_client):
    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    logger().info("start ble adv in remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv()
    assert bt_client_address,"failed to initiate ble in remote device"

    time.sleep(1)
    logger().info("start scanning in dut")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected,"device is in disconnection state"

    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(tx_phy=1,rx_phy=125,coded_phy=125)
    assert result,"failed to set phy on dut"

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

def test_ble_phy_change_C19935(ble_dut, ble_client):
    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    logger().info("start ble adv in remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv()
    assert bt_client_address,"failed to initiate ble in remote device"

    time.sleep(1)
    logger().info("start scanning in dut")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected,"device is in disconnection state"

    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(tx_phy=2,rx_phy=1,coded_phy=125)
    assert result,"failed to set phy on dut"

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

def test_ble_phy_change_C19936(ble_dut, ble_client):
    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    logger().info("start ble adv in remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv()
    assert bt_client_address,"failed to initiate ble in remote device"

    time.sleep(1)
    logger().info("start scanning in dut")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected,"device is in disconnection state"

    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(tx_phy=2,rx_phy=2,coded_phy=125)
    assert result,"failed to set phy on dut"

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

def test_ble_phy_change_C19937(ble_dut, ble_client):
    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    logger().info("start ble adv in remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv()
    assert bt_client_address,"failed to initiate ble in remote device"

    time.sleep(1)
    logger().info("start scanning in dut")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected,"device is in disconnection state"

    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(tx_phy=2,rx_phy=125,coded_phy=125)
    assert result,"failed to set phy on dut"

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

def test_ble_phy_change_C19938(ble_dut, ble_client):
    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    logger().info("start ble adv in remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv()
    assert bt_client_address,"failed to initiate ble in remote device"

    time.sleep(1)
    logger().info("start scanning in dut")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected,"device is in disconnection state"

    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(tx_phy=125,rx_phy=1,coded_phy=125)
    assert result,"failed to set phy on dut"

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

def test_ble_phy_change_C19939(ble_dut, ble_client):
    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    logger().info("start ble adv in remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv()
    assert bt_client_address,"failed to initiate ble in remote device"

    time.sleep(1)
    logger().info("start scanning in dut")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected,"device is in disconnection state"

    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(tx_phy=125,rx_phy=2,coded_phy=125)
    assert result,"failed to set phy on dut"

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

def test_ble_phy_change_C19940(ble_dut, ble_client):
    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    logger().info("start ble adv in remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv()
    assert bt_client_address,"failed to initiate ble in remote device"

    time.sleep(1)
    logger().info("start scanning in dut")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected,"device is in disconnection state"

    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(tx_phy=125,rx_phy=125,coded_phy=125)
    assert result,"failed to set phy on dut"

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

def test_ble_phy_change_C19941(ble_dut, ble_client):
    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    logger().info("start ble adv in remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv()
    assert bt_client_address,"failed to initiate ble in remote device"

    time.sleep(1)
    logger().info("start scanning in dut")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected,"device is in disconnection state"

    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(tx_phy=1,rx_phy=500,coded_phy=500)
    assert result,"failed to set phy on dut"

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

def test_ble_phy_change_C19942(ble_dut, ble_client):
    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    logger().info("start ble adv in remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv()
    assert bt_client_address,"failed to initiate ble in remote device"

    time.sleep(1)
    logger().info("start scanning in dut")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected,"device is in disconnection state"

    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(tx_phy=2,rx_phy=500,coded_phy=500)
    assert result,"failed to set phy on dut"

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

def test_ble_phy_change_C19943(ble_dut, ble_client):
    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    logger().info("start ble adv in remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv()
    assert bt_client_address,"failed to initiate ble in remote device"

    time.sleep(1)
    logger().info("start scanning in dut")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected,"device is in disconnection state"

    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(tx_phy=500,rx_phy=1,coded_phy=500)
    assert result,"failed to set phy on dut"

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

def test_ble_phy_change_C19944(ble_dut, ble_client):
    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    logger().info("start ble adv in remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv()
    assert bt_client_address,"failed to initiate ble in remote device"

    time.sleep(1)
    logger().info("start scanning in dut")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected,"device is in disconnection state"

    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(tx_phy=500,rx_phy=2,coded_phy=500)
    assert result,"failed to set phy on dut"

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

def test_ble_phy_change_C19945(ble_dut, ble_client):
    logger().info("start ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address,"failed to initiate ble in dut"

    logger().info("start ble adv in remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv()
    assert bt_client_address,"failed to initiate ble in remote device"

    time.sleep(1)
    logger().info("start scanning in dut")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected,"device is in disconnection state"

    logger().info("set phy in dut")
    result = ble_dut.interfaces.bluetooth.ble_set_phy(tx_phy=500,rx_phy=500,coded_phy=500)
    assert result,"failed to set phy on dut"

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)