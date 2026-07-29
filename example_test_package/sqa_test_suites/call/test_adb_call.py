"""
ADB phone call control tests for BT Audio Gateway (AG) and Hands-Free Profile (HFP).

Tests Bluetooth call functionality between wifi_dut (acting as Audio Gateway)
and an Android phone controlled via ADB. Follows UTF test structure pattern
similar to test_bt_spp_example.py and test_ag.py.
"""
import time
import pytest
from utf.interfaces.adb import PhoneState
from utf.utf_config import UtfConfig
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116ExtCustomFeatureBitMap

# Configure wifi_dut for Bluetooth coex mode (required for BT AG functionality)
pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default |
                                   RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid
        }
    )
]


def logger():
    return get_logger(__name__)


def get_adb_config(adb_phone):
    config = dict(UtfConfig.instance().defaults.get("adb", {}))
    config.update(adb_phone.config.get("interfaces", {}).get("adb", {}))
    config.update(adb_phone.config.get("adb", {}))
    return config


@pytest.mark.test_src_map_id('TC_ADB_PHONE_CALL_001')
def test_adb_phone_outgoing_call_basic(adb_phone):
    """
    Basic ADB phone test: place and terminate outgoing call (standalone, no DUT).
    
    This is a simple test to verify ADB phone control works.
    Use this to validate your ADB setup before running DUT integration tests.
    
    Requirements:
        - Configure target_number in harness defaults.adb.target_number
        - Or override per-test: @pytest.mark.config("adb_phone", adb={"target_number": "+1234567890"})
        - Ensure adb_phone device is configured in harness
    
    Example:
        pytest test_adb_call.py::test_adb_phone_outgoing_call_basic -v
    """
    # Get target number from harness config (UTF pattern)
    logger().info("Starting ADB phone outgoing call test......")
    time.sleep(30)
    target_number = get_adb_config(adb_phone).get('target_number')
    if not target_number:
        pytest.skip("Configure target_number in harness defaults.adb.target_number")

    logger().info(f"Testing ADB phone call to {target_number}")
    adb_iface = adb_phone.interfaces.adb

    # Ensure phone starts in IDLE state
    assert adb_iface.get_call_state() == PhoneState.IDLE, "Phone not in IDLE state"

    # Place outgoing call
    logger().info(f"Placing call to {target_number}")
    ok = adb_iface.place_call(target_number)
    assert ok, "ADB place_call command failed"

    # Wait for outgoing call to reach OFFHOOK (connected)
    logger().info("Waiting for call to connect (OFFHOOK)...")
    connected = adb_iface.wait_for_state(PhoneState.OFFHOOK, timeout=30)
    
    try:
        assert connected, "Call did not reach OFFHOOK within 30 seconds"
        logger().info("Call connected successfully")
        
        # Hold call for a moment
        time.sleep(10)
        
    finally:
        # Always terminate call in cleanup
        logger().info("Terminating call...")
        adb_iface.terminate_call()
        
        # Verify phone returns to IDLE
        idle = adb_iface.wait_for_state(PhoneState.IDLE, timeout=15)
        assert idle, "Phone did not return to IDLE after termination"
        logger().info("Call terminated, phone returned to IDLE")


@pytest.mark.test_src_map_id('TC_ADB_PHONE_CALL_003')
def test_adb_phone_to_phone_call_accept_and_disconnect_from_caller(adb_phones):
    """
    Place a call from one Android phone, accept it on another Android phone,
    then disconnect the call from the caller phone.

    Harness/config expectations:
        - adb_phones[0] is the receiver phone configured in the harness
        - adb_phones[1] is the caller phone configured in the harness
        - defaults.adb.target_number is the receiver phone number
    """
    time.sleep(20)
    if len(adb_phones) < 2:
        pytest.skip("Configure at least two devices under defaults.adb_phones")

    receiver_phone = adb_phones[0]
    caller_phone = adb_phones[1]
    config = get_adb_config(receiver_phone)
    target_number = config.get("target_number")
    if not target_number:
        pytest.skip("Configure target_number in harness defaults.adb.target_number")

    receiver_iface = receiver_phone.interfaces.adb
    caller_iface = caller_phone.interfaces.adb

    logger().info("Starting two-phone ADB call test")
    logger().info(f"Caller device: {caller_iface.device_id}")
    logger().info(f"Receiver device: {receiver_iface.device_id}")
    logger().info(f"Calling receiver number: {target_number}")

    assert caller_iface.get_call_state() == PhoneState.IDLE, "Caller phone not in IDLE state"
    assert receiver_iface.get_call_state() == PhoneState.IDLE, "Receiver phone not in IDLE state"

    call_started = False
    call_accepted = False
    try:
        logger().info("Placing call from caller phone")
        call_started = caller_iface.place_call(target_number)
        assert call_started, "Caller ADB place_call command failed"

        logger().info("Waiting for receiver phone to ring")
        ringing = receiver_iface.wait_for_state(PhoneState.RINGING, timeout=45)
        assert ringing, "Receiver phone did not reach RINGING state"

        logger().info("Accepting call on receiver phone")
        call_accepted = receiver_iface.accept_incoming_call()
        assert call_accepted, "Receiver ADB accept_incoming_call command failed"

        logger().info("Confirming call is connected on both phones")
        receiver_connected = receiver_iface.wait_for_state(PhoneState.OFFHOOK, timeout=45)
        caller_connected = caller_iface.wait_for_state(PhoneState.OFFHOOK, timeout=20)
        caller_state = caller_iface.get_call_state()
        receiver_state = receiver_iface.get_call_state()
        assert receiver_connected, (
            f"Receiver phone did not reach OFFHOOK state; "
            f"caller={caller_state}, receiver={receiver_state}"
        )
        assert caller_connected, (
            f"Caller phone did not reach OFFHOOK state; "
            f"caller={caller_state}, receiver={receiver_state}"
        )

        time.sleep(5)

    finally:
        if call_started or call_accepted:
            logger().info("Disconnecting call from caller phone")
            caller_iface.terminate_call()

        caller_idle = caller_iface.wait_for_state(PhoneState.IDLE, timeout=20)
        receiver_idle = receiver_iface.wait_for_state(PhoneState.IDLE, timeout=20)
        assert caller_idle, "Caller phone did not return to IDLE after disconnect"
        assert receiver_idle, "Receiver phone did not return to IDLE after disconnect"
        logger().info("Call disconnected from caller, both phones returned to IDLE")


@pytest.mark.test_src_map_id('TC_ADB_PHONE_CALL_002')
@pytest.mark.config("adb_phone", adb={"wait_incoming": True})  # Enable incoming call test
def test_adb_phone_incoming_call_detection(adb_phone):
    """
    Test detecting and handling incoming calls via logcat monitoring.
    
    This test waits for an incoming call and demonstrates logcat-based detection.
    You need to manually initiate a call to the phone during the test.
    
    Requirements:
        - Test is enabled via @pytest.mark.config marker
        - Have another phone ready to call the test phone
    
    Example:
        pytest test_adb_call.py::test_adb_phone_incoming_call_detection -v
    """
    # Check if incoming call test is enabled via config marker
    if not get_adb_config(adb_phone).get('wait_incoming', False):
        pytest.skip("Incoming call test disabled. Enable with @pytest.mark.config marker")
    adb_iface = adb_phone.interfaces.adb

    # Ensure starting in IDLE
    assert adb_iface.get_call_state() == PhoneState.IDLE, "Phone not in IDLE state"
    
    # Wait for incoming call indicator in logcat
    logger().info("=" * 80)
    logger().info("WAITING FOR INCOMING CALL - Please call the phone now")
    logger().info("=" * 80)
    
    incoming = adb_iface.incoming_call_detected_via_log(timeout=60)
    assert incoming, "No incoming call detected in logcat within 60 seconds"
    
    logger().info("Incoming call detected via logcat!")
    
    # Verify phone is in RINGING state
    state = adb_iface.get_call_state()
    logger().info(f"Current call state: {state}")
    
    # Accept the call
    logger().info("Accepting incoming call...")
    adb_iface.accept_incoming_call()
    time.sleep(1)
    
    # Verify call state is OFFHOOK (connected)
    offhook = adb_iface.wait_for_state(PhoneState.OFFHOOK, timeout=10)
    assert offhook, "Call did not reach OFFHOOK after accepting"
    logger().info("Call accepted and connected")
    
    # Hold call briefly
    time.sleep(2)
    
    # Terminate call
    logger().info("Terminating call...")
    adb_iface.terminate_call()
    
    idle = adb_iface.wait_for_state(PhoneState.IDLE, timeout=15)
    assert idle, "Phone did not return to IDLE after termination"
    logger().info("Call terminated successfully")


@pytest.mark.test_src_map_id('TC_BT_AG_PHONE_001')
def test_bt_ag_call_establish_with_phone(wifi_dut, adb_phone):
    """
    Test BT Audio Gateway (AG) call establishment between wifi_dut and Android phone.
    
    This test follows the UTF pattern for DUT + companion device testing.
    The wifi_dut acts as the Audio Gateway (AG) and the Android phone (controlled
    via ADB) acts as the Hands-Free (HF) device.
    
    Test Flow:
        1. Initialize wifi_dut with BT coex mode
        2. Start BT connection between wifi_dut and phone
        3. wifi_dut initiates AG call
        4. Verify call state on phone via ADB
        5. Terminate call
        6. Verify cleanup
    
    Requirements:
        - wifi_dut must support BT AG profile
        - adb_phone must be paired/connected to wifi_dut
        - Configure target_number in harness defaults.adb.target_number
    
    Example:
        pytest test_adb_call.py::test_bt_ag_call_establish_with_phone -v
    """
    # Get target number from harness config (UTF pattern)
    target_number = get_adb_config(adb_phone).get('target_number')
    if not target_number:
        pytest.skip("Configure target_number in harness defaults.adb.target_number")
    
    with TimeMeasurer() as t:
        logger().info("=" * 80)
        logger().info("STEP 1: Initialize wifi_dut BT interface")
        logger().info("=" * 80)
        
        # Get DUT local BT address
        dut_address = wifi_dut.interfaces.wifi.get_local_address()
        logger().info(f"DUT BT address: {dut_address}")
        adb_iface = adb_phone.interfaces.adb
        
        # Ensure phone is in IDLE state
        phone_state = adb_iface.get_call_state()
        logger().info(f"Phone initial state: {phone_state}")
        assert phone_state == PhoneState.IDLE, f"Phone not in IDLE state: {phone_state}"
        
        logger().info("=" * 80)
        logger().info("STEP 2: Establish BT connection between DUT and phone")
        logger().info("=" * 80)
        
        # Note: Actual BT connection setup depends on your wifi_dut API
        # This is a placeholder - adjust based on your DUT's BT connection methods
        # Example: wifi_dut.interfaces.wifi.bt_connect(phone_address)
        
        logger().info("=" * 80)
        logger().info("STEP 3: DUT initiates AG call")
        logger().info("=" * 80)
        
        # Placeholder for AG call establishment via DUT
        # Adjust based on your wifi_dut AG API (similar to test_ag.py)
        # Example: wifi_dut.interfaces.wifi.bt_ag_call_establish(phone_address, target_number)
        
        logger().info(f"AG call to {target_number} initiated by DUT")
        
        logger().info("=" * 80)
        logger().info("STEP 4: Verify call state on phone via ADB")
        logger().info("=" * 80)
        
        # Wait for phone to show incoming call (RINGING) or outgoing call (OFFHOOK)
        # depending on AG call direction
        time.sleep(2)
        phone_state = adb_iface.get_call_state()
        logger().info(f"Phone call state: {phone_state}")
        
        # For now, we'll do a basic phone-side call verification
        # In real implementation, sync this with DUT's AG call state
        
        logger().info("=" * 80)
        logger().info("STEP 5: Terminate call")
        logger().info("=" * 80)
        
        # Terminate via DUT AG or via phone
        # Example: wifi_dut.interfaces.wifi.bt_ag_call_terminate()
        adb_iface.terminate_call()
        
        idle = adb_iface.wait_for_state(PhoneState.IDLE, timeout=15)
        assert idle, "Phone did not return to IDLE"
        
        logger().info("=" * 80)
        logger().info("STEP 6: Cleanup")
        logger().info("=" * 80)
        
        # Disconnect BT connection
        # Example: wifi_dut.interfaces.wifi.btc_disconnect(phone_address)
        
        logger().info(f"✅ Test completed in {t.elapsed_time():.2f}s")
        
        # TODO: Implement full AG call flow when DUT AG API is available
        pytest.skip("Full AG call flow pending DUT AG API implementation")
