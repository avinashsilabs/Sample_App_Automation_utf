from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils import print_dict
import os
import shutil
import time
from datetime import datetime
from typing import Optional
import pytest
from threading import Thread
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utf_config import UtfConfig
from utf_wifi_zephyr.devices.si91x import (
    WiFiPs,
    WiFiPsWakeupMode,
    WiFiPsParamType,
    WiFiPsMode,
    WiFiPsExitStrategy,
)
from utf_wifi_zephyr.utils.sl_status import SLStatus

"""
    Setup requirement:
        1. SoC board
        2. Raspberry PI4
        3. Access Point
        4. Sniffer (NUC device)

    Test Steps:
        1. Configure the DUT in WLAN alone mode and connect it to the access point
        2. Enable DHCP or assign IP configuration after connection
        3. Enable the required WLAN power save mode on the DUT
        4. Initiate ping or traffic based on the test scenario
        5. Validate power save behavior using DUT logs, connectivity checks, and sniffer capture

    Author: Vinod.G
"""


def logger():
    return get_logger(__name__)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


WIFI_PS_WAKEUP_MODE_TEXT = {
    WiFiPsWakeupMode.DTIM: "DTIM",
    WiFiPsWakeupMode.ListenInterval: "Listen interval",
}

# siwx91x driver caps listen interval at 1000 ms (see siwx91x_wifi_ps.c).
# wifi_ps_config reports beacon intervals; with typical ~100 ms beacons, values > 10 read back as 10.
WIFI_PS_LISTEN_INTERVAL_DRIVER_MAX = 10

# FAST PSP uses EVERY_TIM exit strategy; monitor interval maps to wifi_ps timeout_ms.
FAST_PSP_MONITOR_INTERVAL_MS = 50
FAST_PSP_LISTEN_INTERVAL = 800
FAST_PSP_LI_MONITOR_INTERVAL_MS = 70
WIFI_PS_EXIT_STRATEGY_FAST_PSP_TEXT = "Every TIM"
FAST_PSP_TEST_CASES = ('1742327', '1742328')
FAST_PSP_SELF_ENABLE_TEST_CASES = FAST_PSP_TEST_CASES + ('1742329', '1742330')
FAST_PSP_LISTEN_INTERVAL_TEST_CASES = ('1742329', '1742330')

AP_BEACON_INTERVAL_MS = 100
POWERSAVE_CAPTURE_PATH = './reports/Powersave_capture.txt'
C1742322_CONFIGURED_LISTEN_INTERVAL_BEACONS = 16
# siwx91x caps at 10 beacon intervals regardless of configured value (e.g. 16 -> 10).
C1742322_EFFECTIVE_LISTEN_INTERVAL_BEACONS = WIFI_PS_LISTEN_INTERVAL_DRIVER_MAX
C1742335_CONFIGURED_LISTEN_INTERVAL_BEACONS = 8
C1742335_EFFECTIVE_LISTEN_INTERVAL_BEACONS = 8
C1742331_CONFIGURED_LISTEN_INTERVAL_BEACONS = 5
C1742331_EFFECTIVE_LISTEN_INTERVAL_BEACONS = 5
C1742331_KEEP_ALIVE_IDLE_SEC = 300


def get_effective_listen_interval(configured_listen_interval: int) -> int:
    """Return listen interval as reported by wifi_ps_config after driver clamping."""
    if configured_listen_interval == 0:
        return 0
    return min(configured_listen_interval, WIFI_PS_LISTEN_INTERVAL_DRIVER_MAX)


def get_effective_listen_interval_ms(configured_listen_interval: int,
                                     beacon_interval_ms: int = AP_BEACON_INTERVAL_MS) -> int:
    """Return driver-effective listen interval in milliseconds for sniffer validation."""
    return get_effective_listen_interval(configured_listen_interval) * beacon_interval_ms


def archive_powersave_capture(test_name: str) -> Optional[str]:
    """Copy Powersave_capture.txt to a test-specific archive with timestamp."""
    if not os.path.isfile(POWERSAVE_CAPTURE_PATH):
        logger().warning(f"Powersave capture file not found at {POWERSAVE_CAPTURE_PATH}")
        return None

    os.makedirs('./reports', exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    archive_name = f"{test_name}_{timestamp}_Powersave_capture.txt"
    archive_path = os.path.join('./reports', archive_name)
    shutil.copy2(POWERSAVE_CAPTURE_PATH, archive_path)
    logger().info(f"Archived powersave capture to {archive_path}")
    return archive_path


def validate_powersave_capture_and_archive(wifi_sniffer, ap_bssid, dut_mac_address, capture_filename):
    """Run power-save sniffer validation, then archive Powersave_capture.txt."""
    assoc_obj = FilterPacket()
    validation = True
    packet_filter10 = "    Type/Subtype: Association Response (0x0001)"
    packet_filter1 = (
        f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && '
        f'(wlan.da == {dut_mac_address})))'
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(
        validation, packet_filter1, packet_filter10)['packet_count'], \
        'No packet found for Assoc resp frame'

    time.sleep(1)
    association_id = assoc_obj.get_association_id()
    if association_id is None:
        logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
        assert False
    else:
        logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

    packet_filter2 = (
        f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && '
        f'(wlan.sa == {dut_mac_address}) && (wlan.da == {ap_bssid}))'
    )

    packet_filter3 = (
        f'(wlan.da == {dut_mac_address} && wlan.fc.type_subtype == 0x28) || '
        f'(wlan.ta == {dut_mac_address} && (wlan.fc.type_subtype == 0x24 || '
        f'wlan.fc.type_subtype ==0x1a)) || (wlan.sa == {ap_bssid} && '
        f'wlan.fc.type_subtype==8) || ((wlan.sa == {ap_bssid} && '
        f'wlan.da == {dut_mac_address}) && (wlan.fc.type_subtype == 0x002c || '
        f'wlan.fc.type_subtype == 0x000d || wlan.fc.type_subtype == 0x0018))'
    )

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count']
    powersave_validation = True
    assert wifi_sniffer.interfaces.capture.sniffer_validation(
        validation, packet_filter3, None, powersave_validation)['packet_count']

    archive_powersave_capture(capture_filename)
    return association_id


def validate_power_save_wakeup_mode(ps_config, expected_wakeup_mode: WiFiPsWakeupMode):
    """Assert wifi_ps_config wakeup_mode matches the value set via WiFiPsParamType.WakeupMode."""
    assert isinstance(ps_config, dict), (
        f"Expected wifi_ps_config to return a dict, got: {ps_config!r}"
    )
    expected_text = WIFI_PS_WAKEUP_MODE_TEXT[expected_wakeup_mode]
    wakeup_mode = ps_config.get("wakeup_mode")
    assert wakeup_mode == expected_text, (
        f"Expected {expected_wakeup_mode.name}-based power save "
        f"(wakeup_mode={expected_text!r}), got {wakeup_mode!r}. "
        f"Full PS config: {ps_config}"
    )


def validate_power_save_listen_interval(ps_config, configured_listen_interval: int):
    """Assert wifi_ps_config listen_interval matches driver-effective value."""
    assert isinstance(ps_config, dict), (
        f"Expected wifi_ps_config to return a dict, got: {ps_config!r}"
    )
    expected_listen_interval = get_effective_listen_interval(configured_listen_interval)
    listen_interval = ps_config.get("listen_interval")
    assert listen_interval == expected_listen_interval, (
        f"Expected listen_interval={expected_listen_interval} "
        f"(configured={configured_listen_interval}), got {listen_interval!r}. "
        f"Full PS config: {ps_config}"
    )


def enable_fast_psp_dtim_power_save(wifi_dut, monitor_interval_ms=FAST_PSP_MONITOR_INTERVAL_MS):
    """Enable FAST PSP with DTIM wake-up (mirrors siwx91x_power_save_enable() in fast_psp sample)."""
    wifi_dut.interfaces.wifi.wifi_ps(
        param_type=WiFiPsParamType.ExitStrategy,
        exit_strategy=WiFiPsExitStrategy.EveryTim,
    )
    wifi_dut.interfaces.wifi.wifi_ps(
        param_type=WiFiPsParamType.WakeupMode,
        wakeup_mode=WiFiPsWakeupMode.DTIM,
    )
    wifi_dut.interfaces.wifi.wifi_ps(
        param_type=WiFiPsParamType.Timeout,
        timeout_ms=monitor_interval_ms,
    )
    wifi_dut.interfaces.wifi.wifi_ps(
        param_type=WiFiPsParamType.State,
        enabled=WiFiPs.Enabled,
    )


def validate_fast_psp_power_save_config(ps_config, monitor_interval_ms=FAST_PSP_MONITOR_INTERVAL_MS):
    """Assert wifi_ps_config reflects FAST PSP, DTIM wake-up, and monitor interval."""
    assert isinstance(ps_config, dict), (
        f"Expected wifi_ps_config to return a dict, got: {ps_config!r}"
    )
    assert ps_config.get("enabled") is True, (
        f"Expected power save enabled, got: {ps_config!r}"
    )
    validate_power_save_wakeup_mode(ps_config, WiFiPsWakeupMode.DTIM)
    assert ps_config.get("exit_strategy") == WIFI_PS_EXIT_STRATEGY_FAST_PSP_TEXT, (
        f"Expected FAST PSP exit strategy {WIFI_PS_EXIT_STRATEGY_FAST_PSP_TEXT!r}, "
        f"got {ps_config.get('exit_strategy')!r}. Full PS config: {ps_config}"
    )
    assert ps_config.get("timeout_ms") == monitor_interval_ms, (
        f"Expected monitor interval (timeout_ms)={monitor_interval_ms}, "
        f"got {ps_config.get('timeout_ms')!r}. Full PS config: {ps_config}"
    )


def enable_fast_psp_listen_interval_power_save(
        wifi_dut,
        monitor_interval_ms=FAST_PSP_LI_MONITOR_INTERVAL_MS,
        configure_monitor_interval=True):
    """Enable FAST PSP with listen-interval wake-up and optional monitor interval."""
    wifi_dut.interfaces.wifi.wifi_ps(
        param_type=WiFiPsParamType.ExitStrategy,
        exit_strategy=WiFiPsExitStrategy.EveryTim,
    )
    wifi_dut.interfaces.wifi.wifi_ps(
        param_type=WiFiPsParamType.WakeupMode,
        wakeup_mode=WiFiPsWakeupMode.ListenInterval,
    )
    if configure_monitor_interval:
        wifi_dut.interfaces.wifi.wifi_ps(
            param_type=WiFiPsParamType.Timeout,
            timeout_ms=monitor_interval_ms,
        )
    wifi_dut.interfaces.wifi.wifi_ps(
        param_type=WiFiPsParamType.State,
        enabled=WiFiPs.Enabled,
    )


def validate_fast_psp_listen_interval_power_save_config(
        ps_config,
        configured_listen_interval=FAST_PSP_LISTEN_INTERVAL,
        monitor_interval_ms=FAST_PSP_LI_MONITOR_INTERVAL_MS,
        expect_monitor_interval_disabled=False):
    """Assert wifi_ps_config reflects FAST PSP with listen-interval wake-up."""
    assert isinstance(ps_config, dict), (
        f"Expected wifi_ps_config to return a dict, got: {ps_config!r}"
    )
    assert ps_config.get("enabled") is True, (
        f"Expected power save enabled, got: {ps_config!r}"
    )
    validate_power_save_wakeup_mode(ps_config, WiFiPsWakeupMode.ListenInterval)
    validate_power_save_listen_interval(ps_config, configured_listen_interval)
    assert ps_config.get("exit_strategy") == WIFI_PS_EXIT_STRATEGY_FAST_PSP_TEXT, (
        f"Expected FAST PSP exit strategy {WIFI_PS_EXIT_STRATEGY_FAST_PSP_TEXT!r}, "
        f"got {ps_config.get('exit_strategy')!r}. Full PS config: {ps_config}"
    )
    if expect_monitor_interval_disabled:
        assert ps_config.get("timeout_disabled") or ps_config.get("timeout_ms") in (None, 0), (
            f"Expected monitor interval disabled (timeout_ms=0), "
            f"got timeout_ms={ps_config.get('timeout_ms')!r}. Full PS config: {ps_config}"
        )
    else:
        assert ps_config.get("timeout_ms") == monitor_interval_ms, (
            f"Expected monitor interval (timeout_ms)={monitor_interval_ms}, "
            f"got {ps_config.get('timeout_ms')!r}. Full PS config: {ps_config}"
        )


PS_SWITCH_DURATION_SEC = 30 * 60


def run_power_save_enable_disable_switching(wifi_dut, zephyr_wifi_collections, device_ip):
    """Toggle power save enable/disable for 30 minutes and verify DUT responds to ping."""
    end_time = time.time() + PS_SWITCH_DURATION_SEC
    iteration = 0
    while time.time() < end_time:
        iteration += 1
        logger().info(f"PS switch iteration {iteration}: enabling power save")
        wifi_dut.interfaces.wifi.wifi_ps(
            param_type=WiFiPsParamType.State,
            enabled=WiFiPs.Enabled,
        )
        status = zephyr_wifi_collections.ping_with_custom_size(
            device_ip, ping_counts=10, byte_size=100)
        assert status, "DUT not responding to ping after power save enable"

        logger().info(f"PS switch iteration {iteration}: disabling power save")
        wifi_dut.interfaces.wifi.wifi_ps(
            param_type=WiFiPsParamType.State,
            enabled=WiFiPs.Disabled,
        )
        status = zephyr_wifi_collections.ping_with_custom_size(
            device_ip, ping_counts=10, byte_size=100)
        assert status, "DUT not responding to ping after power save disable"

    logger().info(
        f"Completed power save enable/disable switching for {PS_SWITCH_DURATION_SEC // 60} minutes "
        f"in {iteration} iterations"
    )


def run_connect_disconnect_with_listen_interval_ps(wifi_obj):
    """Connect via WifiJoin and disconnect via leave() for 30 minutes."""
    end_time = time.time() + PS_SWITCH_DURATION_SEC
    iteration = 0
    while time.time() < end_time:
        iteration += 1
        remaining_min = int((end_time - time.time()) / 60)
        logger().info(
            f"Connect/disconnect iteration {iteration}: remaining time ~{remaining_min} minutes"
        )
        wifi_obj.connect_with_power_save()
        wifi_obj.disconnect_from_ap()

    logger().info(
        f"Completed connect/disconnect with listen-interval power save for "
        f"{PS_SWITCH_DURATION_SEC // 60} minutes in {iteration} iterations"
    )


class FilterPacket:
    """Sniffer frame analysis for listen-interval power save validation (ref: C19693)."""

    def get_association_id(self):
        # This function will parse the pacap file and find & return the association id
        packet_filter = "= Association ID:"
        association_id = None
        count = 0

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()
        for x in line:
            count = count + 1
            if packet_filter in x:
                association_id = x.strip().split(':')[1].strip()
                logger().info(f'Association id = {association_id}')
                break
        filter_file.close()
        return association_id

    def validate_time_delta(self, ps_poll_packets_time_delta_list, time_delta_for_listen_interval):
        """
         Validates DUT is waking at listen inteval time or not and it returns the count of when DUT didn't send the
         ps_poll at listen interval
        """

        unable_to_send_ps_poll_at_li = 0
        listen_interval_beacon = int(time_delta_for_listen_interval / 100)
        for time_diff in ps_poll_packets_time_delta_list:
            is_between = time_diff in range(time_delta_for_listen_interval - 20, time_delta_for_listen_interval + 90)
            logger().info(f'is_between = {is_between}')
            if is_between is True:
                logger().info(
                    f'DUT sends PS-poll after {listen_interval_beacon} consecutive beacon frame and time diff is = {time_diff / 1000}')
            else:
                logger().info(
                    f'DUT unable to send PS-poll after {listen_interval_beacon} consecutive beacon frame and time diff is = {time_diff / 1000}')
                unable_to_send_ps_poll_at_li = unable_to_send_ps_poll_at_li + 1
        return unable_to_send_ps_poll_at_li

    def validate_pspoll_data_packet_with_more_bit_enable(self, frame_list, frame_number, listen_interval_time,
                                                         current_beacon_time, beacon_count=None, listen_interval=None):
        """
        PS-Poll Data Packet Validation with More Bit Enable Function

        Flowchart Description:
        ┌─────────────────────────────────────────────────────────┐
        │ A[Start PS-Poll Validation]                            │
        │ ↓                                                       │
        │ B[Initialize Variables:<br/>                           │
        │   - Frame types (beacon, ps_poll, qos_data, etc.)<br/> │
        │   - Timing variables<br/>                              │
        │   - Counter variables]                                 │
        │ ↓                                                       │
        │ C[Main Processing Loop: while frame_number < total]    │
        │ ↓                                                       │
        │ D{Is frame NULL with PM='0'?}                          │
        │ ↓ Yes                                                   │
        │ E[Process Active State Entry:<br/>                     │
        │   - Calculate ps_exit_interval<br/>                    │
        │   - Find corresponding NULL with PM='1']              │
        │ ↓                                                       │
        │ F{Is frame QoS/Action with more_bit='1'?}              │
        │ ↓ Yes                                                   │
        │ G[Process More Data Bit Set:<br/>                      │
        │   - Search for next beacon<br/>                        │
        │   - Check if PS-Poll follows<br/>                      │
        │   - Validate timing constraints]                       │
        │ ↓                                                       │
        │ H{Is frame PS-Poll?}                                   │
        │ ↓ Yes                                                   │
        │ I[Continue to next frame]                              │
        │ ↓                                                       │
        │ J{Is frame Beacon?}                                    │
        │ ↓ Yes                                                   │
        │ K[Process Beacon:<br/>                                 │
        │   - Update beacon count<br/>                           │
        │   - Calculate timing differences<br/>                  │
        │   - Check for data frames]                             │
        │ ↓                                                       │
        │ L[Return: frame_number, case2, first_beacon_time,      │
        │   ps_exit_interval, ps_enable_interval, beacon_count]  │
        └─────────────────────────────────────────────────────────┘

        Purpose:
         - Validates DUT can receive data after sending ps-poll
         - Tracks failed scenarios when DUT doesn't send ps-poll with more_data bit set
         - Monitors enhanced max PSP timing behavior

        Args:
            frame_list: List of captured frames from sniffer
            frame_number: Current frame index to start processing
            listen_interval_time: Expected listen interval in milliseconds
            current_beacon_time: Timestamp of current beacon
            beacon_count: Count of beacons processed
            listen_interval: Listen interval value

        Returns:
            tuple: (frame_number, failed_case_count, beacon_time,
                   ps_exit_interval, ps_enable_interval, beacon_count)
        """
        # Step 1: Initialize frame processing variables and frame type constants
        first_beacon_time = current_beacon_time
        beacon = int('0x0008', 16)  # Beacon frame type
        ps_poll = int('0x001a', 16)  # PS-Poll frame type
        qos_data = int('0x0028', 16)  # QoS Data frame type
        qos_null = int('0x002c', 16)  # QoS Null frame type
        action_frame = int('0x000d', 16)  # Action frame type
        block_req = int('0x0018', 16)  # Block ACK request frame type
        null_function = int('0x0024', 16)  # Null function frame type

        # Step 2: Initialize tracking variables for Enhanced Max PSP analysis
        no_of_filtered_packets = len(frame_list)
        ps_exit_interval = 0  # Time to exit power save mode
        ps_enable_interval = 0  # Time to re-enable power save mode
        ps_exit_interval_ignore = 0  # Ignored exit intervals
        ps_enable_interval_ignore = 0  # Ignored enable intervals
        beacon_count = 0  # Count of beacons processed
        max_beacon = int(listen_interval_time / 100)  # Max beacons in listen interval
        bmiss_listen_interval = listen_interval_time  # Handle beacon miss scenarios
        tim_diff_bw_beacon = 0  # Time difference between beacons
        case2 = 0  # Count of more_data bit related failures

        # Step 3: Main frame processing loop - analyze each captured frame
        while 1:
            if frame_number < no_of_filtered_packets - 2:  # removing last 2 frames from the capture
                frame_number = frame_number + 1
            else:
                break
            moredata_pspoll_failed = 0

            if frame_list[frame_number][2] == str(null_function) and frame_list[frame_number][4] == '0':
                logger().info(
                    "found Null frame with PM '0' and DUT is entering into active state during ENH MAX PSP mode")
                logger().info(frame_list[frame_number])
                nullframe_time = frame_list[frame_number][1]
                if frame_list[frame_number - 1][2] == str(ps_poll):
                    logger().info(frame_list[frame_number - 1])
                    current_pspoll_time = frame_list[frame_number - 1][1]
                    ps_exit_interval = (float(nullframe_time) - float(current_pspoll_time)) * 1000
                    logger().info(f'time_diff_bw_pspoll_nullframe={ps_exit_interval}')
                else:
                    if frame_list[frame_number - 1][2] == str(beacon) or (
                            frame_list[frame_number - 1][2] == str(qos_data)):
                        logger().info(frame_list[frame_number - 1])
                        current_pspoll_time = frame_list[frame_number - 1][1]
                        ps_exit_interval_ignore = (float(nullframe_time) - float(current_pspoll_time)) * 1000
                        logger().info(f'time_diff_bw_pspoll_nullframe(ignore)={ps_exit_interval_ignore}')
                while 1:
                    if frame_number < no_of_filtered_packets - 2:
                        frame_number = frame_number + 1
                    else:
                        break
                    if (frame_list[frame_number][2] == str(qos_data) or frame_list[frame_number][2] == str(
                            beacon) or
                            frame_list[frame_number][2] == str(qos_null)):
                        continue
                    else:
                        if frame_list[frame_number][2] == str(null_function) and frame_list[frame_number][4] == '1':
                            logger().info(frame_list[frame_number])
                            nullframe_time = frame_list[frame_number][1]
                            if frame_list[frame_number - 1][2] == str(qos_data) or frame_list[frame_number - 1][
                                2] == str(beacon) or \
                                    frame_list[frame_number - 1][2] == str(null_function):
                                if frame_list[frame_number - 1][2] == str(beacon):
                                    logger().info(frame_list[frame_number - 2])
                                    qos_time = frame_list[frame_number - 2][1]
                                    ps_enable_interval_ignore = (float(nullframe_time) - float(
                                        qos_time)) * 1000
                                    logger().info(
                                        f'time_diff_bw_last_qos_nullframe(ignore)={ps_enable_interval_ignore}')
                                else:
                                    logger().info(frame_list[frame_number - 1])
                                    qos_time = frame_list[frame_number - 1][1]
                                    ps_enable_interval = (float(nullframe_time) - float(
                                        qos_time)) * 1000
                                    logger().info(f'time_diff_bw_last_qos_nullframe={ps_enable_interval}')
                                first_beacon_time = float(frame_list[frame_number][1])
                                return frame_number, case2, first_beacon_time, ps_exit_interval, ps_enable_interval, beacon_count

            if ((frame_list[frame_number][2] == str(qos_data)) or (frame_list[frame_number][2] == str(qos_null)) or (
                    frame_list[frame_number][2] == str(action_frame)) or (
                    frame_list[frame_number][2] == str(block_req))):
                if (frame_list[frame_number][5]) == '1':
                    # logger().info(frame_list[frame_number])
                    # logger().info(
                    #     'Qos data/QOS Null frame/Action frame/block-ack req with more data bit is set to 1')
                    while 1:
                        if frame_number < no_of_filtered_packets - 2:
                            frame_number = frame_number + 1
                        else:
                            break
                        if frame_list[frame_number][2] == str(beacon):
                            beacon_count = beacon_count + 1
                            current_beacon_time = float(frame_list[frame_number][1])
                            tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                            logger().info(frame_list[frame_number])
                            if listen_interval_time == 0:
                                if frame_list[frame_number][6] == '0' and frame_list[frame_number + 1][2] == str(
                                        ps_poll) and len(frame_list[frame_number]) == 8:
                                    # logger().info(frame_list[frame_number])
                                    t1 = float(frame_list[frame_number][2])
                                    t0 = float(frame_list[frame_number - 1][2])
                                    time_diff = int(round((t1 - t0) * 1000))
                                    if time_diff > 100:
                                        logger().info(
                                            "DUT is sending PS-POLL at next DTIM/DTIMSKIP beacon only even though moredata bit set")
                                        case2 = case2 + 1
                                    break
                            else:
                                if tim_diff_bw_beacon > listen_interval_time or beacon_count == max_beacon:
                                    beacon_count = int(tim_diff_bw_beacon / 100)
                                    logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                                    logger().info(f'beacon_count={beacon_count}')
                                    first_beacon_time = current_beacon_time
                                    logger().info(
                                        f'listen_interval_time={listen_interval_time}, max_beacon = {max_beacon}')
                                    if (beacon_count > max_beacon):
                                        listen_interval_time = bmiss_listen_interval - (beacon_count - max_beacon) * 100
                                        logger().info(f'listen_interval_time_lastbmiss={listen_interval_time}')

                                    else:
                                        listen_interval_time = bmiss_listen_interval
                                        logger().info(f'listen_interval_time={listen_interval_time}')
                                if tim_diff_bw_beacon >= (listen_interval_time - 30) and frame_list[frame_number + 1][
                                    2] == str(
                                    ps_poll):
                                    t1 = float(frame_list[frame_number][2])
                                    t0 = float(frame_list[frame_number - 1][2])
                                    time_diff = int(round((t1 - t0) * 1000))
                                    if time_diff > 100:
                                        logger().info(
                                            f'DUT is sending PS-POLL at next LI beacon only even though more data bit set-time_diff={tim_diff_bw_beacon}')
                                        case2 = case2 + 1
                                        first_beacon_time = float(frame_list[frame_number][1])
                                        break
                            continue
                        elif frame_list[frame_number][2] == str(ps_poll):
                            # logger().info(frame_list[frame_number])
                            break
                        else:
                            frame_number = frame_number - 1
                            # logger().info("PS-POLL didn't observe after data packet with more data bit set")
                            break
                    continue
                else:
                    logger().info(frame_list[frame_number])
                    if tim_diff_bw_beacon != 0:
                        if tim_diff_bw_beacon > listen_interval_time:
                            beacon_count = int(tim_diff_bw_beacon / 100) - max_beacon
                        else:
                            beacon_count = int(tim_diff_bw_beacon / 100)
                    logger().info(
                        f'Qos data/QOS Null frame/Action frame/block-ack req with more data bit is set to 0 - beacon_count:{beacon_count}')
                    break
            else:
                # logger().info(frame_list[frame_number])
                if frame_list[frame_number][2] == str(ps_poll):
                    if moredata_pspoll_failed > 1:
                        first_beacon_time = float(frame_list[frame_number][1])
                    continue
                elif frame_list[frame_number][2] == str(beacon):
                    logger().info(frame_list[frame_number])
                    beacon_count = beacon_count + 1
                    if frame_number < no_of_filtered_packets:
                        if (listen_interval_time != 0):
                            current_beacon_time = float(frame_list[frame_number][1])
                            tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                            if tim_diff_bw_beacon > listen_interval_time or beacon_count == max_beacon:
                                beacon_count = int(tim_diff_bw_beacon / 100)
                                logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                                logger().info(f'beacon_count={beacon_count}')
                                first_beacon_time = current_beacon_time
                                if (beacon_count > max_beacon):
                                    listen_interval_time = bmiss_listen_interval - (beacon_count - max_beacon) * 100
                                    logger().info(f'listen_interval_time_lastbmiss={listen_interval_time}')
                                else:
                                    listen_interval_time = bmiss_listen_interval
                                    logger().info(f'listen_interval_time={listen_interval_time}')
                        frame_number = frame_number + 1
                    else:
                        break
                    if ((frame_list[frame_number][2] == str(qos_data)) or (
                            frame_list[frame_number][2] == str(qos_null)) or (
                            frame_list[frame_number][2] == str(action_frame)) or (
                            frame_list[frame_number][2] == str(block_req)) or
                            frame_list[frame_number][
                                2] == str(ps_poll)):
                        continue
                    else:
                        frame_number = frame_number - 1
                        if not (frame_list[frame_number][2] == str(null_function) and frame_list[frame_number][
                            4] == '1'):
                            logger().info("On-air data is missing")
                        break
        return frame_number, case2, first_beacon_time, ps_exit_interval, ps_enable_interval, beacon_count

    def listen_interval_based_validation(self, listen_interval_period, assoc_id):
        """
        Listen Interval Based Power Save Validation Function

        Flowchart Description:
        ┌─────────────────────────────────────────────────────────┐
        │ A[Start Listen Interval Validation]                    │
        │ ↓                                                       │
        │ B[Initialize Variables:<br/>                           │
        │   - Read Powersave_capture.txt<br/>                    │
        │   - Parse frames into frame_list<br/>                  │
        │   - Calculate max_beacon = listen_interval/100<br/>    │
        │   - Initialize tracking lists and counters]           │
        │ ↓                                                       │
        │ C[Trim last 10 frames from capture]                   │
        │ ↓                                                       │
        │ D[Find first NULL frame with PM='1'<br/>              │
        │   Set as starting point]                              │
        │ ↓                                                       │
        │ E[Set first_beacon_time as reference]                 │
        │ ↓                                                       │
        │ F[Main Processing Loop: while frame_number < total]    │
        │ ↓                                                       │
        │ G{Is frame a Beacon?}                                  │
        │ ↓ Yes                                                   │
        │ H[Extract TIM info & increment beacon_count]           │
        │ ↓                                                       │
        │ I[Calculate tim_diff_bw_beacon = current_time -        │
        │   first_beacon_time]                                  │
        │ ↓                                                       │
        │ J{Is TIM set for DUT assoc_id?}                       │
        │ ↓ Yes                                                   │
        │ K{Is tim_diff within listen_interval ± 30ms?}         │
        │ ↓ Yes (Expected PS-Poll Time)                          │
        │ L[Search for PS-Poll after beacon]                    │
        │ ↓                                                       │
        │ M{PS-Poll found?}                                      │
        │ ↓ Yes                                                   │
        │ N[Record wake interval<br/>                            │
        │   Call validate_pspoll_data_packet_with_more_bit_enable] │
        │ ↓ No                                                    │
        │ O[Record missed PS-Poll scenario]                     │
        │ ↓                                                       │
        │ P{Is tim_diff outside expected range?}                 │
        │ ↓ Yes (Early/Late Wake)                                │
        │ Q[Check for PS-Poll at unexpected time]               │
        │ ↓                                                       │
        │ R{PS-Poll found at unexpected time?}                  │
        │ ↓ Yes                                                   │
        │ S[Record early/late wake scenario]                    │
        │ ↓                                                       │
        │ T{Is TIM NOT set for DUT?}                            │
        │ ↓ Yes (Negative Scenario)                              │
        │ U[Check if PS-Poll sent when TIM not set]             │
        │ ↓                                                       │
        │ V{PS-Poll found when TIM not set?}                    │
        │ ↓ Yes                                                   │
        │ W[Increment case1 & record violation]                 │
        │ ↓                                                       │
        │ X[Update timing references for next iteration]        │
        │ ↓                                                       │
        │ Y{More frames to process?}                             │
        │ ↓ No                                                    │
        │ Z[Return: dut_wake_interval_list, case1, case2,       │
        │   ps_exit_interval_list, ps_enable_interval_list]     │
        └─────────────────────────────────────────────────────────┘

        Purpose:
         - Validates listen interval based power-save functionality
         - Ensures DUT wakes up at correct listen interval timing
         - Tracks timing accuracy and protocol violations

        Key Validations:
         - DUT should wake at listen_interval ± tolerance
         - DUT should only send PS-Poll when TIM is set
         - Timing accuracy within expected beacon intervals
         - Proper handling of beacon miss scenarios

        Args:
            listen_interval_period: Expected listen interval in milliseconds
            assoc_id: Association ID of the DUT in hex format

        Returns:
            tuple: (wake_interval_list, case1_violations, case2_violations,
                   ps_exit_interval_list, ps_enable_interval_list)
        """
        # Step 1: Initialize core timing and tracking variables
        beacon_count = 0
        bmiss_listen_interval = listen_interval_period  # Handle beacon miss scenarios
        max_beacon = int(listen_interval_period) / 100  # Max beacons in one listen interval

        # Step 2: Initialize data structures for frame processing and result tracking
        frame_list = []  # Will store parsed capture frames
        dut_wake_interval = []  # Track actual DUT wake intervals
        ps_exit_interval_list = []  # Track power save exit timings
        ps_enable_interval_list = []  # Track power save enable timings
        count = 0  # Frame counter for initial positioning

        # Step 3: Setup association and frame type identifiers
        assoc_id = int(assoc_id, 16)  # Convert association ID to integer
        tim_aid = 0  # TIM association ID extracted from beacons
        beacon = int('0x0008', 16)  # Beacon frame type constant
        null_frame = int('0x0024', 16)  # Null frame type constant
        ps_poll = int('0x001a', 16)  # PS-Poll frame type constant

        # Step 4: Initialize validation case counters for different violation scenarios
        case1 = 0  # VIOLATION: DUT sends PS-POLL when TIM is NOT set for its AID
        case2 = 0  # VIOLATION: DUT waits for next LI beacon despite more_data bit set

        # Step 5: Read and parse the captured wireless frames from sniffer
        filter_file = open(f'./reports/Powersave_capture.txt', 'r')
        lines = filter_file.readlines()
        for line in lines:
            frame_list.append(line.strip().split('\t'))  # Parse tab-separated frame data
        filter_file.close()

        # newly added code

        logger().info(f"frame_list  -------- {frame_list}")

        # Step 6: Prepare frame processing window (remove last 10 frames for stability)
        no_of_filtered_packets = len(frame_list)
        no_of_filtered_packets = no_of_filtered_packets - 10

        # Step 7: Find starting point - locate first NULL frame with PM='1' (power save mode enabled)
        for frame_number in range(no_of_filtered_packets):
            if (frame_list[frame_number][2] == str(null_frame)) and (frame_list[frame_number][4] == '1'):
                logger().info("found Null frame with PM '1'")
                logger().info(frame_list[frame_number])
                frame_number = count + 1
                break
            else:
                count = count + 1

        first_beacon_time = float(frame_list[frame_number][1])
        while frame_number < no_of_filtered_packets:
            if frame_list[frame_number][2] == str(beacon):
                logger().info(f'beacon_count={beacon_count}')
                beacon_count = beacon_count + 1
                if beacon_count == 1:
                    logger().info(frame_list[frame_number])
                '''To get the DUT assoc id from beacon frame'''
                if len(frame_list[frame_number]) == 8:
                    if len(frame_list[frame_number][7]) == 10:
                        tim_aid = int(frame_list[frame_number][7], 16)
                    else:
                        tim_aid = frame_list[frame_number][7].split(',')
                        for j in range(len(tim_aid)):
                            if int(tim_aid[j], 16) == assoc_id:
                                tim_aid = int(tim_aid[j], 16)
                current_beacon_time = float(frame_list[frame_number][1])
                tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                '''Comparison of DUT assoc id from beacon and assoc response'''
                if tim_aid == assoc_id:
                    current_beacon_time = float(frame_list[frame_number][1])
                    tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                    # logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                    '''Validation of PS-POLL at listen interval beacon with TIM set'''
                    if ((tim_diff_bw_beacon >= (listen_interval_period - 30)) and (
                            tim_diff_bw_beacon <= listen_interval_period + 30)) and len(
                        frame_list[frame_number]) == 8:
                        while 1:
                            if frame_number < no_of_filtered_packets:
                                frame_number = frame_number + 1
                                listen_interval_time = bmiss_listen_interval
                            else:
                                break
                            if frame_list[frame_number][2] == str(ps_poll):
                                current_beacon_time = float(frame_list[frame_number][1])
                                tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                                dut_wake_interval.append(tim_diff_bw_beacon)
                                logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                                packet_number, failed_case, beacon_time, ps_exit_interval, ps_enable_interval, beacon_count = self.validate_pspoll_data_packet_with_more_bit_enable(
                                    frame_list, frame_number,
                                    listen_interval_period,
                                    current_beacon_time)
                                ps_enable_interval_list.append(ps_enable_interval)
                                ps_exit_interval_list.append(ps_exit_interval)
                                case2 = case2 + failed_case
                                if beacon_time == current_beacon_time:
                                    first_beacon_time = current_beacon_time
                                else:
                                    first_beacon_time = beacon_time
                                    listen_interval_time = bmiss_listen_interval - beacon_count * 100
                                    logger().info(
                                        f'listen_interval_time_validate_pspoll_data_packet_with_more_bit_enable={listen_interval_time}')
                                    tim_diff_bw_beacon = 0
                                frame_number = packet_number
                                break
                            else:
                                if frame_list[frame_number][2] == str(beacon):
                                    current_beacon_time = float(frame_list[frame_number][1])
                                    tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                                    dut_wake_interval.append(tim_diff_bw_beacon)
                                    logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                                    logger().info(
                                        "DUT wake at more than the LI beacon-tb")
                                    continue
                                else:
                                    frame_number = frame_number - 1
                                    tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                                    dut_wake_interval.append(tim_diff_bw_beacon)
                                    logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                                    logger().info(
                                        "On-air ps-poll miss at LI beacon-time difference")
                                    packet_number, failed_case, beacon_time, ps_exit_interval, ps_enable_interval, beacon_count = self.validate_pspoll_data_packet_with_more_bit_enable(
                                        frame_list, frame_number,
                                        listen_interval_period,
                                        current_beacon_time)
                                    ps_enable_interval_list.append(ps_enable_interval)
                                    ps_exit_interval_list.append(ps_exit_interval)
                                    case2 = case2 + failed_case
                                    if beacon_time == current_beacon_time:
                                        first_beacon_time = current_beacon_time
                                    else:
                                        first_beacon_time = beacon_time
                                        listen_interval_time = bmiss_listen_interval - beacon_count * 100
                                        logger().info(
                                            f'listen_interval_time_validate_pspoll_data_packet_with_more_bit_enable={listen_interval_time}')
                                        tim_diff_bw_beacon = 0
                                    frame_number = packet_number
                                    break
                        beacon_count = 0
                        tim_aid = 0
                    else:
                        if frame_number < no_of_filtered_packets:
                            frame_number = frame_number + 1
                            if frame_list[frame_number][2] == str(ps_poll):
                                beacon_count = 0
                                tim_aid = 0
                                current_beacon_time = float(frame_list[frame_number][1])
                                tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                                dut_wake_interval.append(tim_diff_bw_beacon)
                                logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                                # logger().info("DUT is sending PS-POLL at before/after LI beacon-time-difference")
                                packet_number, failed_case, beacon_time, ps_exit_interval, ps_enable_interval, beacon_count = self.validate_pspoll_data_packet_with_more_bit_enable(
                                    frame_list, frame_number,
                                    listen_interval_period,
                                    current_beacon_time)
                                ps_enable_interval_list.append(ps_enable_interval)
                                ps_exit_interval_list.append(ps_exit_interval)
                                case2 = case2 + failed_case
                                if beacon_time == current_beacon_time:
                                    first_beacon_time = current_beacon_time
                                else:
                                    first_beacon_time = beacon_time
                                    listen_interval_time = bmiss_listen_interval - beacon_count * 100
                                    logger().info(
                                        f'listen_interval_time_validate_pspoll_data_packet_with_more_bit_enable={listen_interval_time}')
                                    tim_diff_bw_beacon = 0
                                frame_number = packet_number
                            else:
                                if frame_list[frame_number][2] != str(beacon):
                                    beacon_count = 0
                                    tim_aid = 0
                                    dut_wake_interval.append(tim_diff_bw_beacon)
                                    logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                                    logger().info(
                                        "DUT is waking at before LI beacon-time-difference & on-air ps-poll miss ")
                                    packet_number, failed_case, beacon_time, ps_exit_interval, ps_enable_interval, beacon_count = self.validate_pspoll_data_packet_with_more_bit_enable(
                                        frame_list, frame_number,
                                        listen_interval_period,
                                        current_beacon_time)
                                    ps_enable_interval_list.append(ps_enable_interval)
                                    ps_exit_interval_list.append(ps_exit_interval)
                                    case2 = case2 + failed_case
                                    if beacon_time == current_beacon_time:
                                        first_beacon_time = current_beacon_time
                                    else:
                                        first_beacon_time = beacon_time
                                        listen_interval_time = bmiss_listen_interval - beacon_count * 100
                                        logger().info(
                                            f'listen_interval_time_validate_pspoll_data_packet_with_more_bit_enable={listen_interval_time}')
                                        tim_diff_bw_beacon = 0
                                    frame_number = packet_number
                                else:
                                    frame_number = frame_number - 1
                else:
                    '''Validation of -ve scenario where DUT is sending ps-poll even though TIM is not set'''
                    if frame_number < no_of_filtered_packets:
                        frame_number = frame_number + 1
                    else:
                        break
                    if frame_list[frame_number][2] == str(ps_poll):
                        beacon_count = 0
                        current_beacon_time = float(frame_list[frame_number][1])
                        tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                        dut_wake_interval.append(tim_diff_bw_beacon)
                        logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                        logger().info("DUT is sending PS-POLL even though tim is not set")
                        case1 = case1 + 1
                        packet_number, failed_case, beacon_time, ps_exit_interval, ps_enable_interval, beacon_count = self.validate_pspoll_data_packet_with_more_bit_enable(
                            frame_list, frame_number,
                            listen_interval_period,
                            current_beacon_time)
                        ps_enable_interval_list.append(ps_enable_interval)
                        ps_exit_interval_list.append(ps_exit_interval)
                        case2 = case2 + failed_case
                        if beacon_time == current_beacon_time:
                            first_beacon_time = current_beacon_time
                        else:
                            first_beacon_time = beacon_time
                            listen_interval_time = bmiss_listen_interval - beacon_count * 100
                            logger().info(
                                f'listen_interval_time_validate_pspoll_data_packet_with_more_bit_enable={listen_interval_time}')
                            tim_diff_bw_beacon = 0
                        frame_number = packet_number
                    else:
                        frame_number = frame_number - 1
            else:
                if (frame_list[frame_number][2] == str(null_frame)) and (
                        (frame_list[frame_number][4] == '1') and (frame_list[frame_number][3] == '1')):
                    logger().info("found Retried Null frame with PM '1'")
                    first_beacon_time = float(frame_list[frame_number][1])
                frame_number = frame_number + 1
                continue
            if frame_number < no_of_filtered_packets:
                '''We are setting to zero for 1st beacon time and beacon count incase of TIM not set at Listen interval time'''
                current_beacon_time = float(frame_list[frame_number][1])
                tim_diff_bw_beacon = int((current_beacon_time - first_beacon_time) * 1000)
                logger().info(f'tim_diff_bw_beacon={tim_diff_bw_beacon}')
                if tim_diff_bw_beacon >= listen_interval_period:
                    beacon_count = int(tim_diff_bw_beacon / 100)
                    if (beacon_count > max_beacon):
                        listen_interval_time = bmiss_listen_interval - (beacon_count - max_beacon) * 100
                        logger().info(f'listen_interval_time_lastbmiss={listen_interval_time}')

                    else:
                        listen_interval_time = bmiss_listen_interval
                        logger().info(f'listen_interval_time={listen_interval_time}')
                    first_beacon_time = current_beacon_time
                    beacon_count = 0
                frame_number = frame_number + 1
        return dut_wake_interval, case1, case2, ps_exit_interval_list, ps_enable_interval_list


class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, net_perf_client=None, wifi_client=None,
                 protocol=None, capture_filename=None, zephyr_wifi_collections=None, power_save=None, test_case=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.capture_filename = capture_filename
        self.zephyr_wifi_collections = zephyr_wifi_collections
        self.dut_addr = None
        self.ps_config = None
        self.power_save = power_save
        self.test_case = test_case
        self._sniffer_started = False

    def _configure_and_join_with_power_save(self):
        """Join AP and enable power save based on test_case configuration."""
        configured_listen_interval = None
        if self.test_case in (
                '1742320', '1742322', '1742326', '1742331', '1742334', '1742335') + FAST_PSP_LISTEN_INTERVAL_TEST_CASES:
            if self.test_case == '1742320':
                configured_listen_interval = 0
            elif self.test_case == '1742331':
                configured_listen_interval = 5
            elif self.test_case == '1742335':
                configured_listen_interval = 8
            elif self.test_case in FAST_PSP_LISTEN_INTERVAL_TEST_CASES:
                configured_listen_interval = FAST_PSP_LISTEN_INTERVAL
            else:
                configured_listen_interval = 16
            self.wifi_dut.interfaces.wifi.wifi_ps(
                param_type=WiFiPsParamType.ListenInterval,
                listen_interval=configured_listen_interval)
        self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(
            self.wifi_dut,
            self.wifi_access_point,
            associated=self.wifi_dut.interfaces.wifi.associated,
            retry_count=3,
            power_save=False,
            ping_after_power_save=False,
        )
        expected_wakeup_mode = None
        expected_listen_interval = None
        if self.test_case in ('1742318', '1742319', '1742321'):
            expected_wakeup_mode = WiFiPsWakeupMode.DTIM
            self.wifi_dut.interfaces.wifi.wifi_ps(
                param_type=WiFiPsParamType.WakeupMode,
                wakeup_mode=expected_wakeup_mode,
            )
        elif self.test_case in ('1742320', '1742322', '1742326', '1742331', '1742334', '1742335'):
            expected_wakeup_mode = WiFiPsWakeupMode.ListenInterval
            self.wifi_dut.interfaces.wifi.wifi_ps(
                param_type=WiFiPsParamType.WakeupMode,
                wakeup_mode=expected_wakeup_mode,
            )
            expected_listen_interval = configured_listen_interval
        elif self.test_case == '1742329':
            enable_fast_psp_listen_interval_power_save(self.wifi_dut)
        elif self.test_case == '1742330':
            enable_fast_psp_listen_interval_power_save(
                self.wifi_dut, configure_monitor_interval=False)
        elif self.test_case in FAST_PSP_TEST_CASES:
            enable_fast_psp_dtim_power_save(self.wifi_dut)
        if self.test_case not in FAST_PSP_SELF_ENABLE_TEST_CASES:
            self.wifi_dut.interfaces.wifi.wifi_ps(
                param_type=WiFiPsParamType.State, enabled=WiFiPs.Enabled)
        self.ps_config = self.wifi_dut.interfaces.wifi.wifi_ps_config()
        logger().info(f"WiFi PS config after join: {self.ps_config}")
        if self.test_case == '1742329':
            validate_fast_psp_listen_interval_power_save_config(self.ps_config)
        elif self.test_case == '1742330':
            validate_fast_psp_listen_interval_power_save_config(
                self.ps_config, expect_monitor_interval_disabled=True)
        elif self.test_case in FAST_PSP_TEST_CASES:
            validate_fast_psp_power_save_config(self.ps_config)
        elif expected_wakeup_mode is not None:
            validate_power_save_wakeup_mode(self.ps_config, expected_wakeup_mode)
        if expected_listen_interval is not None:
            validate_power_save_listen_interval(self.ps_config, expected_listen_interval)
        logger().info("Pinging DUT after connect with power save enabled")
        if self.test_case == '1742318':
            status = self.zephyr_wifi_collections.ping_with_custom_size(
                self.dut_addr["device_ip"], ping_counts=10, byte_size=100, interval=0.3)
        else:
            status = self.zephyr_wifi_collections.ping_with_custom_size(
                self.dut_addr["device_ip"], ping_counts=10, byte_size=100)
        assert status, "DUT not responding to ping after connect with power save enabled"
        return self.dut_addr

    def start_sniffer_capture(self):
        """Start sniffer capture if not already started."""
        if self._sniffer_started:
            return
        logger().info(f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
        self._sniffer_started = True

    def connect_with_power_save(self):
        """Join to AP with power save enabled (uses WifiJoin join flow)."""
        self._configure_and_join_with_power_save()

    def disconnect_from_ap(self):
        """Disconnect DUT from AP."""
        logger().info("Disconnecting DUT from AP")
        self.wifi_dut.interfaces.wifi.leave()

    def run(self):
        try:
            self.start_sniffer_capture()
            self._configure_and_join_with_power_save()
        except Exception as e:
            logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
            raise

    def udp_rx_data_transfer(self, host_ip, bandwidth="1M"):
        """Run UDP RX iperf traffic with DUT configured as server."""
        logger().info("Calling IPERF RX UDP traffic with DUT configured as Server")
        self.net_perf_client.interfaces.net_perf.init_client(
            host_ip=host_ip,
            device_ip=self.dut_addr['device_ip'],
            protocol=self.protocol,
            bandwidth=bandwidth,
        )
        logger().info(
            f"Host IP: {host_ip}, Dut IP: {self.dut_addr['device_ip']}, Protocol: {self.protocol}"
        )
        logger().info("Starting iperf client")
        self.net_perf_client.interfaces.net_perf.start()
        logger().info("Starting DUT iperf server (UDP RX)")
        self.wifi_dut.interfaces.wifi.iperf(
            family=2,
            transfer_type=2,
            protocol=17,
            local_port=self.net_perf_client.interfaces.net_perf.client_port,
            local_ip=self.dut_addr['device_ip'],
            remote_ip=host_ip,
            remote_port=self.net_perf_client.interfaces.net_perf.client_port,
            size=1470,
            ttl=30,
            throughput_type=4,
            qos=0,
        )
        logger().info("UDP RX data transfer completed successfully")
        time.sleep(5)

    def udp_tx_data_transfer(self, host_ip):
        """Run UDP TX iperf traffic with DUT configured as client."""
        logger().info("Calling IPERF TX UDP traffic with DUT configured as Client")
        self.net_perf_client.interfaces.net_perf.init_server(
            host_ip=host_ip,
            device_ip=self.dut_addr['device_ip'],
            protocol=self.protocol,
        )
        logger().info(
            f"Host IP: {host_ip}, Dut IP: {self.dut_addr['device_ip']}, Protocol: {self.protocol}"
        )
        logger().info("Starting iperf server on host")
        self.net_perf_client.interfaces.net_perf.start()
        logger().info("Starting DUT iperf client (UDP TX)")
        self.wifi_dut.interfaces.wifi.iperf(
            family=2,
            transfer_type=2,
            protocol=17,
            local_port=self.net_perf_client.interfaces.net_perf.server_port,
            local_ip=self.dut_addr['device_ip'],
            remote_ip=host_ip,
            remote_port=self.net_perf_client.interfaces.net_perf.server_port,
            size=1460,
            ttl=30,
            throughput_type=2,
            qos=0,
        )
        tp = self.net_perf_client.interfaces.net_perf.process_output()
        assert tp, "Failed to get UDP TX throughput"
        # __print_throughput(tp)
        logger().info("UDP TX data transfer completed successfully")
        time.sleep(5)

    def tcp_rx_data_transfer(self, host_ip, bandwidth="1M"):
        """Run TCP RX iperf traffic with DUT configured as server."""
        logger().info("Calling IPERF RX TCP traffic with DUT configured as Server")
        self.net_perf_client.interfaces.net_perf.init_client(
            host_ip=host_ip,
            device_ip=self.dut_addr['device_ip'],
            protocol=self.protocol,
            bandwidth=bandwidth,
        )
        logger().info(
            f"Host IP: {host_ip}, Dut IP: {self.dut_addr['device_ip']}, Protocol: {self.protocol}"
        )

        def start_client():
            time.sleep(3)
            logger().info("Starting iperf client")
            self.net_perf_client.interfaces.net_perf.start()

        client_thread = Thread(target=start_client, args=())
        client_thread.start()
        logger().info("Starting DUT iperf server (TCP RX)")
        self.wifi_dut.interfaces.wifi.iperf(
            family=2,
            transfer_type=1,
            protocol=6,
            local_port=self.net_perf_client.interfaces.net_perf.client_port,
            local_ip=self.dut_addr['device_ip'],
            remote_ip=host_ip,
            remote_port=self.net_perf_client.interfaces.net_perf.client_port,
            size=1460,
            throughput_type=3,
            qos=0,
        )
        client_thread.join()
        logger().info("TCP RX data transfer completed successfully")
        time.sleep(5)

    def multicast_rx_data_transfer(self, host_ip, multicast_client, timeout=60, bandwidth="1M"):
        """Run UDP multicast RX iperf traffic with DUT configured as server."""
        (
            ip_version,
            ttl,
            multicast_mac,
            multicast_ip,
            device_port,
            server_port,
            buffer_length,
            no_of_pkts,
        ) = multicast_client.interfaces.multicast.multicast_params()
        logger().info(
            f"MultiCast Client Info: {ip_version}, {ttl}, {multicast_mac}, {multicast_ip}, "
            f"{device_port}, {server_port}, {buffer_length}, {no_of_pkts}"
        )

        logger().info(f"DUT joining multicast group {multicast_ip}")
        self.wifi_dut.interfaces.wifi.igmp_join(multicast_ip)

        logger().info("Calling IPERF RX UDP multicast traffic with DUT configured as Server")
        self.net_perf_client.interfaces.net_perf.init_client(
            host_ip=host_ip,
            device_ip=multicast_ip,
            time_out=timeout,
            protocol=self.protocol,
            time_to_leave="32",
            bandwidth=bandwidth,
            host_role="C",
            bind_address=host_ip,
        )
        logger().info(
            f"Host IP: {host_ip}, Dut IP: {self.dut_addr['device_ip']}, "
            f"Multicast IP: {multicast_ip}, Protocol: {self.protocol}"
        )
        logger().info("Starting iperf client")
        self.net_perf_client.interfaces.net_perf.start()
        logger().info("Starting DUT iperf server (UDP multicast RX)")
        self.wifi_dut.interfaces.wifi.iperf(
            family=1,
            transfer_type=2,
            protocol=17,
            local_port=self.net_perf_client.interfaces.net_perf.client_port,
            local_ip=multicast_ip,
            remote_ip=host_ip,
            remote_port=self.net_perf_client.interfaces.net_perf.client_port,
            size=1470,
            ttl=30,
            throughput_type=4,
            qos=0,
            async_socket=0,
        )
        self.wifi_dut.interfaces.wifi.igmp_leave(multicast_ip)
        logger().info("UDP multicast RX data transfer completed successfully")
        time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
def test_wifi_zephyr_udp_data_rx_power_save_dtim_3_c1742318(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut,
                                                            wifi_client, request, zephyr_wifi_collections,
                                                            sniffer_filter):
    """Verify UDP data Rx with power save enabled and DTIM 3."""

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
        wifi_access_point.interfaces.wifi.config['dtim'] = '3'
        wifi_access_point.interfaces.wifi.start_ap()
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info("Start get IP address")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_client=wifi_client,
            protocol=IperfConstants.UDP,
            capture_filename=capture_filename,
            zephyr_wifi_collections=zephyr_wifi_collections,
            power_save=power_save,
            test_case='1742318',
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.udp_rx_data_transfer(host_ip=host_ip)

        logger().info("DUT leaving the AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        zephyr_wifi_collections.join_sniffer_validation(
            wifi_access_point,
            wifi_sniffer,
            wifi_obj.dut_addr['dut_mac_address'],
            ap_bssid,
            sniffer_filter,
            power_save=power_save,
        )

        validate_powersave_capture_and_archive(
            wifi_sniffer, ap_bssid, wifi_obj.dut_addr['dut_mac_address'], capture_filename)


    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
def test_wifi_zephyr_tcp_data_rx_power_save_dtim_3_beacon_interval_200_c1742319(wifi_sniffer, net_perf_client,
                                                                                wifi_access_point, wifi_dut,
                                                                                wifi_client, request,
                                                                                zephyr_wifi_collections,
                                                                                sniffer_filter):
    """Verify TCP data Rx with power save enabled and DTIM 3."""

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        wifi_access_point.interfaces.wifi.config['beacon_interval'] = '200'
        wifi_access_point.interfaces.wifi.config['dtim'] = '3'
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info("Start get IP address")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_client=wifi_client,
            protocol=IperfConstants.TCP,
            capture_filename=capture_filename,
            zephyr_wifi_collections=zephyr_wifi_collections,
            power_save=power_save,
            test_case='1742319',
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.tcp_rx_data_transfer(host_ip=host_ip)

        logger().info("DUT leaving the AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        zephyr_wifi_collections.join_sniffer_validation(
            wifi_access_point,
            wifi_sniffer,
            wifi_obj.dut_addr['dut_mac_address'],
            ap_mac_address,
            sniffer_filter,
            power_save=power_save,
        )

        validate_powersave_capture_and_archive(
            wifi_sniffer, ap_mac_address, wifi_obj.dut_addr['dut_mac_address'], capture_filename)

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
def test_wifi_zephyr_udp_data_rx_power_save_wake_up_mode_listen_dtim_3_c1742320(wifi_sniffer, net_perf_client,
                                                                                wifi_access_point, wifi_dut,
                                                                                wifi_client, request,
                                                                                zephyr_wifi_collections,
                                                                                sniffer_filter):
    """Verify UDP data Rx with power save enabled, wake-up mode set to listen interval, and listen interval of 0"""

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
        wifi_access_point.interfaces.wifi.config['dtim'] = '3'
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info("Start get IP address")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_client=wifi_client,
            protocol=IperfConstants.UDP,
            capture_filename=capture_filename,
            zephyr_wifi_collections=zephyr_wifi_collections,
            power_save=power_save,
            test_case='1742320',
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.udp_rx_data_transfer(host_ip=host_ip)

        logger().info("DUT leaving the AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        zephyr_wifi_collections.join_sniffer_validation(
            wifi_access_point,
            wifi_sniffer,
            wifi_obj.dut_addr['dut_mac_address'],
            ap_mac_address,
            sniffer_filter,
            power_save=power_save,
        )

        validate_powersave_capture_and_archive(
            wifi_sniffer, ap_mac_address, wifi_obj.dut_addr['dut_mac_address'], capture_filename)

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
def test_wifi_zephyr_udp_multicast_data_rx_power_save_dtim_3_c1742321(wifi_sniffer, net_perf_client, wifi_access_point,
                                                                      wifi_dut, wifi_client, request,
                                                                      zephyr_wifi_collections, sniffer_filter,
                                                                      multicast_client):
    """Verify UDP multicast data Rx with power save enabled and DTIM 3."""

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
        wifi_access_point.interfaces.wifi.config['dtim'] = '3'
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info("Start get IP address")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_client=wifi_client,
            protocol=IperfConstants.UDP,
            capture_filename=capture_filename,
            zephyr_wifi_collections=zephyr_wifi_collections,
            power_save=power_save,
            test_case='1742321',
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.multicast_rx_data_transfer(host_ip=host_ip, multicast_client=multicast_client)

        logger().info("DUT leaving the AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        zephyr_wifi_collections.join_sniffer_validation(
            wifi_access_point,
            wifi_sniffer,
            wifi_obj.dut_addr['dut_mac_address'],
            ap_mac_address,
            sniffer_filter,
            power_save=power_save,
        )

        validate_powersave_capture_and_archive(
            wifi_sniffer, ap_mac_address, wifi_obj.dut_addr['dut_mac_address'], capture_filename)

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
def test_wifi_zephyr_udp_data_rx_power_save_listen_interval_16_c1742322(wifi_sniffer, net_perf_client,
                                                                        wifi_access_point,
                                                                        wifi_dut, wifi_client, request,
                                                                        zephyr_wifi_collections, sniffer_filter):
    """Verify UDP data Rx with power save enabled, listen-interval wake-up mode, and listen interval of 16."""

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    ps_poll_time_delta_obj = FilterPacket()
    # Sniffer validation uses driver-effective LI (10 beacons = 1000 ms), not configured 16.
    listen_interval = get_effective_listen_interval_ms(C1742322_CONFIGURED_LISTEN_INTERVAL_BEACONS)
    logger().info(
        f"Listen interval for sniffer validation: configured="
        f"{C1742322_CONFIGURED_LISTEN_INTERVAL_BEACONS} beacons, "
        f"driver-effective={C1742322_EFFECTIVE_LISTEN_INTERVAL_BEACONS} beacons "
        f"({listen_interval} ms)"
    )
    try:
        wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
        wifi_access_point.interfaces.wifi.config['dtim'] = '3'
        wifi_access_point.interfaces.wifi.start_ap()
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        logger().info("Start get IP address")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_client=wifi_client,
            protocol=IperfConstants.UDP,
            capture_filename=capture_filename,
            zephyr_wifi_collections=zephyr_wifi_collections,
            power_save=power_save,
            test_case='1742322',
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.udp_rx_data_transfer(host_ip=host_ip)

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer")
        time.sleep(1)

        association_id = validate_powersave_capture_and_archive(
            wifi_sniffer, ap_bssid, wifi_obj.dut_addr['dut_mac_address'], capture_filename)

        ps_poll_packets_time_delta_list, case1, case2, _, _ = (
            ps_poll_time_delta_obj.listen_interval_based_validation(
                listen_interval, association_id)
        )
        case3 = ps_poll_time_delta_obj.validate_time_delta(
            ps_poll_packets_time_delta_list, listen_interval)

        logger().info(f"case1 ------------->  {case1}")
        logger().info(f"case2 ------------->  {case2}")
        logger().info(f"case3 ------------->  {case3}")
        logger().info(f"ps_poll_packets_time_delta_list ------------->  {ps_poll_packets_time_delta_list}")
        if case1 != 0:
            logger().info(
                f'Observed {case1} times DUT is sending PS-POLL to retrieve the data '
                f'even though TIM is not set')
        if case2 != 0:
            logger().info(
                f'Observed {case2} times DUT is sending the PS-POLL to retrieve the data '
                f'after post listen interval beacon only even though more data bit is set')
        if case3 != 0:
            logger().info(
                f'Observed {case3} times DUT is unable to send PS-POLL at listen interval')
        if case1 > 12 or case3 > 12 or case2 != 0:
            assert False
        else:
            assert True, "DUT is sending PS-POLL to retrieve the data at Listen interval beacon only"

        logger().info("DUT leaving the AP")
        wifi_dut.interfaces.wifi.leave()

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.firmware_app("test_fast_psp")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
def test_wifi_zephyr_udp_data_rx_power_save_listen_interval_8_c1742335(firmware_loader, wifi_sniffer, net_perf_client,
                                                                       wifi_access_point,
                                                                       wifi_dut, wifi_client, request,
                                                                       zephyr_wifi_collections, sniffer_filter):
    """Verify UDP data Rx with power save enabled, listen-interval wake-up mode, and listen interval of 8."""

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    listen_interval = get_effective_listen_interval_ms(C1742335_CONFIGURED_LISTEN_INTERVAL_BEACONS)
    logger().info(
        f"Listen interval for sniffer validation: configured="
        f"{C1742335_CONFIGURED_LISTEN_INTERVAL_BEACONS} beacons, "
        f"driver-effective={C1742335_EFFECTIVE_LISTEN_INTERVAL_BEACONS} beacons "
        f"({listen_interval} ms)"
    )
    try:
        wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
        wifi_access_point.interfaces.wifi.config['dtim'] = '3'
        wifi_access_point.interfaces.wifi.start_ap()
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        logger().info("Start get IP address")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_client=wifi_client,
            protocol=IperfConstants.UDP,
            capture_filename=capture_filename,
            zephyr_wifi_collections=zephyr_wifi_collections,
            power_save=power_save,
            test_case='1742335',
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.udp_rx_data_transfer(host_ip=host_ip)

        logger().info("DUT leaving the AP")
        wifi_dut.interfaces.wifi.leave()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer")
        time.sleep(1)

        validate_powersave_capture_and_archive(
            wifi_sniffer, ap_bssid, wifi_obj.dut_addr['dut_mac_address'], capture_filename)


    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_zephyr_keep_alive_power_save_listen_interval_5_c1742331(wifi_access_point, wifi_dut, wifi_client,
                                                                      request, zephyr_wifi_collections):
    """Verify WLAN keep alive functionality when LISTEN INTERVAL is set to 5."""

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    listen_interval = get_effective_listen_interval_ms(C1742331_CONFIGURED_LISTEN_INTERVAL_BEACONS)
    logger().info(
        f"Listen interval for keep alive validation: configured="
        f"{C1742331_CONFIGURED_LISTEN_INTERVAL_BEACONS} beacons, "
        f"driver-effective={C1742331_EFFECTIVE_LISTEN_INTERVAL_BEACONS} beacons "
        f"({listen_interval} ms)"
    )
    try:
        wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
        wifi_access_point.interfaces.wifi.config['dtim'] = '3'
        wifi_access_point.interfaces.wifi.start_ap()
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=None,
            net_perf_client=None,
            wifi_client=wifi_client,
            protocol=None,
            capture_filename=capture_filename,
            zephyr_wifi_collections=zephyr_wifi_collections,
            power_save=power_save,
            test_case='1742331',
        )
        wifi_obj.connect_with_power_save()

        logger().info(
            f"Waiting {C1742331_KEEP_ALIVE_IDLE_SEC}s idle to verify WLAN keep alive "
            f"with listen interval {C1742331_CONFIGURED_LISTEN_INTERVAL_BEACONS} beacons"
        )
        time.sleep(C1742331_KEEP_ALIVE_IDLE_SEC)

        logger().info("DUT leaving the AP")
        wifi_dut.interfaces.wifi.leave()

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_zephyr_neg_power_save_invalid_listen_interval_c1742323(wifi_sniffer, wifi_access_point, wifi_dut, request,
                                                                     zephyr_wifi_collections):
    """Verify setting listen interval to 17 before join fails with SL_STATUS_FAIL."""

    capture_filename = request.node.name
    try:
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        wifi_dut.interfaces.wifi.wifi_ps(
            param_type=WiFiPsParamType.ListenInterval,
            listen_interval=17,
            expected_status=SLStatus.SL_STATUS_FAIL,
        )
        logger().info("DUT rejected listen interval 17 with SL_STATUS_FAIL as expected")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_zephyr_neg_power_save_wmm_mode_c1742333(wifi_sniffer, wifi_access_point, wifi_dut, request,
                                                      zephyr_wifi_collections):
    """Verify setting WMM power save mode before join fails with SL_STATUS_FAIL."""

    capture_filename = request.node.name
    try:
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        wifi_dut.interfaces.wifi.wifi_ps(
            param_type=WiFiPsParamType.Mode,
            mode=WiFiPsMode.WMM,
            expected_status=SLStatus.SL_STATUS_FAIL,
        )
        logger().info("DUT rejected WMM power save mode with SL_STATUS_FAIL as expected")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_zephyr_power_save_switch_listen_interval_c1742326(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                wifi_client, request, zephyr_wifi_collections,
                                                                sniffer_filter):
    """Verify power save enable/disable switching for 30 minutes with listen-interval based power save."""

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
        wifi_access_point.interfaces.wifi.config['dtim'] = '3'
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=None,
            wifi_client=wifi_client,
            protocol=None,
            capture_filename=capture_filename,
            zephyr_wifi_collections=zephyr_wifi_collections,
            power_save=power_save,
            test_case='1742326',
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        run_power_save_enable_disable_switching(
            wifi_dut,
            zephyr_wifi_collections,
            wifi_obj.dut_addr['device_ip'],
        )

        logger().info("DUT leaving the AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        zephyr_wifi_collections.join_sniffer_validation(
            wifi_access_point,
            wifi_sniffer,
            wifi_obj.dut_addr['dut_mac_address'],
            ap_mac_address,
            sniffer_filter,
            power_save=power_save,
        )

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_zephyr_connect_disconnect_power_save_listen_interval_c1742334(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                            wifi_client, request,
                                                                            zephyr_wifi_collections):
    """Verify connect and disconnect for 30 minutes with listen-interval based power save enabled."""

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=None,
            wifi_client=wifi_client,
            protocol=None,
            capture_filename=capture_filename,
            zephyr_wifi_collections=zephyr_wifi_collections,
            power_save=power_save,
            test_case='1742334',
        )
        wifi_obj.start_sniffer_capture()
        run_connect_disconnect_with_listen_interval_ps(wifi_obj)

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.firmware_app("test_fast_psp")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
def test_wifi_zephyr_udp_tx_fast_psp_dtim_monitor_interval_50ms_c1742327(firmware_loader, wifi_sniffer, net_perf_client,
                                                                         wifi_access_point, wifi_dut,
                                                                         wifi_client, request,
                                                                         zephyr_wifi_collections, sniffer_filter):
    """Verify UDP TX with FAST PSP, DTIM power save, and 50 ms monitor interval."""

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
        wifi_access_point.interfaces.wifi.config['dtim'] = '3'
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info("Start get IP address")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_client=wifi_client,
            protocol=IperfConstants.UDP,
            capture_filename=capture_filename,
            zephyr_wifi_collections=zephyr_wifi_collections,
            power_save=power_save,
            test_case='1742327',
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.udp_tx_data_transfer(host_ip=host_ip)

        logger().info("DUT leaving the AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        zephyr_wifi_collections.join_sniffer_validation(
            wifi_access_point,
            wifi_sniffer,
            wifi_obj.dut_addr['dut_mac_address'],
            ap_mac_address,
            sniffer_filter,
            power_save=power_save,
        )

        validate_powersave_capture_and_archive(
            wifi_sniffer, ap_mac_address, wifi_obj.dut_addr['dut_mac_address'], capture_filename)

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.firmware_app("test_fast_psp")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
def test_wifi_zephyr_udp_rx_fast_psp_dtim_monitor_interval_50ms_c1742328(firmware_loader, wifi_sniffer, net_perf_client,
                                                                         wifi_access_point, wifi_dut,
                                                                         wifi_client, request,
                                                                         zephyr_wifi_collections, sniffer_filter):
    """Verify UDP RX with FAST PSP, DTIM power save, and 50 ms monitor interval."""

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        wifi_access_point.interfaces.wifi.config['beacon_interval'] = '100'
        wifi_access_point.interfaces.wifi.config['dtim'] = '3'
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info("Start get IP address")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_client=wifi_client,
            protocol=IperfConstants.UDP,
            capture_filename=capture_filename,
            zephyr_wifi_collections=zephyr_wifi_collections,
            power_save=power_save,
            test_case='1742328',
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.udp_rx_data_transfer(host_ip=host_ip)

        logger().info("DUT leaving the AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        zephyr_wifi_collections.join_sniffer_validation(
            wifi_access_point,
            wifi_sniffer,
            wifi_obj.dut_addr['dut_mac_address'],
            ap_mac_address,
            sniffer_filter,
            power_save=power_save,
        )

        validate_powersave_capture_and_archive(
            wifi_sniffer, ap_mac_address, wifi_obj.dut_addr['dut_mac_address'], capture_filename)

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.firmware_app("test_fast_psp")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
def test_wifi_zephyr_udp_rx_fast_psp_listen_interval_800_monitor_interval_70ms_c1742329(
        firmware_loader, wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client, request,
        zephyr_wifi_collections, sniffer_filter):
    """Verify UDP RX with FAST PSP, listen interval 800, and 70 ms monitor interval."""

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info("Start get IP address")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_client=wifi_client,
            protocol=IperfConstants.UDP,
            capture_filename=capture_filename,
            zephyr_wifi_collections=zephyr_wifi_collections,
            power_save=power_save,
            test_case='1742329',
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.udp_rx_data_transfer(host_ip=host_ip)

        logger().info("DUT leaving the AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        zephyr_wifi_collections.join_sniffer_validation(
            wifi_access_point,
            wifi_sniffer,
            wifi_obj.dut_addr['dut_mac_address'],
            ap_mac_address,
            sniffer_filter,
            power_save=power_save,
        )

        validate_powersave_capture_and_archive(
            wifi_sniffer, ap_mac_address, wifi_obj.dut_addr['dut_mac_address'], capture_filename)

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.firmware_app("test_fast_psp")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
def test_wifi_zephyr_udp_rx_fast_psp_listen_interval_monitor_interval_0_c1742330(
        firmware_loader, wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut, wifi_client, request,
        zephyr_wifi_collections, sniffer_filter):
    """Verify UDP RX with FAST PSP, listen interval PS, and monitor interval disabled (0)."""

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info("Start get IP address")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            net_perf_client=net_perf_client,
            wifi_client=wifi_client,
            protocol=IperfConstants.UDP,
            capture_filename=capture_filename,
            zephyr_wifi_collections=zephyr_wifi_collections,
            power_save=power_save,
            test_case='1742330',
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.udp_rx_data_transfer(host_ip=host_ip)

        logger().info("DUT leaving the AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        zephyr_wifi_collections.join_sniffer_validation(
            wifi_access_point,
            wifi_sniffer,
            wifi_obj.dut_addr['dut_mac_address'],
            ap_mac_address,
            sniffer_filter,
            power_save=power_save,
        )

        validate_powersave_capture_and_archive(
            wifi_sniffer, ap_mac_address, wifi_obj.dut_addr['dut_mac_address'], capture_filename)

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
