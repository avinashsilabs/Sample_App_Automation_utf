"""
Test BLE Multi-Connection Data Transfer - nRF Dongles + Si91x DUT
==========================================================================

Objective:
    Validate the Si91x DUT's ability to maintain multiple simultaneous BLE
    connections with bidirectional (RX + TX) GATT data transfer over an extended
    duration, exercising both Central and Peripheral roles concurrently.

    Every remote device is an nRF52840 dongle
    driven through the ``blatann`` interface (``nrf_ble_client.interfaces.bluetooth``).
    All connections (up to 8 central + 2 peripheral = 10) are between the DUT and
    nRF dongles.

Configuration:
    Each test scenario is defined by instantiating BLEMultiDataTransferTestNRF with:

        num_central_connections    - Number of devices where DUT acts as Central
        num_peripheral_connections - Number of devices where DUT acts as Peripheral (max 2)
        test_duration              - Data transfer duration in seconds
        data_transfer_mode         - One of: "notification", "indication",
                                     "write_with_response", "write_without_response"
        data_size                  - Bytes per payload (default 20)
        max_retries                - Connection retry count (default 3)

Test Architecture (4-Phase Design):
    Phase 0 - Prepare:      Build the nRF GATT servers, configure SMP security
                            params and register callbacks on every dongle.
    Phase 1 - Advertise:    Central-role (sensor) nRF dongles begin advertising.
    Phase 2 - Connect:      Peripheral-role (phone) dongles connect to the DUT as
                            centrals, then the DUT connects to each advertising
                            sensor dongle. Per-device data transfer threads start
                            immediately after each connection is verified.
    Phase 3 - Retry:        Any connections that failed in Phase 2 are retried.
    Phase 4 - Monitor:      Data transfer runs for test_duration with health checks
                            every 5 minutes, driven by DUT serial logs and data-flow
                            activity. Auto-reconnect triggers on confirmed disconnect.


Author: Ashish Chittimilla (nRF dongle variant)
"""
import os
import time
import threading
import random
import string
import re
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth.nrf_blatann import NRFBLEIoCapabilities, NRFBLEPeerDevAddrTypes
import openpyxl


def logger():
    return get_logger(__name__)


_cached_dut_address = None
_BD_ADDR_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def get_dut_address(wifi_dut):
    """
    Retrieve the DUT BD address dynamically via CLI and cache it for all
    subsequent calls.  No hardcoded fallback - the address is always
    queried from the DUT so the script works on any setup without edits.

    Returns:
        str: BD address in XX:XX:XX:XX:XX:XX format.

    Raises:
        RuntimeError: If the address cannot be retrieved.
    """
    global _cached_dut_address
    if _cached_dut_address is not None:
        logger().info(f"DUT BD Address (cached): {_cached_dut_address}")
        return _cached_dut_address

    try:
        dynamic_address = wifi_dut.interfaces.wifi.get_local_address()
        if dynamic_address and _BD_ADDR_PATTERN.match(dynamic_address.strip()):
            _cached_dut_address = dynamic_address.strip()
            logger().info(f"DUT BD Address (retrieved dynamically): {_cached_dut_address}")
            return _cached_dut_address
        else:
            raise RuntimeError(
                f"get_local_address() returned invalid/empty value: '{dynamic_address}'. "
                f"Ensure the DUT is powered on and the 'btc gap get_local_address' CLI command is available."
            )
    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(
            f"Failed to retrieve DUT BD address: {e}. "
            f"Ensure the DUT is powered on and the 'btc gap get_local_address' CLI command is available."
        )


# =============================================================================
# BLE Multi-Connection Data Transfer Test Class (nRF dongle variant)
# =============================================================================

class BLEMultiDataTransferTestNRF:
    """
    Reusable BLE multi-connection data transfer test engine using nRF dongles.

    Encapsulates the full test flow (prepare, advertise, connect, retry, monitor)
    with configurable connection topology, duration, and data transfer mode.

    Usage:
        test = BLEMultiDataTransferTestNRF(
            wifi_dut=wifi_dut,
            nrf_clients=nrf_ble_clients,
            num_central_connections=3,
            num_peripheral_connections=2,
            test_duration=300,
            data_transfer_mode="notification",
        )
        test.execute()
    """

    # Supported data transfer modes
    MODE_NOTIFICATION = "notification"
    MODE_INDICATION = "indication"
    MODE_WRITE_WITH_RESPONSE = "write_with_response"
    MODE_WRITE_WITHOUT_RESPONSE = "write_without_response"

    VALID_MODES = [
        MODE_NOTIFICATION,
        MODE_INDICATION,
        MODE_WRITE_WITH_RESPONSE,
        MODE_WRITE_WITHOUT_RESPONSE,
    ]

    # =========================================================================
    # GARMIN BLE CONNECTION PARAMETERS
    # =========================================================================
    # Scan parameters: Window=14.375ms, Interval=33.125ms (units of 0.625ms)
    SCAN_INTERVAL = 53            # 33.125ms / 0.625ms
    SCAN_WINDOW = 23              # 14.375ms / 0.625ms

    # High Throughput sensor connections (LSTO=4000ms, PHY=1M).
    # Per the Garmin 8+2 test plan the HT CI and sensor MTU depend on sensor density:
    #   5-sensor cases (2 HT + 3 LT): HT CI = 45ms, MTU = 23 (default)
    #   8-sensor cases (4 HT + 4 LT): HT CI = 90ms, MTU = 70
    # The constants below are the 5-sensor baseline; the 8-sensor overrides are applied
    # per instance in __init__ (self.ht_sensor_ci_min/max, self.sensor_max_data_len),
    # auto-selected by the number of central connections (or overridden by the caller).
    HT_SENSOR_CI_MIN = 36        # 45ms / 1.25ms  (5-sensor baseline)
    HT_SENSOR_CI_MAX = 36        # 45ms / 1.25ms  (5-sensor baseline)
    HT_SENSOR_CI_MS_HIGH_DENSITY = 90   # 8-sensor HT CI (ms) per Garmin plan
    HT_SENSOR_LSTO = 400         # 4000ms / 10ms
    HT_SENSOR_LATENCY = 0
    HT_SENSOR_MIN_CE = 4         # 2.5ms / 0.625ms  (req_legacy_conn min_ce_length)
    HT_SENSOR_MAX_CE = 8         # 5ms   / 0.625ms  (req_legacy_conn max_ce_length)

    # Low Throughput sensor connections (CI=200-250ms, LSTO=4000ms, PHY=1M)
    LT_SENSOR_CI_MIN = 160       # 200ms / 1.25ms
    LT_SENSOR_CI_MAX = 200       # 250ms / 1.25ms
    LT_SENSOR_LSTO = 400         # 4000ms / 10ms
    LT_SENSOR_LATENCY = 0
    LT_SENSOR_MIN_CE = 2         # 1.25ms / 0.625ms (req_legacy_conn min_ce_length)
    LT_SENSOR_MAX_CE = 4         # 2.5ms  / 0.625ms (req_legacy_conn max_ce_length)

    # Sensor DLE parameters (DLE OFF). Sensor ATT MTU: 23 (5-sensor) / 70 (8-sensor).
    SENSOR_BUFFER_MODE = 0       # DLE off
    SENSOR_BUFFER_COUNT = 3
    SENSOR_MAX_DATA_LEN = 20     # MTU 23 - 3 (5-sensor baseline)
    SENSOR_MTU_LOW_DENSITY = 23  # 5-sensor cases
    SENSOR_MTU_HIGH_DENSITY = 70 # 8-sensor cases
    HIGH_DENSITY_CENTRAL_THRESHOLD = 8  # >= this many centrals -> 8-sensor profile

    # Phone (Peripheral) connection parameters: CI=90ms, LSTO=4s, Latency=4, PHY=2M
    PHONE_CI_MIN = 72            # 90ms / 1.25ms
    PHONE_CI_MAX = 72            # 90ms / 1.25ms
    PHONE_LATENCY = 4
    PHONE_LSTO = 400             # 4000ms / 10ms

    # Phone DLE parameters (DLE ON)
    PHONE_BUFFER_MODE = 1        # DLE on
    PHONE_BUFFER_COUNT = 2
    PHONE_MAX_DATA_LEN = 232

    # Connection verification timeouts
    SENSOR_CONNECT_TIMEOUT = 60  # seconds
    SENSOR_CONNECT_RETRIES = 3
    SCAN_TIMEOUT = 30            # nRF scan timeout (seconds)

    # Firmware limit - DUT supports max 2 peripheral-role connections
    MAX_DUT_PERIPHERAL_CONNECTIONS = 2

    # Fixed random address for DUT (used when use_random_address=True)
    RANDOM_DUT_ADDRESS = "F1:22:33:44:55:66"

    # GATT UUIDs (16-bit short form)
    # DUT-hosted data service/characteristic (the nRF, as GATT client, subscribes to
    # and writes to these).
    DUT_SERVICE_UUID_16 = 0xAABB
    DUT_CHAR_UUID_16 = 0x1AA1

    # Standard Bluetooth SIG services the DUT firmware (GATT client on sensor /
    # DUT-central connections) is hard-coded to discover. The nRF GATT server MUST
    # expose these exact UUIDs per mode, otherwise the DUT logs "Client Gatt
    # Notification service not found" / "Client Gatt write service not found" and no
    # data flows. Every sensor mode sets tx_write=1, so the Heart Rate 0x2A39 write
    # target is always present:
    #   notification / write_* -> Heart Rate Service (notify 0x2A37, write 0x2A39)
    #   indication             -> Health Thermometer 0x2A1C (RX) + Heart Rate 0x2A39 (TX)
    HR_SERVICE_UUID_16 = 0x180D
    HR_MEASUREMENT_UUID_16 = 0x2A37          # notify (RX: nRF -> DUT)
    HR_BODY_SENSOR_LOC_UUID_16 = 0x2A38      # read
    HR_CONTROL_POINT_UUID_16 = 0x2A39        # write (TX: DUT -> nRF)
    HT_SERVICE_UUID_16 = 0x1809
    HT_MEASUREMENT_UUID_16 = 0x2A1C          # read/write/notify/indicate
    IA_SERVICE_UUID_16 = 0x1802
    IA_ALERT_LEVEL_UUID_16 = 0x2A06          # read/write/write-without-response

    # Trailing placeholder service appended AFTER the sensor service(s) so the last
    # "real" service (0x180D / 0x1809) gets a BOUNDED end handle instead of 0xFFFF.
    # The DUT's per-service characteristic discovery uses [start..end]; when the
    # sensor service is the last attribute in the table its end handle is 0xFFFF,
    # which the DUT does not enumerate correctly ("service not found"). Device
    # Information (0x180A) + Manufacturer Name (0x2A29, read) is a benign standard
    # service the DUT simply ignores during its 0x180D match.
    PLACEHOLDER_SERVICE_UUID_16 = 0x180A     # Device Information (trailing, bounds handles)
    PLACEHOLDER_CHAR_UUID_16 = 0x2A29        # Manufacturer Name String (read)

    # Emit one throttled log line per this many DUT->nRF notifications (TX direction),
    # so the received traffic is visible without flooding the log.
    TX_LOG_EVERY = 50

    # RX (nRF->DUT notification) pacing. The RX direction is GENERATED by this host, so
    # host-side sleeps used to cap it well below the link's capacity. To let the link /
    # connection interval be the limiter instead:
    #   - HT sensors send with a small in-flight window (multiple notifications can be
    #     packed into one connection event) and NO inter-packet sleep.
    #   - LT sensors keep a modest cadence so they stay genuinely "low throughput".
    #   - Indications are confirmed PDUs (one outstanding at a time), so they stay
    #     serialized with a small delay.
    RX_NOTIFY_WINDOW_HT = 4      # max in-flight (unconfirmed) notifications for HT sensors
    RX_NOTIFY_DELAY_HT = 0.0     # no extra host sleep; notify().wait() paces to the link
    # LT sends serialized (window=1), so the connection interval (200-250ms) is the real
    # limiter (~4-5 pps). No extra host sleep is needed; raise this only if you want LT to
    # emulate a genuinely low ~2 pps sensor per the plan intent.
    RX_NOTIFY_DELAY_LT = 0.0
    RX_INDICATE_DELAY = 0.1      # indications are inherently ~1 per CE

    # Expected per-connection throughput targets from the Garmin 8+2 test plan
    # (BLE_Standalone sheet). Keyed by sensor density -> conn type ->
    # (rx_pps, tx_pps, rx_Bps, tx_Bps). Phone (peripheral) targets are not specified
    # in the plan, so they are reported as observed-only.
    EXPECTED_THROUGHPUT = {
        "low": {   # 5-sensor cases (2 HT + 3 LT)
            "HT Sensor": (35, 26, 650, 480),
            "LT Sensor": (2, 2, 46, 46),
        },
        "high": {  # 8-sensor cases (4 HT + 4 LT)
            "HT Sensor": (19, 19, 700, 450),
            "LT Sensor": (2, 2, 53, 53),
        },
    }
    # Pass/fail is packet-based: a sensor connection passes when its observed RX and TX
    # packet rate (pps) is within 10% of the plan target - i.e. at/above 90% of it.
    # (e.g. target 19 pps -> 18 pps still passes; below ~17.1 pps fails.)
    THROUGHPUT_OK_FRACTION = 0.9

    # Connection-event consistency: a connection is flagged when the DUT scheduler drops
    # more than this fraction of its scheduled events (Sch_Fail / (Conn_evts + Sch_Fail)),
    # which starves its connection-event count relative to its peers. Evaluated on the
    # cumulative DUT link-layer stats accumulated across the Phase-4 polls.
    SCHED_FAIL_MAX_RATIO = 0.20

    def __init__(self, wifi_dut, nrf_clients,
                 num_central_connections,
                 num_peripheral_connections,
                 test_duration,
                 data_transfer_mode="notification",
                 data_size=20,
                 max_retries=3,
                 num_ht_central=0,
                 num_lt_central=0,
                 ble_scanning=False,
                 ble_advertising=False,
                 non_connectable_adv=False,
                 central_data_transfer_mode=None,
                 peripheral_data_transfer_mode=None,
                 ht_data_size=None,
                 lt_data_size=None,
                 dle_enabled=None,
                 use_random_address=False,
                 phy_rate="1M",
                 random_reconnect=False,
                 io_capability=0x00,
                 nrf_io_capability=None,
                 nrf_public_address=True,
                 ht_sensor_ci_ms=None,
                 sensor_mtu=None,
                 enforce_throughput=True,
                 test_case_id=None):
        """
        Args:
            wifi_dut: The DUT fixture (Si91x device).
            nrf_clients: List of nRF dongle fixtures (nrf_ble_clients).
            num_central_connections: Number of dongles where DUT acts as Central.
            num_peripheral_connections: Number of dongles where DUT acts as Peripheral (max 2).
            test_duration: Data transfer duration in seconds.
            data_transfer_mode: One of "notification", "indication",
                                "write_with_response", "write_without_response".
            data_size: Bytes per notification/write payload (default 20).
            max_retries: Max connection attempts per phone device (Phase 2) and per
                         failed device in the Phase 3 retry pass (default 3). Sensor
                         connects use SENSOR_CONNECT_RETRIES.
            num_ht_central: Number of High Throughput central connections.
            num_lt_central: Number of Low Throughput central connections.
            ble_scanning: Enable BLE scanning during data transfer (default False).
            ble_advertising: Enable BLE advertising during data transfer (default False).
            non_connectable_adv: Use non-connectable advertising if ble_advertising is True.
            central_data_transfer_mode: Override data transfer mode for central connections only.
            peripheral_data_transfer_mode: Override data transfer mode for peripheral connections only.
            ht_data_size: Payload size for HT central connections. If None, uses data_size.
            lt_data_size: Payload size for LT central connections. If None, uses data_size.
            dle_enabled: Data Length Extension setting. True=all, False=none, "ht_only",
                         "disabled_central". Default None (not configured).
            use_random_address: Use random BLE address for DUT (default False).
            phy_rate: PHY rate for connections - "1M" or "2M" (default "1M").
            random_reconnect: Enable random connect/reconnect pattern during test.
            io_capability: SMP I/O capability value for DUT (default 0x00).
            nrf_io_capability: NRFBLEIoCapabilities value for the dongles. If None,
                               defaults to NONE (JustWorks / NoInputNoOutput).
            nrf_public_address: When True (default) set a PUBLIC address
                               (dev_addr_type=0) on every dongle before advertising,
                               matching the Garmin test plan. When False, keep the
                               SoftDevice default random-static address.
            ht_sensor_ci_ms: High-throughput sensor connection interval (ms). If None,
                               auto-selected per the Garmin plan: 45ms for the 5-sensor
                               cases, 90ms for the 8-sensor cases.
            sensor_mtu: Sensor ATT MTU. If None, auto-selected per the plan: 23 for the
                               5-sensor cases, 70 for the 8-sensor cases.
            enforce_throughput: When True (default) the test FAILS (raises
                               AssertionError) at the end if any sensor connection's
                               observed RX/TX throughput is below the Garmin plan target
                               (within THROUGHPUT_OK_FRACTION tolerance). Set False to
                               only report pass/fail without failing the test.
        """
        self.wifi_dut = wifi_dut
        self.nrf_clients = nrf_clients
        self.num_central_connections = num_central_connections
        self.num_peripheral_connections = num_peripheral_connections
        self.test_duration = test_duration
        self.data_transfer_mode = data_transfer_mode
        self.data_size = data_size
        self.max_retries = max_retries

        # HT/LT split for central connections
        self.num_ht_central = num_ht_central
        self.num_lt_central = num_lt_central

        # Activity during data transfer
        self.ble_scanning = ble_scanning
        self.ble_advertising = ble_advertising
        self.non_connectable_adv = non_connectable_adv

        # Per-role data transfer modes
        self.central_data_transfer_mode = central_data_transfer_mode or data_transfer_mode
        self.peripheral_data_transfer_mode = peripheral_data_transfer_mode or data_transfer_mode

        # Per-connection-type payload sizes
        self.ht_data_size = ht_data_size or data_size
        self.lt_data_size = lt_data_size or data_size

        # Connection features
        self.dle_enabled = dle_enabled
        self.use_random_address = use_random_address
        self.phy_rate = phy_rate
        self.random_reconnect = random_reconnect
        self.io_capability = io_capability
        self.nrf_io_capability = nrf_io_capability if nrf_io_capability is not None else NRFBLEIoCapabilities.NONE
        # nRF dongles default to a random-static address (dev_addr_type=1). The Garmin
        # test plan expects the sensors to advertise with a PUBLIC address
        # (dev_addr_type=0); when True we set a public address on every dongle before
        # advertising. Disable to keep the SoftDevice default random-static address.
        self.nrf_public_address = nrf_public_address
        self.enforce_throughput = enforce_throughput
        self.test_case_id = test_case_id

        # Sensor profile per the Garmin 8+2 plan: the high-density (8-sensor) cases use
        # HT CI=90ms and MTU=70; the low-density (5-sensor) cases use HT CI=45ms and
        # MTU=23. Auto-selected by central count unless the caller overrides.
        self.is_high_density = (
            self.num_central_connections >= self.HIGH_DENSITY_CENTRAL_THRESHOLD
        )
        if ht_sensor_ci_ms is None:
            ht_sensor_ci_ms = (
                self.HT_SENSOR_CI_MS_HIGH_DENSITY if self.is_high_density
                else self.HT_SENSOR_CI_MIN * 1.25
            )
        if sensor_mtu is None:
            sensor_mtu = (
                self.SENSOR_MTU_HIGH_DENSITY if self.is_high_density
                else self.SENSOR_MTU_LOW_DENSITY
            )
        self.ht_sensor_ci_ms = ht_sensor_ci_ms
        self.sensor_mtu = sensor_mtu
        # CI in 1.25ms controller units (fixed interval -> min==max).
        self.ht_sensor_ci_min = int(round(ht_sensor_ci_ms / 1.25))
        self.ht_sensor_ci_max = self.ht_sensor_ci_min
        # ATT notification payload = MTU - 3 (1B opcode + 2B handle); drives the DUT
        # set_data_pattern max_data_length for sensor connections.
        self.sensor_max_data_len = max(int(sensor_mtu) - 3, 1)

        # Validate data transfer modes
        for mode in [self.data_transfer_mode, self.central_data_transfer_mode, self.peripheral_data_transfer_mode]:
            if mode not in self.VALID_MODES:
                raise ValueError(
                    f"Invalid data_transfer_mode '{mode}'. "
                    f"Must be one of: {self.VALID_MODES}"
                )

        # Validate HT/LT split if specified
        if self.num_ht_central > 0 or self.num_lt_central > 0:
            if self.num_ht_central + self.num_lt_central != self.num_central_connections:
                raise ValueError(
                    f"num_ht_central ({self.num_ht_central}) + num_lt_central ({self.num_lt_central}) "
                    f"must equal num_central_connections ({self.num_central_connections})."
                )

        # Clamp peripheral connections to firmware limit
        if self.num_peripheral_connections > self.MAX_DUT_PERIPHERAL_CONNECTIONS:
            logger().warning(
                f"NUM_PERIPHERAL_CONNECTIONS={self.num_peripheral_connections} exceeds the DUT firmware "
                f"limit of {self.MAX_DUT_PERIPHERAL_CONNECTIONS}. Clamping to {self.MAX_DUT_PERIPHERAL_CONNECTIONS}."
            )
            self.num_peripheral_connections = self.MAX_DUT_PERIPHERAL_CONNECTIONS

        self.num_devices = self.num_central_connections + self.num_peripheral_connections

        # Validate totals
        if self.num_devices < 1:
            raise ValueError("Total number of devices (central + peripheral) must be at least 1.")

        if self.num_devices > len(self.nrf_clients):
            raise ValueError(
                f"Requested {self.num_devices} devices but only {len(self.nrf_clients)} nRF dongles "
                f"are available. Reduce num_central_connections or num_peripheral_connections, "
                f"or add more dongles to the harness 'nrf_ble_clients' list."
            )

        # GATT UUID string forms (for DUT-side APIs / logging)
        self.SERVICE_UUID = "0000aabb-0000-1000-8000-00805f9b34fb"
        self.CHAR_UUID = "00001aa1-0000-1000-8000-00805f9b34fb"

        # Per-device state (initialized in execute())
        self.clients = None
        self.nrf_bles = None
        self.nrf_addrs = None
        self.nrf_services = None
        self.nrf_chars = None
        self.nrf_write_chars = None
        self.dut_char_uuids = None
        self.target_address = None
        self.rx_counts = None
        self.tx_counts = None
        self.connection_attempts = None
        self.connection_success = None
        self.connection_errors = None
        self.reconnect_counts = None
        self.data_transfer_threads = None
        self.data_transfer_stop_events = None
        self.per_device_logs = None
        self.monitoring_history = None
        self.final_pkt_stats_rows = None
        self._last_good_stats_text = None
        self.throughput_pass = None
        self.throughput_failures = []
        self._cum_pkt_stats = {}
        self._scan_report_total = 0

    def execute(self):
        """Run the full BLE multi-connection data transfer test.

        Every phase runs inside a try/finally so that ``_cleanup()`` ALWAYS executes -
        even if a phase raises or an assertion fails midway. Without this, a failure in
        connect/monitor/report would leak nRF links, leave bonding data on the dongles
        and leave the DUT advertising/scanning, all of which corrupt the next test case.
        """
        self._initialize_state()
        try:
            self._log_configuration()
            self._prepare_nrf_devices()
            self._initialize_dut()
            self._phase1_advertise()
            self._phase2_connect()
            self._phase3_retry()
            self._phase4_monitor()
            self._generate_report()
            self._assert_throughput()
        finally:
            self._cleanup()

    # =========================================================================
    # INITIALIZATION
    # =========================================================================

    def _initialize_state(self):
        """Initialize all per-device state arrays."""
        n = self.num_devices
        self.clients = [self.nrf_clients[i] for i in range(n)]
        self.nrf_bles = [c.interfaces.bluetooth for c in self.clients]
        self.nrf_addrs = [None] * n
        # Recorded dev_addr_type per dongle (0=public, 1=random). Set when we force a
        # public address; used so the DUT connects with the matching add_type instead
        # of inferring it from the address bytes.
        self.nrf_addr_types = [None] * n
        self.nrf_services = [None] * n
        self.nrf_chars = [None] * n
        self.nrf_write_chars = [None] * n
        self.dut_char_uuids = [None] * n
        self.rx_counts = [0] * n
        self.tx_counts = [0] * n
        self.connection_attempts = [0] * n
        self.connection_success = [False] * n
        self.connection_errors = [None] * n
        self.reconnect_counts = [0] * n
        self.data_transfer_threads = [None] * n
        self.data_transfer_stop_events = [threading.Event() for _ in range(n)]
        self.per_device_logs = [{} for _ in range(n)]
        self.monitoring_history = []
        self.final_pkt_stats_rows = None
        self._last_good_stats_text = None
        self.throughput_pass = None
        self.throughput_failures = []
        self._cum_pkt_stats = {}
        self._scan_report_total = 0

    def _log_configuration(self):
        """Log test configuration."""
        logger().info("=" * 60)
        logger().info("TEST CONFIGURATION (nRF dongle variant)")
        logger().info(f"  Total devices:          {self.num_devices}")
        logger().info(f"  Central connections:     {self.num_central_connections}  (DUT connects to nRF)")
        if self.num_ht_central or self.num_lt_central:
            logger().info(f"    HT centrals:           {self.num_ht_central}")
            logger().info(f"    LT centrals:           {self.num_lt_central}")
        logger().info(f"  Peripheral connections:  {self.num_peripheral_connections}  (nRF connects to DUT)")
        logger().info(f"  Data transfer mode:      {self.data_transfer_mode}")
        if self.central_data_transfer_mode != self.data_transfer_mode:
            logger().info(f"    Central mode:           {self.central_data_transfer_mode}")
        if self.peripheral_data_transfer_mode != self.data_transfer_mode:
            logger().info(f"    Peripheral mode:        {self.peripheral_data_transfer_mode}")
        logger().info(f"  Data size:               {self.data_size} bytes")
        if self.ht_data_size != self.data_size:
            logger().info(f"    HT data size:          {self.ht_data_size} bytes")
        if self.lt_data_size != self.data_size:
            logger().info(f"    LT data size:          {self.lt_data_size} bytes")
        logger().info(f"  Test duration:           {self.test_duration}s")
        logger().info(f"  Max retries:             {self.max_retries}")
        logger().info(f"  BLE scanning:            {self.ble_scanning}")
        logger().info(f"  BLE advertising:         {self.ble_advertising}")
        if self.ble_advertising:
            logger().info(f"    Non-connectable:       {self.non_connectable_adv}")
        if self.dle_enabled is not None:
            logger().info(f"  DLE enabled:             {self.dle_enabled}")
        logger().info(f"  PHY rate:                {self.phy_rate}")
        logger().info(f"  Sensor density:          {'high (8-sensor)' if self.is_high_density else 'low (5-sensor)'}")
        logger().info(f"  HT sensor CI:            {self.ht_sensor_ci_ms:.0f} ms")
        logger().info(f"  Sensor MTU:              {self.sensor_mtu} (max_data_len={self.sensor_max_data_len})")
        logger().info(f"  nRF public address:      {self.nrf_public_address} (dev_addr_type=0 when True)")
        logger().info(f"  Use random address:      {self.use_random_address}")
        logger().info(f"  Random reconnect:        {self.random_reconnect}")
        logger().info(f"  DUT I/O capability:      0x{self.io_capability:02X}")
        logger().info(f"  nRF I/O capability:      {self.nrf_io_capability}")
        logger().info("=" * 60)

    def _ensure_nrf_initialized(self):
        """Initialize the nRF dongles this test will actually use.

        Works around the `nrf_ble_clients` fixture only calling init() for dongles
        that were given indexed @pytest.mark.config params. Only the first
        ``num_devices`` dongles are initialized; initializing dongles beyond what the
        test needs just wastes time and spams errors for any absent/undetected dongle
        in the harness (whose serial port cannot be found).
        """
        for i in range(self.num_devices):
            client = self.nrf_clients[i]
            nrf_ble = client.interfaces.bluetooth
            try:
                if getattr(nrf_ble, "ble_device", None) is None:
                    logger().info(f"Initializing nRF dongle index {i} (ble_device was None)...")
                    nrf_ble.init()
                else:
                    logger().info(f"nRF dongle index {i} already initialized.")
            except Exception as e:
                logger().error(f"Failed to init nRF dongle index {i}: {e}")

    def _standard_sensor_service_spec(self, mode):
        """Return the standard SIG GATT layout the DUT firmware expects for a mode.

        The DUT (GATT client on sensor connections) is hard-coded to look for fixed
        service+characteristic UUIDs (see ble_config.h in the firmware):
            rx_notifications -> 0x180D / 0x2A37  (Heart Rate Measurement, NOTIFY)
            rx_indications   -> 0x1809 / 0x2A1C  (Health Thermometer Measurement, INDICATE)
            tx_write         -> 0x180D / 0x2A39  (Heart Rate Control Point, WRITE)

        For *every* sensor mode the DUT firmware sets ``tx_write=1``, so the Heart Rate
        service (which carries the 0x2A39 write target the DUT writes to) must ALWAYS be
        present, regardless of the RX mode. Indication mode additionally needs the
        Health Thermometer service for the 0x2A1C indicate characteristic.

        Characteristic property bitmaps are fixed so the DUT's char-property parser
        sees the expected flags: 0x2A37 = notify-only, 0x2A38 = read-only,
        0x2A39 = write-only.

        Returns a dict with keys:
            services    - list of {"uuid": <svc>, "chars": [(uuid, props), ...]}
            notify_char - char the nRF notifies/indicates on (RX: nRF -> DUT) or None
            write_char  - char the DUT writes to (TX: DUT -> nRF); on_write counter target
            use_indicate- True for indication mode (use char.indicate() not char.notify())
        """
        # Each characteristic carries a 0x2901 Characteristic User Description
        # descriptor. It is purely informational and plays no part in discovery/CCCD
        # subscription.
        notify_props = {"notify": True, "max_length": 247, "variable_length": True,
                        "user_description": "Notify Heart Rate Measurement"}
        read_props = {"read": True, "max_length": 247, "variable_length": True,
                      "user_description": "Sensor locator"}
        write_props = {"write": True, "max_length": 247, "variable_length": True,
                       "user_description": "Heart Rate Point Write Value"}
        # Health Thermometer measurement: read/write/notify/indicate (property bitmap 0x3A).
        ht_props = {"read": True, "write": True, "notify": True, "indicate": True,
                    "max_length": 247, "variable_length": True,
                    "user_description": "Read/Write/Notify/Indicate temperature level"}

        # Heart Rate service is ALWAYS required: it holds the 0x2A39 write target that
        # the DUT firmware writes to (tx_write) on every sensor connection, and the
        # 0x2A37 notify characteristic used for notification mode.
        hr_service = {
            "uuid": self.HR_SERVICE_UUID_16,
            "chars": [
                (self.HR_MEASUREMENT_UUID_16, notify_props),     # 0x2A37 notify (RX)
                (self.HR_BODY_SENSOR_LOC_UUID_16, read_props),   # 0x2A38 read
                (self.HR_CONTROL_POINT_UUID_16, write_props),    # 0x2A39 write (TX target)
            ],
        }

        # Trailing placeholder so the sensor service is NOT the last attribute in the
        # table (otherwise its end handle is 0xFFFF, which the DUT fails to
        # enumerate). Always appended LAST in the services list.
        placeholder_service = {
            "uuid": self.PLACEHOLDER_SERVICE_UUID_16,
            "chars": [
                (self.PLACEHOLDER_CHAR_UUID_16,
                 {"read": True, "max_length": 32, "variable_length": True}),
            ],
        }

        if mode == self.MODE_INDICATION:
            ht_service = {
                "uuid": self.HT_SERVICE_UUID_16,
                "chars": [(self.HT_MEASUREMENT_UUID_16, ht_props)],  # 0x2A1C indicate (RX)
            }
            return {
                "services": [hr_service, ht_service, placeholder_service],
                "notify_char": self.HT_MEASUREMENT_UUID_16,
                "write_char": self.HR_CONTROL_POINT_UUID_16,
                "use_indicate": True,
            }

        # notification / write_with_response / write_without_response:
        # the DUT receives via 0x2A37 notify and writes via 0x2A39 (both in HR service).
        return {
            "services": [hr_service, placeholder_service],
            "notify_char": self.HR_MEASUREMENT_UUID_16,
            "write_char": self.HR_CONTROL_POINT_UUID_16,
            "use_indicate": False,
        }

    def _prepare_nrf_devices(self):
        """Build GATT servers, configure SMP security and register callbacks on every dongle.

        Each dongle hosts a GATT server exposing the standard Bluetooth SIG service
        that the DUT firmware (GATT client on sensor connections) expects for the
        configured data-transfer mode (Heart Rate for notification and write modes,
        Health Thermometer for indication). ``nrf_chars`` holds the
        notify/indicate characteristic (RX: nRF -> DUT) and ``nrf_write_chars`` holds
        the writable characteristic the DUT writes to (TX: DUT -> nRF), counted via the
        ``on_write`` callback. Phone (DUT-peripheral) dongles primarily act as GATT
        clients, but the server is still created for symmetry.
        """
        logger().info("=" * 60)
        logger().info("PHASE 0: Preparing nRF dongles (GATT servers + SMP security)")
        logger().info("=" * 60)

        # The plural `nrf_ble_clients` fixture only calls init() for dongles that
        # have indexed @pytest.mark.config params; without that, ble_device stays
        # None and every operation fails with "'NoneType' has no attribute ...".
        # Initialize all dongles here so the test is self-contained. Every dongle
        # in the fixture list is initialized (not just the ones we use) so the
        # fixture's unconditional deinit() teardown loop does not crash on an
        # uninitialized device.
        self._ensure_nrf_initialized()

        # Delete any stored bonding data on every dongle BEFORE this test pairs, so
        # each test case starts from a clean security database and performs a fresh
        # pairing instead of silently reusing an LTK bonded in a previous test. (We
        # also delete on teardown, but doing it here guarantees freshness even if a
        # previous test crashed before its cleanup ran.)
        for i in range(self.num_devices):
            try:
                self.nrf_bles[i].delete_bonding_data()
                logger().info(f"nRF {i+1}: cleared stored bonding data (fresh-pairing start).")
            except Exception as e:
                logger().warning(f"nRF {i+1}: start-of-test delete_bonding_data: {e}")

        # Force a PUBLIC address (dev_addr_type=0) on every dongle BEFORE any
        # advertising/scanning/connecting. The nRF SoftDevice otherwise advertises with
        # a random-static address (dev_addr_type=1), which the Garmin test plan does not
        # want for the sensors. Setting the address is only allowed while the device is
        # idle, so this MUST run before _phase1_advertise / the discovery self-test.
        # The resulting type is recorded so the DUT connects with the matching add_type.
        if self.nrf_public_address:
            for i in range(self.num_devices):
                try:
                    pub_addr = self.nrf_bles[i].set_local_address()  # defaults to PUBLIC
                    self.nrf_addrs[i] = pub_addr
                    self.nrf_addr_types[i] = 0
                    logger().info(
                        f"nRF {i+1}: advertising address forced to PUBLIC {pub_addr} "
                        f"(dev_addr_type=0)."
                    )
                except Exception as e:
                    self.nrf_addr_types[i] = None
                    logger().warning(
                        f"nRF {i+1}: failed to set public address ({e}); falling back to "
                        f"the SoftDevice default random-static address (dev_addr_type=1)."
                    )
            # Verify the change actually took (read back the live address type).
            for i in range(self.num_devices):
                try:
                    actual = self.nrf_bles[i].get_ble_address_type()
                    self.nrf_addr_types[i] = actual if actual is not None else self.nrf_addr_types[i]
                    logger().info(
                        f"nRF {i+1}: verified dev_addr_type={actual} "
                        f"({'public' if actual == 0 else 'random'})."
                    )
                except Exception as e:
                    logger().debug(f"nRF {i+1}: address-type readback warning: {e}")

        for i in range(self.num_devices):
            nrf_ble = self.nrf_bles[i]
            mode = self._get_effective_mode(i)
            spec = self._standard_sensor_service_spec(mode)
            try:
                built = {}
                svc_uuids = []
                first_service = None
                for svc in spec["services"]:
                    service = nrf_ble.add_custom_service(uuid=svc["uuid"])
                    if first_service is None:
                        first_service = service
                    svc_uuids.append(svc["uuid"])
                    for char_uuid, props in svc["chars"]:
                        characteristic = nrf_ble.add_custom_characteristic(
                            service=service,
                            uuid=char_uuid,
                            properties=props,
                            initial_value=b"nrf",
                        )
                        built[char_uuid] = characteristic
                self.nrf_services[i] = first_service
                # RX char (nRF -> DUT notify/indicate) and TX char (DUT -> nRF write)
                self.nrf_chars[i] = built.get(spec["notify_char"]) if spec["notify_char"] else None
                self.nrf_write_chars[i] = built.get(spec["write_char"]) if spec["write_char"] else None
                # Count DUT->nRF writes (TX direction for sensor connections)
                if self.nrf_write_chars[i] is not None:
                    self._register_write_counter(i, self.nrf_write_chars[i])
                # Log when the DUT subscribes to (or unsubscribes from) the nRF's
                # notify characteristic. This is the single clearest signal that the
                # DUT's rx_notifications GATT discovery of the nRF server succeeded -
                # without a subscription blatann cannot (and will not) notify.
                if self.nrf_chars[i] is not None:
                    self._register_subscription_logger(i, self.nrf_chars[i])
                logger().info(
                    f"nRF {i+1}: GATT server ready (mode={mode}, "
                    f"services={', '.join('0x%04X' % u for u in svc_uuids)}, "
                    f"notify_char={('0x%04X' % spec['notify_char']) if spec['notify_char'] else 'None'}, "
                    f"write_char={('0x%04X' % spec['write_char']) if spec['write_char'] else 'None'})"
                )
                # Dump the actual server database (what the DUT will discover over the
                # air). Confirms service UUID type (16-bit SIG vs 128-bit vendor),
                # characteristic handles and property bitmaps so we can tell whether a
                # failed DUT-side discovery is a server-build problem or a DUT-stack one.
                if i < self.num_central_connections:
                    self._log_nrf_server_database(i, nrf_ble)
            except Exception as e:
                logger().warning(f"nRF {i+1}: failed to build GATT server: {e}")

            # Configure SMP security params (peripheral perspective; DUT may initiate pairing)
            try:
                nrf_ble.set_security_params(
                    passcode_pairing=False,
                    io_capabilities=self.nrf_io_capability,
                    long_term_bonding=True,
                    lesc_pairing=True,
                )
            except Exception as e:
                logger().warning(f"nRF {i+1}: set_security_params warning: {e}")

            # Register informational callbacks (peripheral role)
            for reg in ("register_on_connect", "register_on_disconnect",
                        "register_on_security_level_changed",
                        "register_on_client_pairing_complete"):
                try:
                    getattr(nrf_ble, reg)()
                except Exception as e:
                    logger().debug(f"nRF {i+1}: {reg} warning: {e}")

            # Pre-compute the DUT data-characteristic UUID object for client-side ops
            try:
                self.dut_char_uuids[i] = nrf_ble.get_blatann_uuid(self.DUT_CHAR_UUID_16)
            except Exception as e:
                logger().debug(f"nRF {i+1}: get_blatann_uuid warning: {e}")

        # Prove (or disprove) that the sensor GATT servers are discoverable over the
        # air using a known-good GATT client (another nRF). This isolates whether the
        # DUT 'service not found' is an nRF server-build problem or a DUT-side stack
        # limitation, without needing a firmware rebuild.
        self._nrf_to_nrf_discovery_selftest()

    def _nrf_to_nrf_discovery_selftest(self):
        """nRF-to-nRF GATT discovery self-test.

        Uses one nRF as a GATT client (central) to connect to a sensor nRF
        (peripheral) and discover its services. If a peer nRF can enumerate the
        Heart Rate service (0x180D) with its notify (0x2A37) and write (0x2A39)
        characteristics, the sensor server is correct and discoverable over the air -
        meaning a DUT-side 'service not found' is a DUT discovery limitation, not
        an nRF build issue. Everything here is best-effort and fully cleaned up so it
        never disturbs the main test.
        """
        if self.num_devices < 2 or self.num_central_connections < 1:
            logger().info("Self-test skipped (need >=2 dongles incl. a sensor).")
            return

        target_idx = 0                       # a sensor dongle (has the HR server)
        central_idx = self.num_devices - 1   # borrow the last dongle as GATT client
        target = self.nrf_clients[target_idx].interfaces.bluetooth
        central = self.nrf_clients[central_idx].interfaces.bluetooth
        target_addr = None
        connected = False

        logger().info(
            f"=== nRF-to-nRF discovery self-test: central nRF {central_idx+1} -> "
            f"sensor nRF {target_idx+1} ==="
        )
        try:
            selftest_spec = self._standard_sensor_service_spec(self._get_effective_mode(target_idx))
            target_addr = target.start_advertising(
                local_name="NRF_SELFTEST", auto_restart=False,
                service_uuid16s=[svc["uuid"] for svc in selftest_spec["services"]],
            )
            logger().info(f"Self-test: sensor nRF {target_idx+1} advertising as {target_addr}")
            time.sleep(1)

            central.connect(
                dev_addr=target_addr,
                dev_addr_type=NRFBLEPeerDevAddrTypes.RANDOM_STATIC,
                timeout=20,
            )
            peer = getattr(central, "peer_device", None)
            if peer is None:
                logger().warning(
                    "Self-test: central nRF could NOT connect to the sensor nRF "
                    "(peripheral). Cannot evaluate discoverability."
                )
                return
            connected = True

            try:
                peer.discover_services().wait(15)
            except Exception as e:
                logger().info(f"Self-test: discover_services wait note: {e}")
                time.sleep(3)

            database = getattr(peer, "database", None)
            services = []
            if database is not None:
                services = (getattr(database, "services", None)
                            or list(getattr(database, "iter_services", lambda: [])()))
            logger().info(f"Self-test: peer nRF discovered {len(services)} services:")
            found_hr = found_notify = found_write = False
            for svc in services:
                svc_uuid = getattr(svc, "uuid", svc)
                logger().info(f"Self-test:   service uuid={svc_uuid}")
                if "180d" in str(svc_uuid).lower():
                    found_hr = True
                chars = (getattr(svc, "characteristics", None)
                         or list(getattr(svc, "iter_characteristics", lambda: [])()))
                for ch in chars:
                    ch_uuid = str(getattr(ch, "uuid", ch)).lower()
                    logger().info(f"Self-test:     char uuid={ch_uuid}")
                    if "2a37" in ch_uuid:
                        found_notify = True
                    if "2a39" in ch_uuid:
                        found_write = True

            if found_hr and found_notify and found_write:
                logger().info(
                    "Self-test VERDICT: PASS - a peer nRF fully discovered the sensor "
                    "Heart Rate service (0x180D + 0x2A37 + 0x2A39). The nRF server is "
                    "correct and discoverable over the air; the DUT 'service not found' "
                    "is a DUT-side discovery limitation, not an nRF build issue."
                )
            elif services:
                logger().warning(
                    f"Self-test VERDICT: PARTIAL - peer discovered services but not the "
                    f"full HR set (hr={found_hr}, notify={found_notify}, write={found_write}). "
                    f"The nRF server exposure needs adjustment."
                )
            else:
                logger().warning(
                    "Self-test VERDICT: FAIL - a peer nRF discovered NO services on the "
                    "sensor. The nRF GATT server is not being exposed/served correctly; "
                    "fix the nRF server build before blaming the DUT."
                )
        except Exception as e:
            logger().warning(f"Self-test error (non-fatal): {e}")
        finally:
            try:
                if connected and target_addr:
                    central.disconnect(target_addr)
            except Exception as e:
                logger().debug(f"Self-test: central disconnect note: {e}")
            try:
                target.stop_advertising()
            except Exception as e:
                logger().debug(f"Self-test: target stop_advertising note: {e}")
            time.sleep(1)
            logger().info("=== nRF-to-nRF discovery self-test complete ===")

    def _register_write_counter(self, idx, characteristic):
        """Register an on_write handler that counts DUT->nRF writes for a sensor connection."""
        def _on_write(_characteristic, event_args):
            try:
                value = getattr(event_args, "value", None)
                if value is None:
                    value = event_args
                try:
                    decoded = value.decode(errors="ignore") if isinstance(value, (bytes, bytearray)) else str(value)
                except Exception:
                    decoded = str(value)
                self.tx_counts[idx] += 1
                self.per_device_logs[idx].setdefault('tx', []).append(decoded)
            except Exception as e:
                logger().debug(f"nRF {idx+1}: on_write handler error: {e}")
        try:
            characteristic.on_write.register(_on_write)
        except Exception as e:
            logger().debug(f"nRF {idx+1}: could not register on_write: {e}")

    def _register_subscription_logger(self, idx, characteristic):
        """Log DUT subscribe/unsubscribe on the nRF notify char (RX discovery signal).

        When this fires with a NOTIFY/INDICATE state, it proves the DUT successfully
        discovered the nRF's GATT server and wrote the CCCD - i.e. the RX-notification
        path is live. If it never fires, the DUT's rx_notifications discovery failed and
        RX notifications cannot flow (the nRF will keep waiting for a subscriber).
        """
        def _on_sub_change(_characteristic, event_args):
            try:
                state = getattr(event_args, "subscription_state", event_args)
                logger().info(
                    f"nRF {idx+1} (sensor): DUT subscription change on notify char -> "
                    f"{state} (RX-notification path {'ENABLED' if str(state) != 'SubscriptionState.NOT_SUBSCRIBED' else 'disabled'})"
                )
            except Exception as e:
                logger().debug(f"nRF {idx+1}: on_subscription_change handler error: {e}")
        try:
            characteristic.on_subscription_change.register(_on_sub_change)
        except Exception as e:
            logger().debug(f"nRF {idx+1}: could not register on_subscription_change: {e}")

    def _log_nrf_server_database(self, idx, nrf_ble):
        """Dump the nRF local GATT server database for diagnostics.

        Logs every service (UUID + whether it is exposed as a 16-bit SIG UUID or a
        128-bit vendor UUID) and each characteristic (UUID, value/CCCD handles and
        property flags). This is exactly the database a connecting central (the DUT)
        sees during GATT discovery, so it lets us confirm the nRF is advertising the
        Heart Rate service (0x180D) with notify (0x2A37) / write (0x2A39) as proper
        16-bit UUIDs - and therefore whether a DUT 'service not found' is a server
        build issue or a DUT-side discovery limitation.
        """
        def _hx(value):
            # Format a handle as 0xNN to match the DUT serial log style; pass other
            # values through untouched.
            try:
                return "0x%X" % int(value)
            except (TypeError, ValueError):
                return str(value)

        try:
            ble_device = getattr(nrf_ble, "ble_device", None)
            database = getattr(ble_device, "database", None)
            if database is None:
                logger().info(f"nRF {idx+1}: server database introspection unavailable.")
                return
            services = (getattr(database, "services", None)
                        or list(getattr(database, "iter_services", lambda: [])()))
            logger().info(f"nRF {idx+1}: --- server database dump ({len(services)} services) ---")
            for svc in services:
                svc_uuid = getattr(svc, "uuid", svc)
                nrf_uuid = getattr(svc_uuid, "nrf_uuid", None)
                uuid_type = getattr(nrf_uuid, "type", "?") if nrf_uuid is not None else "?"
                start_h = getattr(svc, "start_handle", "?")
                end_h = getattr(svc, "end_handle", "?")
                chars = (getattr(svc, "characteristics", None)
                         or list(getattr(svc, "iter_characteristics", lambda: [])()))
                # The SoftDevice does not report a service's end handle at add time,
                # so derive the effective end from the highest attribute handle in the
                # service. This is the value that matters: if the sensor service's
                # effective end is well below 0xFFFF (i.e. it is followed by the
                # placeholder service), the DUT's per-service char discovery has a
                # bounded range to walk - the whole point of the placeholder fix.
                attr_handles = []
                for ch in chars:
                    for attr in getattr(ch, "attributes", []) or []:
                        h = getattr(attr, "handle", None)
                        if isinstance(h, int):
                            attr_handles.append(h)
                effective_end = _hx(max(attr_handles)) if attr_handles else "?"
                logger().info(
                    f"nRF {idx+1}:   service uuid={svc_uuid} nrf_type={uuid_type} "
                    f"start_handle={_hx(start_h)} end_handle={_hx(end_h)} "
                    f"effective_end={effective_end} "
                    f"(type 1 = 16-bit SIG, >1 = 128-bit vendor)"
                )
                for ch in chars:
                    ch_uuid = getattr(ch, "uuid", ch)
                    props = getattr(ch, "properties", None)
                    value_attr = getattr(ch, "_value_attr", None)
                    vh = getattr(value_attr, "handle", "?") if value_attr is not None else "?"
                    cccd_attr = getattr(ch, "_cccd_attr", None)
                    cccd = getattr(cccd_attr, "handle", None) if cccd_attr is not None else None
                    logger().info(
                        f"nRF {idx+1}:     char uuid={ch_uuid} value_handle={_hx(vh)} "
                        f"cccd_handle={_hx(cccd) if cccd is not None else 'none'} props={props}"
                    )
        except Exception as e:
            logger().info(f"nRF {idx+1}: server database dump failed (non-fatal): {e}")

    def _stop_dut_adv_scan(self, reason=""):
        """Stop ALL DUT advertising and scanning so no stale radio activity leaks
        between test cases.

        The DUT advertises (peripheral role, for phone connections) and scans
        (central role, for sensor connections). If either is left running when the
        next test starts, a fresh advertising start is rejected by the firmware
        ("already advertising") - which silently breaks every peripheral (phone)
        connection in the new test while the central (sensor) connections still work.

        Each stop is issued independently and guarded so a single failure (or an API
        that is a no-op in the current state) never aborts the rest.
        """
        wifi = self.wifi_dut.interfaces.wifi
        label = f" ({reason})" if reason else ""
        logger().info(f"Stopping DUT advertising and scanning{label}...")
        for desc, call in (
            ("legacy_scan_stop", wifi.legacy_scan_stop),
            ("stop_scan", wifi.stop_scan),
            ("stop_adv", wifi.stop_adv),
        ):
            try:
                call()
                time.sleep(1)
            except Exception as e:
                logger().warning(f"  DUT {desc}: {e}")

    def _start_dut_adv_scan(self):
        """Start DUT advertising once for THIS test (scanning is handled separately).

        Advertising is issued with a SINGLE ``legacy_adv`` call (no retries / no repeat
        starts). The firmware owns the advertising scenario (fast/slow intervals,
        connectable vs non-connectable, etc.). ``own_addr_type`` follows the configured
        address mode (0 = public, 1 = random).

        On the very first test the DUT is already advertising from boot, so this call may
        be a no-op / report 'already advertising' - that is fine, the boot advertising
        keeps the DUT discoverable. Advertising is stopped exactly once in _cleanup.

        DUT scanning is deliberately NOT started here. Scan (observer) reports flood the
        serial log and make it impossible to track when a connection actually forms, and
        a connect issued while an observer scan is running can be rejected by the firmware
        (0x4e0c). Scanning is therefore kept OFF during connection establishment
        (phases 1-3) and only turned on - once - during the data-transfer monitor phase
        when the scenario requests it (``ble_scanning``). See _resume_dut_scan /
        _pause_dut_scan.
        """
        wifi = self.wifi_dut.interfaces.wifi
        own_addr_type = 1 if self.use_random_address else 0
        direct_addr = self.target_address if self.use_random_address else "00:00:00:00:00:00"

        try:
            wifi.legacy_adv(status=1, own_addr_type=own_addr_type, direct_addr=direct_addr)
            logger().info(f"DUT advertising started (own_addr_type={own_addr_type}).")
        except Exception as e:
            logger().warning(
                f"DUT legacy_adv start warning: {e} (on the first test the DUT is "
                f"already advertising from boot, so this can be ignored)."
            )
        time.sleep(2)

        # Ensure no stale observer scan is left running from boot / a previous test
        # while we establish connections. This keeps the connection logs clean.
        self._pause_dut_scan(reason="connection establishment - keep logs clean")

    def _pause_dut_scan(self, reason=""):
        """Stop ONLY the DUT observer scan (advertising is left untouched).

        Used to silence the flood of scan/advertising reports in the DUT serial log
        while a connection is being established, and to avoid the firmware's 0x4e0c
        'command disallowed' error that can occur when a connect is issued while an
        observer scan is active. Paired with :meth:`_resume_dut_scan`. Each stop is
        guarded so a no-op (scan already stopped) never aborts the caller.
        """
        wifi = self.wifi_dut.interfaces.wifi
        label = f" ({reason})" if reason else ""
        logger().info(f"Pausing DUT scanning{label}...")
        for desc, call in (
            ("legacy_scan_stop", wifi.legacy_scan_stop),
            ("stop_scan", wifi.stop_scan),
        ):
            try:
                call()
                time.sleep(0.5)
            except Exception as e:
                logger().debug(f"  DUT {desc}: {e}")

    def _resume_dut_scan(self, reason=""):
        """Start the DUT observer scan with a SINGLE ``legacy_scan`` call.

        Mirrors :meth:`_pause_dut_scan`; called once the connection window is over so
        scanning resumes (only when the scenario enables ``ble_scanning``).
        """
        wifi = self.wifi_dut.interfaces.wifi
        label = f" ({reason})" if reason else ""
        try:
            wifi.legacy_scan(
                scan_type=1, scan_int=self.SCAN_INTERVAL, scan_win=self.SCAN_WINDOW
            )
            logger().info(f"DUT scanning (re)started{label}.")
        except Exception as e:
            logger().warning(f"DUT legacy_scan start warning: {e}")
        time.sleep(1)

    def _initialize_dut(self):
        """Initialize DUT BLE stack and retrieve dynamic address."""
        logger().info("\n\n **** set sleep to initialize dut ****\n\n")

        # DUT SAPI/BLE error codes hard-fail by default. For this 8+2 concurrent
        # scenario we deliberately switch to log-only so a single command error does
        # not abort the run - we need the full 5-minute outcome for all 10 links, and
        # the error codes are still surfaced (at ERROR) and mapped to their yaml
        # descriptions for post-run analysis.
        try:
            self.wifi_dut.interfaces.wifi.set_sapi_error_handling(hard_fail=False)
        except AttributeError:
            logger().debug("DUT interface has no set_sapi_error_handling(); skipping.")
        except Exception as e:
            logger().warning(f"Could not set SAPI error handling to log-only: {e}")

        time.sleep(20)

        # Initialize SMP pairing on DUT:
        #   io_capability -> configurable per test scenario
        #   auth_req=0x09 -> Bonding + LE Secure Connections -> triggers LTK generation
        try:
            self.wifi_dut.interfaces.wifi.set_smp_pairing_capability_data(
                io_capability=self.io_capability,
                auth_req=0x09
            )
        except Exception as e:
            logger().warning(f"set_smp_pairing_capability_data warning: {e}")
        time.sleep(15)  # Allow DUT BLE stack to fully initialize

        # Advertising is managed as a single start / single stop, like the firmware does
        # on boot. We do NOT stop it here: on the very first test the DUT is already
        # advertising from boot, and stopping before our single (re)start (which the
        # firmware can reject right after a stop) would leave the DUT non-discoverable.
        # Advertising is started exactly once below (_start_dut_adv_scan) and stopped
        # exactly once in _cleanup. Scanning is intentionally kept OFF during connection
        # setup and only (re)started during the data-transfer monitor phase.
        wifi = self.wifi_dut.interfaces.wifi

        self.target_address = get_dut_address(self.wifi_dut)
        logger().info(f"DUT BLE address (public): {self.target_address}")

        # Set random BLE address on DUT if requested. Changing the address requires
        # advertising to be off, so this is the one place (random scenarios only) where
        # we stop advertising before the single legacy_adv start below.
        if self.use_random_address:
            random_addr = self.RANDOM_DUT_ADDRESS
            logger().info(f"Setting DUT to use random address: {random_addr}")
            try:
                wifi.stop_adv()
                time.sleep(2)
                wifi.set_random_address(bd_addr=random_addr)
                time.sleep(2)
                self.target_address = random_addr
                logger().info(f"DUT random address set. Using {self.target_address} for connections.")
            except Exception as e:
                logger().error(f"Failed to set random address: {e}. Continuing with public address.")

        # Start advertising fresh for this test case (single legacy_adv); the firmware
        # owns the advertising scenario. Scanning stays OFF until the monitor phase.
        self._start_dut_adv_scan()

        time.sleep(2)

    # =========================================================================
    # HELPER FUNCTIONS
    # =========================================================================

    # Column headers for the DUT's per-connection BLE legacy packet stats table.
    PKT_STATS_HEADERS = [
        "Slave_id", "State", "Conn_evts", "Data_frm", "Data_sent",
        "Empty_snt", "Data_rcvd", "Retry_snt", "Sch_Fail", "Rx_Tout"
    ]

    def _parse_pkt_stats_rows(self, raw_text):
        """Parse raw BLE legacy packet stats text into (headers, data_rows).

        Returns the column headers and a list of per-connection rows (each a list
        of string column values). Shared by the log formatter and the Excel writer.
        """
        HEADERS = self.PKT_STATS_HEADERS
        if isinstance(raw_text, str):
            lines = raw_text.replace('\\n', '\n').split('\n')
        elif isinstance(raw_text, (list, tuple)):
            lines = []
            for item in raw_text:
                s = item if isinstance(item, str) else str(item)
                lines.extend(s.replace('\\n', '\n').split('\n'))
        else:
            return HEADERS, []

        data_rows = []
        for line in lines:
            text = line.strip()
            if not text or text.startswith('---') or 'BLE_Legacy_Stats' in text or 'BLE Legacy Stats' in text:
                continue
            if 'Slave_id' in text:
                continue
            if 'received data' in text or 'pkt stats' in text.lower() or 'btc ble' in text:
                continue
            cols = [c.strip() for c in text.split('|')]
            if len(cols) >= len(HEADERS):
                try:
                    int(cols[0])
                    int(cols[1])
                    data_rows.append(cols[:len(HEADERS)])
                except ValueError:
                    continue
        return HEADERS, data_rows

    def _format_pkt_stats_table(self, raw_text):
        """Parse raw BLE legacy packet stats text into a clean, formatted table."""
        HEADERS, data_rows = self._parse_pkt_stats_rows(raw_text)

        if not data_rows:
            return ["  (no stats data)"]

        active_rows = [r for r in data_rows if r[1] != '0']
        display_rows = active_rows if active_rows else data_rows
        col_widths = [len(h) for h in HEADERS]
        for row in display_rows:
            for ci, val in enumerate(row):
                col_widths[ci] = max(col_widths[ci], len(val))

        def fmt_row(values):
            return " | ".join(v.rjust(col_widths[ci]) for ci, v in enumerate(values))

        output = []
        output.append(fmt_row(HEADERS))
        output.append("-+-".join("-" * col_widths[ci] for ci in range(len(HEADERS))))
        for row in display_rows:
            output.append(fmt_row(row))
        output.append("-+-".join("-" * col_widths[ci] for ci in range(len(HEADERS))))
        total_active = len(active_rows)
        total_connections = len(data_rows)
        output.append(f"Active connections: {total_active}/{total_connections}")
        return output

    def _extract_latest_stats_from_log(self, log_start_index=0):
        """Extract the most recent BLE_Legacy_Stats table from DUT serial log."""
        try:
            serial_conn = self.wifi_dut.interfaces.wifi.bus
            input_log = serial_conn.get_input_log()
            new_index = len(input_log)
            new_entries = input_log[log_start_index:]

            combined = ""
            for _, line in new_entries:
                try:
                    decoded = line.decode(errors="ignore") if isinstance(line, bytes) else str(line)
                except Exception:
                    decoded = str(line)
                combined += decoded + "\n"

            STATS_HEADER = 'BLE_Legacy_Stats(per_connection):'
            positions = []
            start = 0
            while True:
                pos = combined.find(STATS_HEADER, start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + 1

            if not positions:
                return None, new_index

            for pos in reversed(positions):
                block = combined[pos:]
                sep_count = 0
                end_pos = 0
                for match in re.finditer(r'-{3,}\|', block):
                    sep_count += 1
                    if sep_count >= 2:
                        end_pos = match.end() + 50
                        break
                if end_pos > 0:
                    table_text = block[:end_pos]
                else:
                    table_text = block[:2000]

                if re.search(r'\|\s+1\s+\|', table_text):
                    return table_text, new_index

            block = combined[positions[-1]:]
            return block[:2000], new_index

        except Exception as e:
            logger().warning(f"Error extracting stats from serial log: {e}")
            return None, log_start_index

    def _get_current_log_length(self):
        """Get current DUT serial log length to use as snapshot for LTK detection."""
        try:
            serial_conn = self.wifi_dut.interfaces.wifi.bus
            return len(serial_conn.get_input_log())
        except Exception:
            return 0

    def _wait_for_ltk_in_logs(self, device_label, timeout=30, log_start_index=0):
        """Wait for a NEW LTK generation in DUT serial logs."""
        try:
            serial_conn = self.wifi_dut.interfaces.wifi.bus
        except Exception:
            return False
        LTK_BANNER_PATTERN = re.compile(r'\*{5,}.*?LE\s+LTK', re.DOTALL)
        for _ in range(timeout):
            input_log = serial_conn.get_input_log()
            new_entries = input_log[log_start_index:]
            combined = ""
            for _, line in new_entries:
                try:
                    decoded = line.decode(errors="ignore")
                except Exception:
                    decoded = str(line)
                combined += decoded + "\n"
            if LTK_BANNER_PATTERN.search(combined):
                ltk_hex = re.search(r'LE\s+LTK\s*\n\s*([0-9a-f]{2}[\s][0-9a-f]{2}.*)', combined)
                if ltk_hex:
                    logger().info(f"LTK confirmed for {device_label}: {ltk_hex.group(1).strip()[:80]}")
                else:
                    logger().info(f"LTK confirmed for {device_label} (banner pattern matched)")
                return True
            if "device disconnected" in combined.lower() or "restarted advertising" in combined.lower():
                logger().warning(f"Disconnect/restart detected in logs while waiting for LTK ({device_label}).")
                return False
            time.sleep(1)
        logger().warning(f"Timeout waiting for LTK generation for {device_label}.")
        return False

    def _dut_char_notif_key(self):
        """Canonical key under which the nrf_blatann wrapper records notifications
        received from the DUT characteristic.

        The wrapper's notification callback stores values under
        ``str(characteristic.uuid)``, which for the 16-bit DUT data characteristic
        is the lowercase 4-hex string (e.g. "1aa1"). We must use this exact key
        when seeding and reading the notifications dict so the keys match.
        """
        return f"{self.DUT_CHAR_UUID_16:04x}"

    @staticmethod
    def _nrf_addr_type(addr):
        """Return the BLE peer address type for req_legacy_connect.

        nRF dongles advertise with a random *static* address by default, whose
        two most-significant bits of the MSB are both 1. The DUT must be told to
        connect using the random address type (1); using public (0) makes the
        controller hunt for an address that does not exist and the connection
        never forms. Returns 1 (random) for static/private random addresses,
        else 0 (public).
        """
        try:
            msb = int(str(addr).split(":")[0], 16)
            # Random address: top bits 0b11 (static) or 0b01/0b00 (private).
            # Public IEEE addresses are the only ones we treat as type 0; any
            # address whose top two bits are set is unambiguously random static.
            return 1 if (msb & 0xC0) != 0x00 else 0
        except Exception:
            # Safest default for nRF dongles is random.
            return 1

    def _connect_add_type(self, idx, addr):
        """Return the add_type to pass to req_legacy_connect for sensor ``idx``.

        Prefers the dev_addr_type recorded when we forced the dongle's address
        (0=public), so the DUT connects with the address type the nRF is actually
        advertising. Falls back to inferring from the address bytes when unknown.
        """
        recorded = self.nrf_addr_types[idx] if self.nrf_addr_types else None
        if recorded is not None:
            return recorded
        return self._nrf_addr_type(addr)

    def _connect_peripheral(self, idx):
        """Connect DUT (central) to an nRF dongle (peripheral) with GARMIN sensor parameters.

        Flow: nRF advertises (GATT server already built) -> req_legacy_connect with
              CI/LSTO params (DUT observer scan is kept OFF during connection setup so
              the logs stay clean and the firmware does not reject the connect with
              0x4e0c) -> poll nRF get_connection_status(DUT).
        """
        nrf_ble = self.nrf_bles[idx]
        try:
            # Re-advertise the SIG service UUID(s) the sensor hosts (e.g. 0x180D).
            # This call overwrites the PHASE 1 advertising data, so it MUST also
            # include the service UUID - otherwise the DUT (central) sees a
            # name-only advert and its rx_notifications GATT discovery fails
            # ("service not found").
            spec = self._standard_sensor_service_spec(self._get_effective_mode(idx))
            adv_service_uuids = [svc["uuid"] for svc in spec["services"]]
            nrf_addr = nrf_ble.start_advertising(
                local_name=f"NRF_SENSOR_{idx+1}",
                timeout_sec=0,
                auto_restart=True,
                service_uuid16s=adv_service_uuids,
            )
            self.nrf_addrs[idx] = nrf_addr
            logger().info(
                f"nRF {idx+1} advertising: {nrf_addr} "
                f"(services={', '.join('0x%04X' % u for u in adv_service_uuids)})"
            )
            time.sleep(2)

            # Determine HT vs LT connection parameters
            if self.num_ht_central > 0 and idx < self.num_ht_central:
                ci_min, ci_max = self.ht_sensor_ci_min, self.ht_sensor_ci_max
                lsto, latency = self.HT_SENSOR_LSTO, self.HT_SENSOR_LATENCY
                min_ce, max_ce = self.HT_SENSOR_MIN_CE, self.HT_SENSOR_MAX_CE
                sensor_type = "High Throughput"
            else:
                ci_min, ci_max = self.LT_SENSOR_CI_MIN, self.LT_SENSOR_CI_MAX
                lsto, latency = self.LT_SENSOR_LSTO, self.LT_SENSOR_LATENCY
                min_ce, max_ce = self.LT_SENSOR_MIN_CE, self.LT_SENSOR_MAX_CE
                sensor_type = "Low Throughput"

            log_snapshot = self._get_current_log_length()
            add_type = self._connect_add_type(idx, nrf_addr)
            logger().info(f"DUT connecting to nRF {idx+1} ({nrf_addr}) as {sensor_type} "
                          f"CI={ci_min*1.25:.0f}-{ci_max*1.25:.0f}ms, LSTO={lsto*10}ms, "
                          f"CE_len={min_ce*0.625:.2f}-{max_ce*0.625:.2f}ms, "
                          f"add_type={add_type} ({'random' if add_type else 'public'})")
            self.wifi_dut.interfaces.wifi.req_legacy_connect(
                dev_addr=nrf_addr,
                add_type=add_type,
                conn_interval_min=ci_min,
                conn_interval_max=ci_max,
                conn_latency=latency,
                supervision_tout=lsto,
                min_ce_length=min_ce,
                max_ce_length=max_ce
            )

            # Poll nRF-side connection status
            deadline = time.time() + self.SENSOR_CONNECT_TIMEOUT
            connected = False
            while time.time() < deadline:
                try:
                    if nrf_ble.get_connection_status(self.target_address):
                        connected = True
                        break
                except Exception:
                    pass
                time.sleep(2)

            if connected:
                time.sleep(5)
                ltk_ok = self._wait_for_ltk_in_logs(
                    f"nRF {idx+1} (sensor)", timeout=30, log_start_index=log_snapshot
                )
                if not ltk_ok:
                    logger().warning(f"LTK not confirmed for nRF {idx+1}, proceeding anyway.")
                return True
            else:
                logger().error(f"nRF {idx+1}: connection did not form within "
                               f"{self.SENSOR_CONNECT_TIMEOUT}s")
                self.connection_errors[idx] = "Connection timeout"
                return False
        except Exception as e:
            logger().error(f"Failed to connect to nRF {idx+1} (sensor): {e}")
            self.connection_errors[idx] = str(e)
            return False

    def _connect_central(self, idx):
        """Connect an nRF dongle (central) to the DUT (peripheral) with GARMIN phone params.

        Flow: nRF scans -> discovers DUT -> connects -> SMP pairing -> discover
              services -> subscribe to DUT data characteristic. Then apply
              conn_param_update + set_phy(2M) from the DUT side.
        Returns True on success.
        """
        nrf_ble = self.nrf_bles[idx]
        try:
            log_snapshot = self._get_current_log_length()
            nrf_addr = nrf_ble.get_ble_address()
            self.nrf_addrs[idx] = nrf_addr
            logger().info(f"nRF {idx+1} (phone) BLE address: {nrf_addr}")

            # Scan for the DUT (blocking scan). The scan also exposes the nRF's own
            # GATT server services to the peer that connects - so the DUT (which is
            # the peripheral here) can discover the nRF's data service. We pass the
            # nRF's hosted service UUID(s) so the scan call verifies the server is
            # actually standing before we connect.
            host_spec = self._standard_sensor_service_spec(self._get_effective_mode(idx))
            host_service_uuids = [svc["uuid"] for svc in host_spec["services"]]
            nrf_ble.set_default_scan_params(timeout_seconds=self.SCAN_TIMEOUT)
            logger().info(
                f"nRF {idx+1} (phone/central) scanning to discover DUT "
                f"(exposing host services {', '.join('0x%04X' % u for u in host_service_uuids)})..."
            )
            nrf_ble.start_scanning(host_service_uuid16s=host_service_uuids)
            found_devices = nrf_ble.get_devices()
            try:
                nrf_ble.stop_scanning()
            except Exception:
                pass
            logger().info(f"Devices scanned by nRF {idx+1}: {found_devices}")

            # Assert the DUT was actually discovered by the nRF's scan before connecting.
            dut_found = any(self.target_address.upper() == str(dev).upper() for dev in found_devices)
            if not dut_found:
                logger().error(
                    f"nRF {idx+1}: DUT {self.target_address} NOT found in scan results "
                    f"(found: {list(found_devices)})"
                )
                self.connection_errors[idx] = "DUT not found in scan results"
                return False
            logger().info(f"nRF {idx+1}: DUT {self.target_address} confirmed found in scan results")

            # Use Garmin phone connection params (ms)
            try:
                nrf_ble.set_connection_parameters(
                    int(self.PHONE_CI_MIN * 1.25),
                    int(self.PHONE_CI_MAX * 1.25),
                    self.PHONE_LSTO * 10,
                    self.PHONE_LATENCY,
                )
            except Exception as e:
                logger().warning(f"nRF {idx+1}: set_connection_parameters warning: {e}")

            logger().info(f"nRF {idx+1} (phone) connecting to DUT ({self.target_address})...")
            conn = nrf_ble.connect(self.target_address)
            if conn is None:
                logger().error(f"nRF {idx+1} (phone): connect() returned no handle")
                self.connection_errors[idx] = "nRF connect() failed"
                return False

            # CRITICAL: the DUT (peripheral) auto-initiates SMP pairing within ~1s
            # of the link forming. The nRF central MUST have its peer security
            # params configured BEFORE that request arrives, otherwise the DUT
            # reports "SMP failed ... status 4b05" and disconnects (0x4e16).
            # Set security params and kick off pairing immediately - do NOT sleep
            # or gate this behind a connection-status check first.
            try:
                nrf_ble.set_peer_security_params(
                    self.target_address,
                    passcode_pairing=False,
                    io_capabilities=self.nrf_io_capability,
                    lesc_pairing=True,
                    long_term_bonding=True,
                )
            except Exception as e:
                logger().warning(f"nRF {idx+1}: set_peer_security_params warning: {e}")

            try:
                nrf_ble.pair(self.target_address)
            except Exception as e:
                logger().warning(f"nRF {idx+1}: pairing warning: {e}")

            # Now confirm the link survived pairing.
            time.sleep(2)
            if not nrf_ble.get_peer_connection_status(self.target_address):
                logger().error(f"nRF {idx+1} (phone): peer disconnected during/after pairing")
                self.connection_errors[idx] = "peer disconnected during pairing (check SMP status in DUT log)"
                return False

            # Wait for LTK in DUT logs
            ltk_ok = self._wait_for_ltk_in_logs(f"nRF {idx+1} (phone)", timeout=30, log_start_index=log_snapshot)
            if not ltk_ok:
                logger().warning(f"LTK not confirmed for nRF {idx+1} (phone), proceeding anyway.")

            # Apply GARMIN phone connection parameters from DUT side
            logger().info(f"nRF {idx+1}: Applying conn_param_update (CI=90ms, LSTO=4s, Latency=4)...")
            try:
                self.wifi_dut.interfaces.wifi.conn_param_update(
                    dev_addr=nrf_addr,
                    min_interval=self.PHONE_CI_MIN,
                    max_interval=self.PHONE_CI_MAX,
                    latency=self.PHONE_LATENCY,
                    timeout=self.PHONE_LSTO
                )
                time.sleep(2)
            except Exception as e:
                logger().warning(f"nRF {idx+1}: conn_param_update warning: {e}")

            # Set PHY to 2M for phone connections (Garmin requirement). The PHY is a
            # negotiated, per-connection property, so we drive it from BOTH ends: the
            # DUT requests 2M, and the nRF (GAP-central here) also initiates the PHY
            # update so the rate change does not rely on one side passively accepting.
            logger().info(f"nRF {idx+1}: Setting PHY to 2M...")
            try:
                self.wifi_dut.interfaces.wifi.set_phy(
                    ble_address=nrf_addr,
                    tx_phy=2,
                    rx_phy=2,
                    coded_phy=0
                )
                time.sleep(2)
            except Exception as e:
                logger().warning(f"nRF {idx+1}: set_phy(2M) warning: {e}")
            try:
                nrf_ble.update_phy("2M")
                time.sleep(1)
            except Exception as e:
                logger().warning(f"nRF {idx+1}: nRF-side update_phy(2M) warning: {e}")

            logger().info(f"nRF {idx+1}: CI=90ms, LSTO=4s, Latency=4, PHY=2M applied")
            return True
        except Exception as e:
            logger().error(f"Failed to connect nRF {idx+1} (phone) to DUT: {e}")
            self.connection_errors[idx] = str(e)
            return False

    def _setup_gatt_and_start_transfer(self, idx):
        """Resolve GATT (client side for phones), configure DUT data pattern, and start
        RX/TX data transfer threads for one device."""
        stop_event = self.data_transfer_stop_events[idx]
        stop_event.clear()
        is_sensor = idx < self.num_central_connections
        try:
            # Both phones AND sensors run as a GATT *client* of the DUT: the nRF
            # discovers the DUT's data characteristic, subscribes to it (TX: DUT->nRF)
            # and writes to it (RX: nRF->DUT). This is the path that works for phones,
            # and it sidesteps the DUT limitation where it cannot discover the
            # nRF's own GATT server. For a sensor the nRF is the GAP peripheral, so the
            # connected central (the DUT) is exposed as ``ble_device.client`` - point the
            # wrapper's peer at it so the same client helpers operate over that link.
            nrf_ble = self.nrf_bles[idx]
            if is_sensor:
                client_peer = getattr(getattr(nrf_ble, "ble_device", None), "client", None)
                if client_peer is None:
                    logger().error(f"nRF {idx+1}: no client peer (DUT) available for GATT-client "
                                   f"setup. Marking NOT connected.")
                    self.connection_errors[idx] = "No client peer for sensor GATT-client setup"
                    return False
                # Route the wrapper's client helpers (discover/find/subscribe/write)
                # over the DUT->nRF connection.
                nrf_ble.peer_device = client_peer

            resolved = False
            for attempt in range(1, 6):
                try:
                    nrf_ble.discover_services()
                    time.sleep(3)
                    svc = nrf_ble.find_service(service_uuid=nrf_ble.get_blatann_uuid(self.DUT_SERVICE_UUID_16))
                    char = nrf_ble.find_characteristic(characteristic_uuid=self.dut_char_uuids[idx])
                    if svc is not None and char is not None:
                        resolved = True
                        break
                except Exception as e:
                    logger().warning(f"nRF {idx+1} GATT discover attempt {attempt}/5: {e}")
                time.sleep(3)
            if not resolved:
                logger().error(f"nRF {idx+1}: could not resolve DUT data characteristic "
                               f"0x{self.DUT_CHAR_UUID_16:04X}. Marking NOT connected.")
                self.connection_errors[idx] = "GATT resolution failed - DUT characteristic not found"
                return False
            # Subscribe to DUT notifications (TX: DUT -> nRF)
            try:
                nrf_ble.subscribe_to_notifications(characteristic_uuid=self.dut_char_uuids[idx])
                time.sleep(2)
            except Exception as e:
                logger().warning(f"nRF {idx+1}: subscribe_to_notifications warning: {e}")
            # The nrf_blatann wrapper stores incoming notifications under
            # str(characteristic.uuid) (e.g. "1aa1") but subscribe_to_notifications
            # keys the dict by the BlatannUuid16 *object* we pass. That mismatch makes
            # the notification callback raise KeyError and silently drop every packet
            # the DUT sends. Seed the dict with the canonical string key so received
            # notifications are recorded (and read back with the same key below).
            try:
                nrf_ble.notifications.setdefault(self._dut_char_notif_key(), [])
            except Exception as e:
                logger().warning(f"nRF {idx+1}: notification key seed warning: {e}")
            logger().info(f"nRF {idx+1} GATT client setup complete (subscribed to DUT char).")

            # Configure DUT data pattern
            self._configure_dut_data_pattern(idx)

            # Start per-device data transfer threads
            self._start_data_transfer_threads(idx, stop_event)
            logger().info(f"Data transfer started for nRF {idx+1} (mode: {self._get_effective_mode(idx)})")
            return True
        except Exception as e:
            logger().error(f"Failed to setup GATT / start data transfer for nRF {idx+1}: {e}")
            self.connection_errors[idx] = str(e)
            return False

    def _configure_dut_data_pattern(self, idx):
        """Configure the DUT's data pattern engine for one connection.

        Bidirectional data transfer for the mode under test, keyed on the transfer
        *mode* only (not the sensor/phone GAP role):

            - notification:  rx_notifications=1, tx_notifications=1
                             RX (peer -> DUT): DUT subscribes to peer 0x2A37 and receives.
                             TX (DUT -> peer): DUT notifies its char; peer subscribes & reads.
            - indication:    rx_indications=1, tx_indications=1   (peer 0x2A1C)
            - write modes:   tx_write=1

        NOTE: rx_notifications=1 is REQUIRED so the DUT writes the peer's CCCD and the
        nRF (blatann) will actually send notifications - blatann refuses to notify a
        client that has not subscribed.
        """
        is_sensor = idx < self.num_central_connections
        mode = self._get_effective_mode(idx)
        ble_addr = self.nrf_addrs[idx] if self.nrf_addrs[idx] else self.target_address
        buf_mode, buf_cnt, max_data = self._get_dle_params(idx, is_sensor)

        logger().info(f"nRF {idx+1}: set_data_pattern - ble_addr={ble_addr}, mode={mode}, "
                      f"buf_mode={buf_mode}, buf_cnt={buf_cnt}, max_data={max_data}")
        try:
            kwargs = dict(ble_address=ble_addr,
                          buffer_mode=buf_mode, buffer_cnt=buf_cnt, max_data_length=max_data)
            if mode == self.MODE_INDICATION:
                kwargs["rx_indications"] = 1
                kwargs["tx_indications"] = 1
            elif mode == self.MODE_NOTIFICATION:
                kwargs["rx_notifications"] = 1
                kwargs["tx_notifications"] = 1
            else:
                # write-with-response / write-without-response
                kwargs["tx_write"] = 1
            self.wifi_dut.interfaces.wifi.set_data_pattern(**kwargs)
        except Exception as e:
            logger().warning(f"nRF {idx+1}: set_data_pattern warning (may need firmware-specific flags): {e}")

    def _get_effective_mode(self, idx):
        """Get the effective data transfer mode for a given connection index."""
        if idx < self.num_central_connections:
            return self.central_data_transfer_mode
        else:
            return self.peripheral_data_transfer_mode

    def _get_dle_params(self, idx, is_sensor):
        """Get DLE buffer_mode, buffer_cnt, max_data_length for a connection.

        Applies Garmin DLE rules:
          - Sensors (DLE OFF): buffer_mode=0, buffer_cnt=3, max_data=20
          - Phones  (DLE ON):  buffer_mode=1, buffer_cnt=2, max_data=232

        Overrides based on self.dle_enabled:
          - True:              DLE ON for ALL connections
          - False/None:        Default Garmin behavior (sensor OFF, phone ON)
          - "ht_only":         DLE ON only for HT sensors
          - "disabled_central": DLE OFF for all centrals/sensors, ON for phones
        """
        if is_sensor:
            buf_mode = self.SENSOR_BUFFER_MODE
            buf_cnt = self.SENSOR_BUFFER_COUNT
            max_data = self.sensor_max_data_len

            if self.dle_enabled is True:
                buf_mode = self.PHONE_BUFFER_MODE
                buf_cnt = self.PHONE_BUFFER_COUNT
                max_data = self.PHONE_MAX_DATA_LEN
            elif self.dle_enabled == "ht_only":
                if self.num_ht_central > 0 and idx < self.num_ht_central:
                    buf_mode = self.PHONE_BUFFER_MODE
                    buf_cnt = self.PHONE_BUFFER_COUNT
                    max_data = self.PHONE_MAX_DATA_LEN
            elif self.dle_enabled == "disabled_central":
                pass
        else:
            buf_mode = self.PHONE_BUFFER_MODE
            buf_cnt = self.PHONE_BUFFER_COUNT
            max_data = self.PHONE_MAX_DATA_LEN

            if self.dle_enabled is False:
                buf_mode = self.SENSOR_BUFFER_MODE
                buf_cnt = self.SENSOR_BUFFER_COUNT
                max_data = self.sensor_max_data_len

        return buf_mode, buf_cnt, max_data

    def _get_data_size_for_connection(self, idx):
        """Get the payload data size for a given connection index."""
        if idx < self.num_central_connections:
            if self.num_ht_central > 0 and idx < self.num_ht_central:
                return self.ht_data_size
            else:
                return self.lt_data_size
        else:
            return self.data_size

    def _get_ci_range_ms_for_connection(self, idx):
        """Return the configured (ci_min_ms, ci_max_ms) for connection ``idx``.

        Connection-interval values are stored in 1.25 ms controller units, so they
        are scaled here for human-readable reporting. The negotiated CI lands within
        this range; the expected connection-event rate is ~1000/CI events per second.
        """
        if idx < self.num_central_connections:
            if self.num_ht_central > 0 and idx < self.num_ht_central:
                return self.ht_sensor_ci_min * 1.25, self.ht_sensor_ci_max * 1.25
            return self.LT_SENSOR_CI_MIN * 1.25, self.LT_SENSOR_CI_MAX * 1.25
        return self.PHONE_CI_MIN * 1.25, self.PHONE_CI_MAX * 1.25

    def _get_expected_throughput(self, idx, conn_type):
        """Return the plan's expected (rx_pps, tx_pps, rx_Bps, tx_Bps) for a connection.

        Looks up the Garmin 8+2 plan targets by sensor density (5- vs 8-sensor) and
        connection type. Returns None for phone connections (no plan target).
        """
        density = "high" if self.is_high_density else "low"
        return self.EXPECTED_THROUGHPUT.get(density, {}).get(conn_type)

    def _throughput_status(self, observed, expected):
        """Compare observed vs the plan's expected value -> 'OK (NN%)' / 'LOW (NN%)'.

        NOTE: the host-side pps/B/s is paced by the data-transfer worker loop, so it
        can read LOW even when the radio link is healthy - the DUT per-CE table is the
        authoritative throughput view. This status is a quick plan-comparison aid.
        """
        if not expected:
            return ""
        pct = (observed / expected) * 100.0
        label = "OK" if observed >= expected * self.THROUGHPUT_OK_FRACTION else "LOW"
        return f"{label} ({pct:.0f}%)"

    def _evaluate_throughput(self, throughput_data):
        """Evaluate observed vs plan-expected throughput for every sensor connection.

        Pass criteria (per the Garmin 8+2 plan): a sensor connection PASSES when both
        its observed RX and TX packet rate (pps) are at least THROUGHPUT_OK_FRACTION of
        the plan target for its type/density. Phone (peripheral) connections have no
        plan target and are reported as informational only.

        Returns (overall_pass, results, failures):
            results  - one dict per evaluated sensor connection (for the report sheet)
            failures - human-readable strings describing each shortfall / dead link
        """
        tol = self.THROUGHPUT_OK_FRACTION
        results = []
        failures = []
        for i in range(self.num_devices):
            td = throughput_data[i]
            if td['exp_rx_pps'] is None:
                continue  # phone / no plan target
            rx_obs, tx_obs = td['rx_pps'], td['tx_pps']
            rx_exp, tx_exp = td['exp_rx_pps'], td['exp_tx_pps']
            rx_req, tx_req = rx_exp * tol, tx_exp * tol
            connected = bool(self.connection_success[i])
            rx_ok = connected and rx_obs >= rx_req
            tx_ok = connected and tx_obs >= tx_req
            conn_pass = rx_ok and tx_ok
            results.append({
                'device': i + 1,
                'conn_type': td['conn_type'],
                'rx_obs': rx_obs, 'rx_exp': rx_exp, 'rx_req': rx_req, 'rx_ok': rx_ok,
                'tx_obs': tx_obs, 'tx_exp': tx_exp, 'tx_req': tx_req, 'tx_ok': tx_ok,
                'connected': connected, 'pass': conn_pass,
            })
            if not connected:
                failures.append(
                    f"Device {i+1} ({td['conn_type']}): NOT CONNECTED (RX/TX=0 pps).")
                continue
            if not rx_ok:
                failures.append(
                    f"Device {i+1} ({td['conn_type']}): RX {rx_obs:.1f} pps < required "
                    f"{rx_req:.1f} pps (plan {rx_exp} pps).")
            if not tx_ok:
                failures.append(
                    f"Device {i+1} ({td['conn_type']}): TX {tx_obs:.1f} pps < required "
                    f"{tx_req:.1f} pps (plan {tx_exp} pps).")
        overall_pass = len(failures) == 0
        return overall_pass, results, failures

    def _assert_throughput(self):
        """Fail the test if the observed packet rate did not meet the plan (when
        enforcement is on).

        Pass/fail is packet-based only: each sensor connection must reach at least 90%
        of its plan RX and TX pps target. Runs after the report is written so the
        Excel/logs are always available for analysis even on failure. Controlled by
        ``enforce_throughput``.
        """
        if self.throughput_pass is None:
            return
        if self.throughput_pass:
            logger().info("PASS: all sensor connections met the plan packet-rate targets.")
            return
        summary = "; ".join(self.throughput_failures)
        msg = (f"Packet-rate below plan target on "
               f"{len(self.throughput_failures)} connection check(s): {summary}")
        if self.enforce_throughput:
            logger().error(f"TEST FAIL: {msg}")
            raise AssertionError(msg)
        logger().warning(f"TEST FAIL (not enforced): {msg}")

    def _format_pkt_stats_per_ce(self, raw_text):
        """Derive a per-connection-event (CE) view from a DUT BLE stats table.

        The host-side rx/tx counters are paced by the worker loop, so they cannot
        report the radio's true per-CE behaviour. The DUT's link-layer counters
        (Conn_evts, Data_sent, Data_rcvd) can: this returns one line per ACTIVE
        connection with packets-per-CE (sent + rcvd), which is exactly the metric the
        Garmin test plan compares against (~2 packets per CE for High Throughput).
        """
        _, data_rows = self._parse_pkt_stats_rows(raw_text)
        I_SLAVE, I_STATE, I_CE, I_SENT, I_RCVD = 0, 1, 2, 4, 6
        lines = []
        for row in data_rows:
            try:
                if row[I_STATE] == '0':
                    continue
                ce = int(row[I_CE])
                sent = int(row[I_SENT])
                rcvd = int(row[I_RCVD])
            except (ValueError, IndexError):
                continue
            sent_per_ce = sent / ce if ce else 0.0
            rcvd_per_ce = rcvd / ce if ce else 0.0
            lines.append(
                f"Slave {row[I_SLAVE]}: CE={ce} Data_sent={sent} Data_rcvd={rcvd} "
                f"-> {sent_per_ce:.2f} sent/CE, {rcvd_per_ce:.2f} rcvd/CE, "
                f"{(sent_per_ce + rcvd_per_ce):.2f} total/CE"
            )
        return lines or ["(no active connections in stats table)"]

    # Column indices in the DUT BLE_Legacy_Stats table.
    _S_SLAVE, _S_STATE, _S_CE, _S_SENT, _S_RCVD, _S_SCHFAIL = 0, 1, 2, 4, 6, 8

    def _accumulate_pkt_stats(self, raw_text):
        """Accumulate per-slave CE / Sch_Fail across Phase-4 stat snapshots.

        The DUT stat counters reset each print interval, so summing every polled snapshot
        yields cumulative connection-event and scheduler-failure totals for the whole run.
        These cumulative totals feed the connection-event-consistency pass/fail, which is
        far more reliable than a single 1-second snapshot.
        """
        _, rows = self._parse_pkt_stats_rows(raw_text)
        for row in rows:
            try:
                if row[self._S_STATE] == '0':
                    continue
                sid = str(row[self._S_SLAVE])
                ce = int(row[self._S_CE])
                sch = int(row[self._S_SCHFAIL])
                sent = int(row[self._S_SENT])
                rcvd = int(row[self._S_RCVD])
            except (ValueError, IndexError):
                continue
            acc = self._cum_pkt_stats.setdefault(
                sid, {'ce': 0, 'sch_fail': 0, 'sent': 0, 'rcvd': 0, 'samples': 0})
            acc['ce'] += ce
            acc['sch_fail'] += sch
            acc['sent'] += sent
            acc['rcvd'] += rcvd
            acc['samples'] += 1

    def _count_scan_activity_since(self, log_start_index):
        """Count DUT scan/advertising reports in new serial output since an index.

        Returns (num_scan_reports, new_index). Used during Phase 4 to make scanning /
        advertising activity explicit alongside the packet-stats poll, so the concurrent
        radio activity is observable in the stats-check log instead of being drowned out
        by the per-second stats tables.
        """
        try:
            serial_conn = self.wifi_dut.interfaces.wifi.bus
            input_log = serial_conn.get_input_log()
            new_index = len(input_log)
            scan = 0
            for _, line in input_log[log_start_index:]:
                try:
                    decoded = line.decode(errors="ignore") if isinstance(line, bytes) else str(line)
                except Exception:
                    decoded = str(line)
                scan += decoded.count("advertised details")
            return scan, new_index
        except Exception:
            return 0, log_start_index

    def _evaluate_connection_events(self):
        """Flag connections whose connection-event count is starved by scheduler failures.

        Uses the cumulative DUT stats (``self._cum_pkt_stats``). A slave FAILS when its
        scheduler-failure ratio Sch_Fail / (CE + Sch_Fail) exceeds SCHED_FAIL_MAX_RATIO -
        i.e. the DUT scheduler is dropping a significant fraction of its scheduled events,
        so its connection-event count is out of range vs its peers (the manual tester's
        "scheduler failing on a central connection -> fewer connection events" case).

        Returns (results, failures).
        """
        results = []
        failures = []

        def _sid_key(item):
            s = item[0]
            return (0, int(s)) if str(s).isdigit() else (1, str(s))

        for sid, acc in sorted(self._cum_pkt_stats.items(), key=_sid_key):
            ce = acc['ce']
            sch = acc['sch_fail']
            total = ce + sch
            ratio = (sch / total) if total else 0.0
            ok = ratio <= self.SCHED_FAIL_MAX_RATIO
            results.append({
                'slave': sid, 'ce': ce, 'sch_fail': sch,
                'ratio': ratio, 'ok': ok, 'samples': acc['samples'],
            })
            if not ok:
                failures.append(
                    f"Slave {sid}: scheduler dropped {ratio*100:.0f}% of events "
                    f"(cumulative CE={ce}, Sch_Fail={sch}) - connection events below peers.")
        return results, failures

    def _start_data_transfer_threads(self, idx, stop_event):
        """Start RX and TX threads for one connection (generic, mode-aware)."""
        rx_t = threading.Thread(
            target=self._rx_worker, args=(idx, stop_event),
            name=f"RX-{idx+1}", daemon=True
        )
        tx_t = threading.Thread(
            target=self._tx_worker, args=(idx, stop_event),
            name=f"TX-{idx+1}", daemon=True
        )
        rx_t.start()
        tx_t.start()
        self.data_transfer_threads[idx] = [rx_t, tx_t]

    # =========================================================================
    # DATA TRANSFER WORKERS
    # =========================================================================

    def _rx_worker(self, idx, evt):
        """RX direction: nRF -> DUT.

        Two paths, chosen by GAP role + transfer mode:

        * Sensor (DUT = central, nRF = peripheral) in notification/indication mode:
          the nRF *notifies/indicates* on its own GATT-server characteristic (0x2A37 /
          0x2A1C). The DUT, configured with ``rx_notifications=1`` (or
          ``rx_indications=1``), discovers that characteristic and subscribes to it, so
          this exercises the DUT's genuine "receive notifications/indications from peer"
          path. blatann is spec-strict and refuses to notify until the DUT has written
          the CCCD, so this worker waits for ``client_subscribed`` before sending.

        * Phone (DUT = peripheral, nRF = central) OR any write mode: the nRF acts as a
          GATT client and WRITES to the DUT's data characteristic (0x1AA1). This is the
          correct RX path when the DUT is the peripheral (the central writes to the
          DUT's char). Write modes are writes by definition regardless of role.
        """
        payload_size = self._get_data_size_for_connection(idx)
        mode = self._get_effective_mode(idx)
        is_sensor = idx < self.num_central_connections
        use_notify = (
            is_sensor
            and mode in (self.MODE_NOTIFICATION, self.MODE_INDICATION)
            and self.nrf_chars[idx] is not None
        )
        if use_notify:
            self._rx_worker_notify(idx, evt, payload_size, mode)
        else:
            self._rx_worker_write(idx, evt, payload_size, mode)

    def _rx_worker_notify(self, idx, evt, payload_size, mode):
        """Sensor RX: nRF notifies/indicates on its own server characteristic (0x2A37/0x2A1C).

        Waits for the DUT to subscribe (write the CCCD) before sending, because blatann
        raises ``InvalidStateException`` if asked to notify an unsubscribed client. If the
        DUT never subscribes (its rx_notifications discovery of the nRF's characteristic
        failed) a single warning is logged so the failure is obvious in the report.
        """
        char = self.nrf_chars[idx]
        use_indicate = (mode == self.MODE_INDICATION)
        is_ht = (self.num_ht_central > 0 and idx < self.num_ht_central)
        rx_char_uuid = (self.HT_MEASUREMENT_UUID_16 if use_indicate
                        else self.HR_MEASUREMENT_UUID_16)
        # Pacing: HT notifications use an in-flight window so the SoftDevice can pack
        # multiple notifications into one connection event (link/CI limited); LT and
        # indications stay serialized (one outstanding) with a modest delay.
        if use_indicate:
            window, inter_delay = 1, self.RX_INDICATE_DELAY
        elif is_ht:
            window, inter_delay = max(1, self.RX_NOTIFY_WINDOW_HT), self.RX_NOTIFY_DELAY_HT
        else:
            window, inter_delay = 1, self.RX_NOTIFY_DELAY_LT
        err_logged = False
        waited = 0.0
        warned_no_sub = False
        # Notifications are unacknowledged, so several can be queued before waiting on
        # the oldest; each (waitable, sample) is only counted once the send confirms,
        # so rx_counts reflects what actually went over the air.
        pending = []

        def _drain_one():
            w, sample = pending.pop(0)
            w.wait(5)
            self.rx_counts[idx] += 1
            self.per_device_logs[idx].setdefault('rx', []).append(sample)

        while not evt.is_set():
            if not getattr(char, "client_subscribed", False):
                # DUT has not (yet) subscribed to the nRF's 0x2A37/0x2A1C. Keep waiting;
                # the subscription arrives shortly after set_data_pattern triggers the
                # DUT's GATT-client discovery on the sensor link.
                pending.clear()
                time.sleep(0.2)
                waited += 0.2
                if waited >= 30 and not warned_no_sub:
                    logger().warning(
                        f"nRF {idx+1} (sensor): DUT has not subscribed to the nRF "
                        f"0x{rx_char_uuid:04X} characteristic after 30s - the DUT's "
                        f"rx_notifications discovery of the nRF server likely failed, so "
                        f"RX notifications cannot flow."
                    )
                    warned_no_sub = True
                continue
            waited = 0.0
            try:
                # blatann's GATTS notify path feeds the payload straight into a
                # uint8 array, so it must be bytes (a str makes it try to assign
                # single-char strings to uint8 -> TypeError, no notification sent).
                data = ''.join(random.choices(
                    string.ascii_uppercase + string.digits, k=payload_size)).encode("ascii")
                # Bounded wait so a stalled link cannot wedge this worker thread and
                # block pytest teardown (same rationale as the write path).
                # Indication mode (0x2A1C) must use indicate() (confirmed PDU);
                # notification mode (0x2A37) uses notify() (unacknowledged).
                if use_indicate:
                    char.indicate(data).wait(5)
                    self.rx_counts[idx] += 1
                    self.per_device_logs[idx].setdefault('rx', []).append(data.decode("ascii"))
                else:
                    pending.append((char.notify(data), data.decode("ascii")))
                    while len(pending) >= window:
                        _drain_one()
                err_logged = False
            except Exception as e:
                if not err_logged:
                    logger().warning(
                        f"RX {'indicate' if use_indicate else 'notify'} error "
                        f"(nRF {idx+1}): {e}")
                    err_logged = True
                pending.clear()
                time.sleep(0.5)
                continue
            if inter_delay:
                time.sleep(inter_delay)

        # Drain any still-queued notifications so rx_counts is accurate at stop.
        while pending:
            try:
                _drain_one()
            except Exception:
                break

    def _rx_worker_write(self, idx, evt, payload_size, mode):
        """Phone / write-mode RX: nRF acts as a GATT client and writes to the DUT char.

        The PDU type tracks the configured mode: write_without_response issues an
        unacknowledged Write Command, every other mode issues a Write Request (ACKed).
        write_without_response is also slightly slower-paced because the unacked path can
        otherwise overrun blatann's 1-deep write-no-response queue.
        """
        nrf_ble = self.nrf_bles[idx]
        with_response = (mode != self.MODE_WRITE_WITHOUT_RESPONSE)
        delay = 0.1 if mode == self.MODE_INDICATION else 0.05
        err_logged = False
        while not evt.is_set():
            try:
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=payload_size))
                nrf_ble.write_characteristic_value(
                    characteristic_uuid=self.dut_char_uuids[idx], data=data, timeout=5,
                    with_response=with_response,
                )
                self.rx_counts[idx] += 1
                self.per_device_logs[idx].setdefault('rx', []).append(data)
                err_logged = False
            except Exception as e:
                if not err_logged:
                    logger().warning(f"RX error (nRF {idx+1}): {e}")
                    err_logged = True
                time.sleep(0.5)
                continue
            time.sleep(delay)

    def _tx_worker(self, idx, evt):
        """TX direction: DUT -> nRF.

        Uniform for sensors AND phones: the nRF is subscribed to the DUT's data
        characteristic and polls the notifications it receives from the DUT.

        Throttled logging: to make the DUT->nRF traffic visible without flooding the
        log, a one-line summary (running count + a short preview of the latest payload)
        is emitted every ``TX_LOG_EVERY`` notifications.
        """
        nrf_ble = self.nrf_bles[idx]
        notif_key = self._dut_char_notif_key()
        last_logged = 0
        last_log_milestone = 0
        while not evt.is_set():
            try:
                notifs = nrf_ble.notifications.get(notif_key, [])
                if len(notifs) > last_logged:
                    for nidx in range(last_logged, len(notifs)):
                        self.per_device_logs[idx].setdefault('tx', []).append(notifs[nidx])
                    self.tx_counts[idx] = len(notifs)
                    last_logged = self.tx_counts[idx]
                    # Throttled visibility of what the nRF receives from the DUT.
                    # Show the first few immediately, then every TX_LOG_EVERY.
                    if (self.tx_counts[idx] <= 5
                            or self.tx_counts[idx] - last_log_milestone >= self.TX_LOG_EVERY):
                        last_log_milestone = self.tx_counts[idx]
                        preview = str(notifs[-1])
                        if len(preview) > 32:
                            preview = preview[:32] + "..."
                        role = "sensor" if idx < self.num_central_connections else "phone"
                        logger().info(
                            f"nRF {idx+1} ({role}): received {self.tx_counts[idx]} "
                            f"notifications from DUT, last={preview!r}"
                        )
            except Exception as e:
                logger().warning(f"TX poll error (nRF {idx+1}): {e}")
            time.sleep(0.05)

    # =========================================================================
    # STOP / DISCONNECT HELPERS
    # =========================================================================

    def _stop_data_transfer(self, idx):
        """Stop data transfer threads for a single device."""
        self.data_transfer_stop_events[idx].set()
        if self.data_transfer_threads[idx]:
            # join timeout must exceed the worker's max in-flight write wait (5s)
            # so a worker blocked mid-write is reliably reaped instead of lingering.
            for t in self.data_transfer_threads[idx]:
                t.join(timeout=8)
                if t.is_alive():
                    logger().warning(
                        f"nRF {idx+1}: data-transfer thread '{t.name}' did not stop "
                        f"within 8s (likely stalled GATT op); continuing teardown."
                    )
            self.data_transfer_threads[idx] = None

    def _check_dut_log_for_disconnects(self, log_start_index=0):
        """Check DUT serial logs for explicit disconnect events since log_start_index."""
        disconnected = set()
        try:
            serial_conn = self.wifi_dut.interfaces.wifi.bus
            input_log = serial_conn.get_input_log()
            new_entries = input_log[log_start_index:]
            for _, line in new_entries:
                try:
                    decoded = line.decode(errors="ignore")
                except Exception:
                    decoded = str(line)
                disc_match = re.search(
                    r'(?:peripheral|central)\s+is\s+disconnected.*?-conn(\d+)',
                    decoded, re.IGNORECASE
                )
                if disc_match:
                    conn_idx = int(disc_match.group(1))
                    if 0 <= conn_idx < self.num_devices:
                        disconnected.add(conn_idx)
        except Exception as e:
            logger().warning(f"Error checking DUT logs for disconnect: {e}")
        return disconnected

    def _is_device_data_flowing(self, idx, prev_rx, prev_tx):
        """Check if a device is actively transferring data."""
        return self.rx_counts[idx] > prev_rx or self.tx_counts[idx] > prev_tx

    # =========================================================================
    # PHASE 1 - ADVERTISE
    # =========================================================================

    def _phase1_advertise(self):
        """Start advertising on central-role (sensor) nRF dongles (DUT will connect to them)."""
        logger().info("=" * 60)
        logger().info(f"PHASE 1: Starting advertising on nRF 1-{self.num_central_connections} (DUT as Central)")
        logger().info("=" * 60)
        for i in range(self.num_central_connections):
            try:
                # Advertise the SIG service UUID(s) the sensor hosts (e.g. 0x180D).
                # The DUT multi-connection firmware uses the advertised service UUID
                # to drive its post-connection GATT discovery. Without it the DUT
                # reports "service not found".
                spec = self._standard_sensor_service_spec(self._get_effective_mode(i))
                adv_service_uuids = [svc["uuid"] for svc in spec["services"]]
                nrf_addr = self.nrf_bles[i].start_advertising(
                    local_name=f"NRF_SENSOR_{i+1}",
                    timeout_sec=0,
                    auto_restart=True,
                    service_uuid16s=adv_service_uuids,
                )
                self.nrf_addrs[i] = nrf_addr
                logger().info(
                    f"nRF {i+1} advertising: {nrf_addr} "
                    f"(services={', '.join('0x%04X' % u for u in adv_service_uuids)})"
                )
            except Exception as e:
                logger().error(f"Failed to start advertising on nRF {i+1}: {e}")
                self.connection_errors[i] = str(e)
        time.sleep(5)

    # =========================================================================
    # PHASE 2 - CONNECT
    # =========================================================================

    def _phase2_connect(self):
        """Sequential connections: PHONES FIRST, then SENSORS (mirrors Garmin use case)."""
        logger().info("=" * 60)
        logger().info("PHASE 2: Sequential connections - PHONES first, then SENSORS")
        logger().info("=" * 60)

        # =====================================================================
        # STEP 1: PHONE CONNECTIONS (nRF as central, DUT as peripheral)
        # =====================================================================
        if self.num_peripheral_connections > 0:
            logger().info(f"Connecting {self.num_peripheral_connections} phone(s) to DUT...")
            for i in range(self.num_central_connections, self.num_devices):
                self.connection_attempts[i] = 1
                for attempt in range(1, self.max_retries + 1):
                    self.connection_attempts[i] = attempt
                    if attempt > 1:
                        logger().info(f"nRF {i+1} (phone) retry attempt {attempt}/{self.max_retries}...")
                        try:
                            self.nrf_bles[i].disconnect(self.target_address)
                            time.sleep(2)
                        except Exception as cleanup_err:
                            logger().info(f"nRF {i+1} pre-retry cleanup: {cleanup_err} (continuing)")

                    success = self._connect_central(i)
                    if success:
                        logger().info(f"nRF {i+1} (phone) attempting GATT setup to verify connection...")
                        gatt_ok = self._setup_gatt_and_start_transfer(i)
                        if gatt_ok:
                            self.connection_success[i] = True
                            self.connection_errors[i] = None
                            logger().info(f"nRF {i+1} (phone) VERIFIED connected (GATT OK). Data transfer running.")
                            break
                        else:
                            self.connection_success[i] = False
                            self.connection_errors[i] = "GATT resolution failed"
                            logger().error(f"nRF {i+1} (phone) GATT failed (attempt {attempt}/{self.max_retries}).")
                    else:
                        self.connection_success[i] = False
                    time.sleep(2)

                if i < self.num_devices - 1 and self.connection_success[i]:
                    logger().info("Pausing 10s between phone connections to drain DUT buffers...")
                    time.sleep(10)

            phone_count = sum(self.connection_success[self.num_central_connections:])
            logger().info(f"Phone connections verified: {phone_count}/{self.num_peripheral_connections}")

            if phone_count == self.num_peripheral_connections:
                logger().info("All phones connected. Waiting for firmware advertising to settle...")
                time.sleep(10)

        # =====================================================================
        # STEP 2: SENSOR CONNECTIONS (DUT as central, nRF as peripheral)
        # =====================================================================
        if self.num_central_connections > 0:
            logger().info(f"DUT connecting to {self.num_central_connections} sensor nRF(s) as central...")
            for i in range(self.num_central_connections):
                self.connection_attempts[i] = 1
                if self.nrf_addrs[i] is None:
                    logger().warning(f"Skipping nRF {i+1} - no address from advertising.")
                    self.connection_success[i] = False
                    self.connection_errors[i] = "No advertising address"
                    continue

                if self.num_ht_central > 0 and i < self.num_ht_central:
                    ci_min, ci_max = self.ht_sensor_ci_min, self.ht_sensor_ci_max
                    lsto, latency = self.HT_SENSOR_LSTO, self.HT_SENSOR_LATENCY
                    min_ce, max_ce = self.HT_SENSOR_MIN_CE, self.HT_SENSOR_MAX_CE
                    sensor_type = "High Throughput"
                else:
                    ci_min, ci_max = self.LT_SENSOR_CI_MIN, self.LT_SENSOR_CI_MAX
                    lsto, latency = self.LT_SENSOR_LSTO, self.LT_SENSOR_LATENCY
                    min_ce, max_ce = self.LT_SENSOR_MIN_CE, self.LT_SENSOR_MAX_CE
                    sensor_type = "Low Throughput"

                connected = False
                for attempt in range(1, self.SENSOR_CONNECT_RETRIES + 1):
                    self.connection_attempts[i] = attempt
                    logger().info(f"nRF {i+1} ({sensor_type}): connect attempt {attempt}/{self.SENSOR_CONNECT_RETRIES}...")

                    log_snapshot = self._get_current_log_length()
                    add_type = self._connect_add_type(i, self.nrf_addrs[i])
                    # Prime the DUT data pattern (rx/tx notifications) BEFORE connecting.
                    # The firmware runs its peer-notification discovery + CCCD subscribe
                    # autonomously right after the connection forms; if rx_notifications
                    # is not already set at that moment the DUT never subscribes to the
                    # nRF's 0x2A37, and blatann (spec-strict) will not notify an
                    # unsubscribed client -> sensor RX stays 0 (observed). Setting it here,
                    # keyed by the sensor's advertised address, lets the DUT subscribe at
                    # connect time so the nRF's notifications actually flow. It is re-issued
                    # after connection in _setup_gatt_and_start_transfer for completeness.
                    logger().info(f"nRF {i+1}: priming set_data_pattern before connect (rx/tx notifications).")
                    self._configure_dut_data_pattern(i)
                    logger().info(f"nRF {i+1}: issuing req_legacy_connect to {self.nrf_addrs[i]} ({sensor_type}) "
                                  f"CI={ci_min*1.25:.0f}-{ci_max*1.25:.0f}ms, LSTO={lsto*10}ms, "
                                  f"CE_len={min_ce*0.625:.2f}-{max_ce*0.625:.2f}ms, "
                                  f"add_type={add_type} ({'random' if add_type else 'public'})")
                    try:
                        conn_result = self.wifi_dut.interfaces.wifi.req_legacy_connect(
                            dev_addr=self.nrf_addrs[i],
                            add_type=add_type,
                            conn_interval_min=ci_min,
                            conn_interval_max=ci_max,
                            conn_latency=latency,
                            supervision_tout=lsto,
                            min_ce_length=min_ce,
                            max_ce_length=max_ce
                        )
                        logger().info(f"nRF {i+1}: req_legacy_connect result: {conn_result!r}")
                    except Exception as e:
                        logger().error(f"nRF {i+1}: req_legacy_connect raised: {e}")
                        self.connection_errors[i] = str(e)
                        time.sleep(2)
                        continue

                    deadline = time.time() + self.SENSOR_CONNECT_TIMEOUT
                    while time.time() < deadline:
                        try:
                            if self.nrf_bles[i].get_connection_status(self.target_address):
                                connected = True
                                break
                        except Exception:
                            pass
                        time.sleep(2)

                    if connected:
                        logger().info(f"nRF {i+1}: connected (attempt {attempt}). Verifying...")
                        time.sleep(5)
                        ltk_ok = self._wait_for_ltk_in_logs(
                            f"nRF {i+1} (sensor)", timeout=30, log_start_index=log_snapshot
                        )
                        if not ltk_ok:
                            logger().warning(f"LTK not confirmed for nRF {i+1}, continuing.")

                        if self.phy_rate == "2M":
                            logger().info(f"nRF {i+1}: Setting PHY to 2M (phy_rate=2M)...")
                            try:
                                self.wifi_dut.interfaces.wifi.set_phy(
                                    ble_address=self.nrf_addrs[i],
                                    tx_phy=2, rx_phy=2, coded_phy=0
                                )
                                time.sleep(2)
                            except Exception as e:
                                logger().warning(f"nRF {i+1}: set_phy(2M) warning: {e}")
                            # Drive the PHY update from the nRF side too. On a sensor
                            # link the nRF is the GAP-peripheral; the connected central
                            # is reachable via ble_device.client, which update_phy()
                            # resolves automatically, so the rate change is negotiated
                            # by both ends rather than only requested by the DUT.
                            try:
                                self.nrf_bles[i].update_phy("2M")
                                time.sleep(1)
                            except Exception as e:
                                logger().warning(f"nRF {i+1}: nRF-side update_phy(2M) warning: {e}")

                        gatt_ok = self._setup_gatt_and_start_transfer(i)
                        if gatt_ok:
                            self.connection_success[i] = True
                            self.connection_errors[i] = None
                            logger().info(f"nRF {i+1} VERIFIED connected. Data transfer running.")
                            break
                        else:
                            self.connection_success[i] = False
                            self.connection_errors[i] = "Data transfer setup failed"
                            logger().error(f"nRF {i+1} data setup failed (attempt {attempt}).")
                            connected = False
                    else:
                        reason = (f"attempt {attempt}: connection did not form "
                                  f"within {self.SENSOR_CONNECT_TIMEOUT}s for {self.nrf_addrs[i]}")
                        self.connection_errors[i] = reason
                        logger().warning(f"nRF {i+1}: {reason}")
                        time.sleep(2)

                if not connected:
                    self.connection_success[i] = False
                time.sleep(2)

            sensor_count = sum(self.connection_success[:self.num_central_connections])
            logger().info(f"Sensor connections verified: {sensor_count}/{self.num_central_connections}")

    # =========================================================================
    # PHASE 3 - RETRY
    # =========================================================================

    def _phase3_retry(self):
        """Retry failed connections."""
        failed_indices = [i for i in range(self.num_devices) if not self.connection_success[i]]
        if failed_indices:
            logger().info("=" * 60)
            logger().info(f"PHASE 3: Retrying failed connections: {[i+1 for i in failed_indices]}")
            logger().info("=" * 60)
            for i in failed_indices:
                for attempt in range(2, self.max_retries + 1):
                    self.connection_attempts[i] = attempt
                    logger().info(f"Retry attempt {attempt} for nRF {i+1}...")
                    if i < self.num_central_connections:
                        success = self._connect_peripheral(i)
                    else:
                        success = self._connect_central(i)
                    if success:
                        gatt_ok = self._setup_gatt_and_start_transfer(i)
                        if gatt_ok:
                            self.connection_success[i] = True
                            self.connection_errors[i] = None
                            logger().info(f"nRF {i+1} retry VERIFIED connected.")
                            break
                        else:
                            logger().error(f"nRF {i+1} retry: connect succeeded but data setup failed.")
                    time.sleep(3)
        else:
            logger().info("PHASE 3: All connections successful, no retries needed.")

        connected_count = sum(self.connection_success)
        logger().info(f"Connected devices: {connected_count}/{self.num_devices}")

    # =========================================================================
    # PHASE 4 - MONITOR
    # =========================================================================

    def _phase4_monitor(self):
        """Monitor connection health with auto-reconnect."""
        logger().info("=" * 60)
        logger().info(f"PHASE 4: Data transfer running for {self.test_duration}s with connection monitoring")
        logger().info(f"         Mode: {self.data_transfer_mode}")
        if self.ble_scanning:
            logger().info(f"         BLE Scanning: ENABLED (interval={self.SCAN_INTERVAL*0.625:.3f}ms, window={self.SCAN_WINDOW*0.625:.3f}ms)")
        if self.ble_advertising:
            adv_type = "non-connectable" if self.non_connectable_adv else "connectable"
            logger().info(f"         BLE Advertising: ENABLED ({adv_type})")
        logger().info("=" * 60)

        # Advertising stays up from _initialize_dut and is stopped once in _cleanup.
        # Scanning was kept OFF during connection establishment so the connection logs
        # stayed readable; now that all connections are up, (re)start it ONCE here if the
        # scenario exercises BLE scanning as a concurrent activity. Reconnects below
        # pause/resume it around each new connection attempt.
        if self.ble_scanning:
            self._resume_dut_scan(reason="Phase 4 - data transfer (concurrent scan)")

        STATS_POLL_INTERVAL = 1
        logger().info(f"Enabling BLE legacy packet stats (interval={STATS_POLL_INTERVAL * 1000}ms)...")
        try:
            self.wifi_dut.interfaces.wifi.cmd_legacy_pkts_stats(enable=1, rate=STATS_POLL_INTERVAL * 1000)
            logger().info("BLE legacy packet stats enabled.")
        except Exception as e:
            logger().warning(f"Failed to enable legacy pkt stats: {e}")

        start_time = time.time()
        last_status_log = 0
        last_stats_log = 0
        stats_log_snapshot = self._get_current_log_length()
        scan_log_snapshot = stats_log_snapshot
        prev_rx_snapshot = list(self.rx_counts)
        prev_tx_snapshot = list(self.tx_counts)
        monitoring_log_snapshot = self._get_current_log_length()

        while time.time() - start_time < self.test_duration:
            elapsed = int(time.time() - start_time)

            if elapsed > 0 and elapsed % STATS_POLL_INTERVAL == 0 and elapsed != last_stats_log:
                last_stats_log = elapsed
                try:
                    stats_text, stats_log_snapshot = self._extract_latest_stats_from_log(stats_log_snapshot)
                    if stats_text:
                        # Cache the latest good snapshot so the report's DUT/Per-CE
                        # tables are populated even if the post-loop final extraction
                        # finds no fresh table in its (incremental) log window.
                        self._last_good_stats_text = stats_text
                        # Accumulate cumulative CE / Sch_Fail for the connection-event
                        # consistency pass/fail computed at the end of the test.
                        self._accumulate_pkt_stats(stats_text)
                        formatted = self._format_pkt_stats_table(stats_text)
                        logger().info(f"[{elapsed}s] BLE Packet Stats:")
                        for line in formatted:
                            logger().info(f"  {line}")
                        # Per-connection-event throughput (Data_sent/Data_rcvd per CE),
                        # the authoritative per-CE view for HT vs LT analysis.
                        logger().info(f"[{elapsed}s] Per-CE throughput (DUT link-layer):")
                        for line in self._format_pkt_stats_per_ce(stats_text):
                            logger().info(f"  {line}")
                    else:
                        logger().info(f"[{elapsed}s] BLE Packet Stats: (waiting for DUT to print stats...)")

                    # Make concurrent scan/advertising activity explicit during the stats
                    # check (otherwise the per-second stats tables drown the scan reports
                    # in the log and it looks like scanning stopped).
                    if self.ble_scanning or self.ble_advertising:
                        scan_reports, scan_log_snapshot = self._count_scan_activity_since(scan_log_snapshot)
                        self._scan_report_total += scan_reports
                        state = []
                        if self.ble_scanning:
                            state.append("scan=ON")
                        if self.ble_advertising:
                            state.append("adv=ON")
                        logger().info(
                            f"[{elapsed}s] Scan/Adv activity: {scan_reports} report(s) since "
                            f"last poll ({', '.join(state)}; total={self._scan_report_total})"
                        )
                except Exception as e:
                    logger().warning(f"[{elapsed}s] Failed to read pkt stats from log: {e}")

            if elapsed > 0 and elapsed % 300 == 0 and elapsed != last_status_log:
                last_status_log = elapsed
                elapsed_min = elapsed // 60

                dut_disconnected = self._check_dut_log_for_disconnects(monitoring_log_snapshot)
                if dut_disconnected:
                    logger().warning(f"[{elapsed_min}min] DUT log disconnect events for conn indices: {dut_disconnected}")

                device_status = {}
                for i in range(self.num_devices):
                    if not self.connection_success[i]:
                        device_status[i] = False
                    elif i in dut_disconnected:
                        device_status[i] = False
                        logger().warning(f"  nRF {i+1}: DISCONNECTED (confirmed by DUT serial log)")
                    else:
                        data_active = self._is_device_data_flowing(i, prev_rx_snapshot[i], prev_tx_snapshot[i])
                        device_status[i] = True
                        if not data_active:
                            logger().warning(
                                f"  nRF {i+1}: Data flow stalled (RX: {prev_rx_snapshot[i]}->{self.rx_counts[i]}, "
                                f"TX: {prev_tx_snapshot[i]}->{self.tx_counts[i]}) but no DUT disconnect event"
                            )

                prev_rx_snapshot = list(self.rx_counts)
                prev_tx_snapshot = list(self.tx_counts)

                connected_devices = [i+1 for i in range(self.num_devices) if device_status.get(i, False)]
                disconnected_devices = [i+1 for i in range(self.num_devices) if not device_status.get(i, False)]

                logger().info("=" * 60)
                logger().info(f"[{elapsed_min}min] CONNECTION STATUS CHECK")
                logger().info(f"[{elapsed_min}min] Connected   ({len(connected_devices)}/{self.num_devices}): {connected_devices}")
                logger().info(f"[{elapsed_min}min] Disconnected ({len(disconnected_devices)}/{self.num_devices}): {disconnected_devices}")
                logger().info(f"[{elapsed_min}min] RX sent: {self.rx_counts}")
                logger().info(f"[{elapsed_min}min] TX received: {self.tx_counts}")
                for i in range(self.num_devices):
                    status_str = "CONNECTED" if device_status.get(i, False) else "DISCONNECTED"
                    logger().info(
                        f"  Device {i+1}: {status_str} | RX={self.rx_counts[i]} | TX={self.tx_counts[i]} | Reconnects={self.reconnect_counts[i]}"
                    )
                logger().info("=" * 60)

                self.monitoring_history.append({
                    "time_min": elapsed_min,
                    "connected": list(connected_devices),
                    "disconnected": list(disconnected_devices),
                    "rx_counts": list(self.rx_counts),
                    "tx_counts": list(self.tx_counts),
                    "reconnect_counts": list(self.reconnect_counts),
                })

                for i in range(self.num_devices):
                    if self.connection_success[i] and i in dut_disconnected:
                        logger().warning(f"nRF {i+1} confirmed disconnected by DUT log. Attempting reconnect...")
                        self.connection_success[i] = False
                        self._stop_data_transfer(i)
                        self.reconnect_counts[i] += 1
                        # Pause scanning while re-establishing the link so the reconnect
                        # is not buried under scan reports / rejected with 0x4e0c.
                        scan_was_on = self.ble_scanning
                        if scan_was_on:
                            self._pause_dut_scan(reason=f"reconnecting nRF {i+1}")
                        if i < self.num_central_connections:
                            success = self._connect_peripheral(i)
                        else:
                            success = self._connect_central(i)
                        if success:
                            gatt_ok = self._setup_gatt_and_start_transfer(i)
                            if gatt_ok:
                                self.connection_success[i] = True
                                self.connection_errors[i] = None
                                logger().info(f"nRF {i+1} reconnected and VERIFIED.")
                                monitoring_log_snapshot = self._get_current_log_length()
                            else:
                                logger().error(f"nRF {i+1} reconnect: connect succeeded but data setup failed.")
                        else:
                            logger().error(f"nRF {i+1} reconnect failed.")
                        if scan_was_on:
                            self._resume_dut_scan(reason=f"reconnected nRF {i+1}")

            if self.random_reconnect and elapsed > 0 and elapsed % 60 == 0:
                connected_centrals = [i for i in range(self.num_central_connections)
                                      if self.connection_success[i]]
                if connected_centrals:
                    victim = random.choice(connected_centrals)
                    logger().info(f"[{elapsed}s] RANDOM RECONNECT: Disconnecting nRF {victim+1} (central)...")
                    scan_was_on = self.ble_scanning
                    try:
                        self._stop_data_transfer(victim)
                        self.wifi_dut.interfaces.wifi.btc_disconnect(
                            ble_address=self.nrf_addrs[victim]
                        )
                        time.sleep(5)
                        self.connection_success[victim] = False
                        self.reconnect_counts[victim] += 1

                        logger().info(f"[{elapsed}s] RANDOM RECONNECT: Reconnecting nRF {victim+1}...")
                        if scan_was_on:
                            self._pause_dut_scan(reason=f"random-reconnecting nRF {victim+1}")
                        success = self._connect_peripheral(victim)
                        if success:
                            gatt_ok = self._setup_gatt_and_start_transfer(victim)
                            if gatt_ok:
                                self.connection_success[victim] = True
                                self.connection_errors[victim] = None
                                logger().info(f"[{elapsed}s] RANDOM RECONNECT: nRF {victim+1} reconnected.")
                            else:
                                logger().error(f"[{elapsed}s] RANDOM RECONNECT: nRF {victim+1} data setup failed.")
                        else:
                            logger().error(f"[{elapsed}s] RANDOM RECONNECT: nRF {victim+1} reconnect failed.")
                    except Exception as e:
                        logger().error(f"[{elapsed}s] RANDOM RECONNECT error for nRF {victim+1}: {e}")
                    finally:
                        if scan_was_on:
                            self._resume_dut_scan(reason=f"random-reconnected nRF {victim+1}")

            time.sleep(1)

        logger().info("Extracting final BLE packet stats from serial log...")
        try:
            # Try the incremental window first; if nothing fresh was printed since the
            # last poll, scan the whole log, then fall back to the last good snapshot
            # cached during monitoring. This guarantees the report's DUT Packet Stats
            # and Per-CE tables are populated whenever any poll succeeded.
            final_stats_text, _ = self._extract_latest_stats_from_log(stats_log_snapshot)
            source = "incremental log window"
            if not final_stats_text:
                final_stats_text, _ = self._extract_latest_stats_from_log(0)
                source = "full log scan"
            if not final_stats_text and self._last_good_stats_text:
                final_stats_text = self._last_good_stats_text
                source = "last good snapshot (during monitoring)"

            if final_stats_text:
                formatted = self._format_pkt_stats_table(final_stats_text)
                logger().info(f"[FINAL] BLE Packet Stats (source: {source}):")
                for line in formatted:
                    logger().info(f"  {line}")
                # Keep the structured rows so they can be added to the Excel report
                # for side-by-side comparison with the host-side throughput counts.
                _, self.final_pkt_stats_rows = self._parse_pkt_stats_rows(final_stats_text)
            else:
                logger().info("[FINAL] No stats table found in recent serial log.")
        except Exception as e:
            logger().warning(f"Failed to extract final stats: {e}")

        logger().info("Disabling BLE legacy packet stats...")
        try:
            self.wifi_dut.interfaces.wifi.cmd_legacy_pkts_stats(enable=0, rate=STATS_POLL_INTERVAL * 1000)
            logger().info("BLE legacy packet stats disabled.")
        except Exception as e:
            logger().warning(f"Failed to disable legacy pkt stats: {e}")

        # NOTE: neither scanning nor advertising is stopped here. Both are stopped exactly
        # once in _cleanup, so we avoid issuing duplicate radio commands mid-test.

        for i in range(self.num_devices):
            self._stop_data_transfer(i)

    # =========================================================================
    # REPORTING
    # =========================================================================

    # Control characters that openpyxl/XML refuse in worksheet cells
    # (everything 0x00-0x1F except TAB 0x09, LF 0x0A, CR 0x0D).
    _EXCEL_ILLEGAL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

    @classmethod
    def _excel_safe(cls, value):
        """Return a worksheet-safe representation of ``value``.

        DUT notification/data payloads are binary, so decoded samples can contain
        ASCII control characters that openpyxl rejects with IllegalCharacterError.
        Convert non-string values to ``str`` and replace illegal control chars with
        their hex escape so the report still shows the raw content.
        """
        if value is None:
            return ""
        if isinstance(value, (bytes, bytearray)):
            return value.hex()
        text = value if isinstance(value, str) else str(value)
        return cls._EXCEL_ILLEGAL_RE.sub(lambda m: f"\\x{ord(m.group()):02x}", text)

    def _generate_report(self):
        """Generate Excel report with throughput calculations and monitoring timeline."""
        logger().info("=" * 60)
        logger().info("FINAL RESULTS")
        logger().info("=" * 60)

        duration = max(self.test_duration, 1)
        throughput_data = []
        for i in range(self.num_devices):
            is_sensor = i < self.num_central_connections
            payload_size = self._get_data_size_for_connection(i)
            rx_pps = self.rx_counts[i] / duration
            tx_pps = self.tx_counts[i] / duration
            # Average packets/connection/second (both directions combined) - the metric
            # that correlates directly with the expected per-connection performance.
            total_pps = rx_pps + tx_pps
            rx_bps = rx_pps * payload_size
            tx_bps = tx_pps * payload_size

            ci_min_ms, ci_max_ms = self._get_ci_range_ms_for_connection(i)
            # Expected connection-event rate ~ 1000 / CI (events per second). Reported as
            # a range because CI is negotiated within [ci_min, ci_max].
            expected_ce_s_max = 1000.0 / ci_min_ms if ci_min_ms else 0.0
            expected_ce_s_min = 1000.0 / ci_max_ms if ci_max_ms else 0.0

            if is_sensor:
                if self.num_ht_central > 0 and i < self.num_ht_central:
                    conn_type = "HT Sensor"
                else:
                    conn_type = "LT Sensor"
            else:
                conn_type = "Phone"

            # Plan expected throughput (sensors only) and an observed-vs-expected status.
            expected = self._get_expected_throughput(i, conn_type)
            exp_rx_pps = exp_tx_pps = exp_rx_bps = exp_tx_bps = None
            rx_status = tx_status = ""
            if expected is not None:
                exp_rx_pps, exp_tx_pps, exp_rx_bps, exp_tx_bps = expected
                rx_status = self._throughput_status(rx_bps, exp_rx_bps)
                tx_status = self._throughput_status(tx_bps, exp_tx_bps)

            throughput_data.append({
                'conn_type': conn_type,
                'payload_size': payload_size,
                'rx_pps': rx_pps,
                'tx_pps': tx_pps,
                'total_pps': total_pps,
                'rx_bps': rx_bps,
                'tx_bps': tx_bps,
                'ci_min_ms': ci_min_ms,
                'ci_max_ms': ci_max_ms,
                'expected_ce_s_min': expected_ce_s_min,
                'expected_ce_s_max': expected_ce_s_max,
                'exp_rx_pps': exp_rx_pps,
                'exp_tx_pps': exp_tx_pps,
                'exp_rx_bps': exp_rx_bps,
                'exp_tx_bps': exp_tx_bps,
                'rx_status': rx_status,
                'tx_status': tx_status,
            })

            exp_str = ""
            if expected is not None:
                exp_str = (f" | Plan exp RX {exp_rx_pps} pps/{exp_rx_bps} B/s [{rx_status}], "
                           f"TX {exp_tx_pps} pps/{exp_tx_bps} B/s [{tx_status}]")
            logger().info(
                f"Device {i+1} ({conn_type}): "
                f"CI={ci_min_ms:.0f}-{ci_max_ms:.0f}ms (expected ~{expected_ce_s_min:.0f}-{expected_ce_s_max:.0f} CE/s) | "
                f"RX={self.rx_counts[i]} ({rx_pps:.1f} pps, {rx_bps:.0f} B/s) | "
                f"TX={self.tx_counts[i]} ({tx_pps:.1f} pps, {tx_bps:.0f} B/s) | "
                f"Avg {int(round(total_pps))} pkts/conn/s"
                f"{exp_str} | "
                f"Reconnects={self.reconnect_counts[i]} | "
                f"Error={self.connection_errors[i]}"
            )

        logger().info(f"Test duration: {self.test_duration}s")
        logger().info(f"Data transfer mode: {self.data_transfer_mode}")
        if self.test_case_id:
            logger().info(f"Test case ID: {self.test_case_id}")

        # Pass/fail is determined by the packet-rate criteria ONLY (observed RX/TX pps
        # vs the plan target, within 10%). Connection-event consistency is still computed
        # and reported for diagnostics, but does NOT affect the overall result.
        tput_pass, pf_results, tput_failures = self._evaluate_throughput(throughput_data)
        ce_results, ce_failures = self._evaluate_connection_events()
        failures = list(tput_failures)
        overall_pass = tput_pass
        self.throughput_pass = overall_pass
        self.throughput_failures = failures
        profile_label = ("8-sensor (4HT+4LT)" if self.is_high_density
                         else "5-sensor (2HT+3LT)")
        tol_pct = int(self.THROUGHPUT_OK_FRACTION * 100)
        logger().info("-" * 60)
        logger().info(f"THROUGHPUT PASS/FAIL ({profile_label}, threshold {tol_pct}% of plan):")
        for r in pf_results:
            logger().info(
                f"  Device {r['device']} ({r['conn_type']}): "
                f"RX {r['rx_obs']:.1f}/{r['rx_exp']} pps [{'PASS' if r['rx_ok'] else 'FAIL'}], "
                f"TX {r['tx_obs']:.1f}/{r['tx_exp']} pps [{'PASS' if r['tx_ok'] else 'FAIL'}] "
                f"-> {'PASS' if r['pass'] else 'FAIL'}"
            )
        logger().info(f"  OVERALL RESULT (packets only): {'PASS' if overall_pass else 'FAIL'}")
        logger().info("-" * 60)
        logger().info(f"CONNECTION-EVENT CONSISTENCY (diagnostic only, does not affect "
                      f"pass/fail; scheduler-failure threshold "
                      f"{int(self.SCHED_FAIL_MAX_RATIO * 100)}%):")
        if ce_results:
            for r in ce_results:
                logger().info(
                    f"  Slave {r['slave']}: cumulative CE={r['ce']}, Sch_Fail={r['sch_fail']} "
                    f"({r['ratio']*100:.0f}%) -> {'OK' if r['ok'] else 'STARVED'}"
                )
        else:
            logger().info("  (no cumulative DUT stats captured)")
        logger().info("-" * 60)

        wb = openpyxl.Workbook()

        # ---------------------------------------------------------------------
        # Sheet 1: Pass-Fail Summary (clean, criteria-focused)
        # ---------------------------------------------------------------------
        ws_sum = wb.active
        ws_sum.title = "Pass-Fail Summary"
        ws_sum.append(["BLE Multi-Connection Throughput - Pass/Fail Summary"])
        ws_sum.append(["Test Case", self.test_case_id or "(none)"])
        ws_sum.append(["Profile", profile_label])
        ws_sum.append(["Data Transfer Mode", self.data_transfer_mode])
        ws_sum.append(["Test Duration (s)", self.test_duration])
        ws_sum.append(["Pass Threshold", f"RX and TX pkts/s >= {tol_pct}% of plan target (packets only)"])
        ws_sum.append(["OVERALL RESULT", "PASS" if overall_pass else "FAIL"])
        ws_sum.append([])
        ws_sum.append([
            "Device", "Type",
            "RX pps (obs)", "RX pps (plan)", "RX min req", "RX result",
            "TX pps (obs)", "TX pps (plan)", "TX min req", "TX result",
            "Connected", "Result",
        ])
        for r in pf_results:
            ws_sum.append([
                r['device'], r['conn_type'],
                round(r['rx_obs'], 2), r['rx_exp'], round(r['rx_req'], 2),
                "PASS" if r['rx_ok'] else "FAIL",
                round(r['tx_obs'], 2), r['tx_exp'], round(r['tx_req'], 2),
                "PASS" if r['tx_ok'] else "FAIL",
                "Yes" if r['connected'] else "No",
                "PASS" if r['pass'] else "FAIL",
            ])
        # Phones (no plan target) listed for completeness.
        for i in range(self.num_central_connections, self.num_devices):
            td = throughput_data[i]
            ws_sum.append([
                i + 1, td['conn_type'],
                round(td['rx_pps'], 2), "-", "-", "N/A (no plan target)",
                round(td['tx_pps'], 2), "-", "-", "N/A (no plan target)",
                "Yes" if self.connection_success[i] else "No", "INFO",
            ])
        # Connection-event consistency: cumulative CE vs scheduler failures per slave.
        # DIAGNOSTIC ONLY - this does not affect the pass/fail result (packets only).
        ws_sum.append([])
        ws_sum.append([
            f"Connection-Event Consistency (DIAGNOSTIC ONLY - does not affect pass/fail; "
            f"Sch_Fail threshold {int(self.SCHED_FAIL_MAX_RATIO * 100)}% of scheduled events)"
        ])
        ws_sum.append([
            "Slave_id", "Cumulative CE", "Cumulative Sch_Fail",
            "Sch_Fail %", "Status",
        ])
        if ce_results:
            for r in ce_results:
                ws_sum.append([
                    r['slave'], r['ce'], r['sch_fail'],
                    round(r['ratio'] * 100, 1),
                    "OK" if r['ok'] else "STARVED",
                ])
        else:
            ws_sum.append(["(no cumulative DUT stats captured)"])
        if self.ble_scanning or self.ble_advertising:
            ws_sum.append([
                "Scan/Adv reports during stats check",
                self._scan_report_total,
            ])

        if failures:
            ws_sum.append([])
            ws_sum.append(["Failures:"])
            for f in failures:
                ws_sum.append([f])

        # ---------------------------------------------------------------------
        # Sheet 2: Throughput Details (full per-connection metrics + DUT stats)
        # ---------------------------------------------------------------------
        ws = wb.create_sheet(title="Throughput Details")
        ws.append([
            "Device", "Connection Type", "Payload (B)",
            "CI min (ms)", "CI max (ms)", "Expected CE/s",
            "RX Count", "TX Count",
            "RX pps", "TX pps", "Avg pkts/conn/s",
            "RX B/s", "TX B/s",
            "Plan RX pps", "Plan TX pps", "Plan RX B/s", "Plan TX B/s",
            "RX vs Plan", "TX vs Plan",
            "Attempts", "Success", "Reconnects", "Error"
        ])
        for i in range(self.num_devices):
            td = throughput_data[i]
            ws.append([
                i + 1,
                td['conn_type'],
                td['payload_size'],
                round(td['ci_min_ms'], 1),
                round(td['ci_max_ms'], 1),
                f"{td['expected_ce_s_min']:.0f}-{td['expected_ce_s_max']:.0f}",
                self.rx_counts[i],
                self.tx_counts[i],
                round(td['rx_pps'], 2),
                round(td['tx_pps'], 2),
                int(round(td['total_pps'])),
                round(td['rx_bps'], 1),
                round(td['tx_bps'], 1),
                td['exp_rx_pps'] if td['exp_rx_pps'] is not None else "-",
                td['exp_tx_pps'] if td['exp_tx_pps'] is not None else "-",
                td['exp_rx_bps'] if td['exp_rx_bps'] is not None else "-",
                td['exp_tx_bps'] if td['exp_tx_bps'] is not None else "-",
                td['rx_status'] or "-",
                td['tx_status'] or "-",
                self.connection_attempts[i],
                str(self.connection_success[i]),
                self.reconnect_counts[i],
                self._excel_safe(self.connection_errors[i]),
            ])

        ws.append([])
        ws.append([
            "Note: Plan targets are from the Garmin 8+2 BLE_Standalone test plan "
            f"({'8-sensor / high-density' if self.is_high_density else '5-sensor / low-density'} profile). "
            "Host-side RX/TX pps is paced by the data-transfer worker loop, so 'vs Plan' "
            "may read LOW even on a healthy link - use the Per-CE Throughput table below "
            "for the authoritative link-layer view."
        ])

        ws.append([])
        ws.append(["Test Duration (s)", self.test_duration])
        ws.append(["Data Transfer Mode", self.data_transfer_mode])
        ws.append(["PHY Rate", self.phy_rate])
        ws.append(["DLE Enabled", str(self.dle_enabled)])
        ws.append(["BLE Scanning", str(self.ble_scanning)])
        ws.append(["BLE Advertising", str(self.ble_advertising)])
        ws.append(["Remote Device", "nRF52840 dongle"])
        if self.test_case_id:
            ws.append(["Test Case ID", self.test_case_id])

        # DUT-side packet stats (from the firmware's BLE_Legacy_Stats command),
        # placed beneath the host-side summary for side-by-side comparison.
        # NOTE: this is the DUT's most recent stats snapshot (last poll window),
        # NOT cumulative full-test totals, and its counters are link-layer
        # (Data_sent/Data_rcvd include the DUT's own framing). Slave_id is the
        # DUT connection handle, which does not map 1:1 to the Device numbers above.
        ws.append([])
        ws.append(["DUT Packet Stats (BLE_Legacy_Stats - last snapshot, link-layer counters)"])
        if self.final_pkt_stats_rows:
            ws.append(self.PKT_STATS_HEADERS)
            for row in self.final_pkt_stats_rows:
                ws.append([self._excel_safe(c) for c in row])
        else:
            ws.append(["(no DUT stats table captured)"])

        # Per-connection-event (CE) throughput derived from the DUT link-layer
        # counters above. This is the authoritative per-CE view (the host-side
        # rx/tx pps are paced by the worker loop and cannot reflect the radio's
        # true per-CE behaviour). HT connections are expected to carry ~2 packets
        # per CE (one sent + one received); LT connections carry fewer.
        ws.append([])
        ws.append(["Per-CE Throughput (derived from DUT link-layer counters)"])
        ws.append([
            "Slave_id", "State", "Conn_evts", "Data_sent", "Data_rcvd",
            "Sent/CE", "Rcvd/CE", "Total/CE"
        ])
        if self.final_pkt_stats_rows:
            I_SLAVE, I_STATE, I_CE, I_SENT, I_RCVD = 0, 1, 2, 4, 6
            any_row = False
            for row in self.final_pkt_stats_rows:
                try:
                    ce = int(row[I_CE])
                    sent = int(row[I_SENT])
                    rcvd = int(row[I_RCVD])
                except (ValueError, IndexError):
                    continue
                if row[I_STATE] == '0':
                    continue
                any_row = True
                sent_per_ce = sent / ce if ce else 0.0
                rcvd_per_ce = rcvd / ce if ce else 0.0
                ws.append([
                    self._excel_safe(row[I_SLAVE]),
                    self._excel_safe(row[I_STATE]),
                    ce, sent, rcvd,
                    round(sent_per_ce, 3),
                    round(rcvd_per_ce, 3),
                    round(sent_per_ce + rcvd_per_ce, 3),
                ])
            if not any_row:
                ws.append(["(no active connections in DUT stats snapshot)"])
        else:
            ws.append(["(no DUT stats table captured)"])

        if self.monitoring_history:
            ws2 = wb.create_sheet(title="Monitoring Timeline")
            header = ["Time (min)"]
            for i in range(1, self.num_devices + 1):
                header.append(f"Dev {i} Status")
            for i in range(1, self.num_devices + 1):
                header.append(f"Dev {i} RX")
            for i in range(1, self.num_devices + 1):
                header.append(f"Dev {i} TX")
            header.append("Connected Count")
            header.append("Disconnected Devices")
            ws2.append(header)
            for snapshot in self.monitoring_history:
                row = [snapshot["time_min"]]
                for i in range(self.num_devices):
                    if (i+1) in snapshot["connected"]:
                        row.append("CONNECTED")
                    else:
                        row.append("DISCONNECTED")
                for i in range(self.num_devices):
                    row.append(snapshot["rx_counts"][i])
                for i in range(self.num_devices):
                    row.append(snapshot["tx_counts"][i])
                row.append(len(snapshot["connected"]))
                row.append(", ".join(str(d) for d in snapshot["disconnected"]) if snapshot["disconnected"] else "None")
                ws2.append(row)

        ws3 = wb.create_sheet(title="Data Samples")
        ws3.append(["Device", "Direction", "Sample Data (first 10)"])
        for i in range(self.num_devices):
            rx_samples = ", ".join(self._excel_safe(x) for x in self.per_device_logs[i].get('rx', [])[:10])
            tx_samples = ", ".join(self._excel_safe(x) for x in self.per_device_logs[i].get('tx', [])[:10])
            ws3.append([i + 1, "RX (nRF->DUT)", rx_samples])
            ws3.append([i + 1, "TX (DUT->nRF)", tx_samples])

        mode_suffix = self.data_transfer_mode.replace("_", "-")
        if self.test_case_id:
            filename = f"ble_nrf_{self.test_case_id}_{self.num_central_connections}c_{self.num_peripheral_connections}p_{mode_suffix}.xlsx"
        else:
            filename = f"ble_nrf_data_transfer_{self.num_central_connections}c_{self.num_peripheral_connections}p_{mode_suffix}.xlsx"

        report_dir = None
        candidate_dirs = [
            "/app/reports",
            os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'reports'),
        ]
        for candidate in candidate_dirs:
            if os.path.isdir(candidate):
                report_dir = os.path.abspath(candidate)
                break
        if not report_dir:
            report_dir = os.getcwd()
        excel_path = os.path.abspath(os.path.join(report_dir, filename))
        try:
            wb.save(excel_path)
            logger().info(f"Results written to {excel_path}")
        except Exception as e:
            logger().error(f"Failed to write Excel file to {excel_path}: {e}")
            logger().error(f"Current report_dir: {report_dir}, CWD: {os.getcwd()}")
        logger().info("=" * 60)

    # =========================================================================
    # CLEANUP
    # =========================================================================

    def _cleanup(self):
        """Disconnect all devices, stop DUT activities, and release nRF resources."""
        logger().info("=" * 60)
        logger().info("CLEANUP: Disconnecting all devices and releasing resources")
        logger().info("=" * 60)

        for i in range(self.num_devices):
            logger().info(f"Cleaning up nRF {i+1}...")
            nrf_ble = self.nrf_bles[i]
            is_sensor = i < self.num_central_connections

            # Unsubscribe / disconnect from nRF side
            if not is_sensor:
                try:
                    nrf_ble.unsubscribe_to_notifications(characteristic_uuid=self.dut_char_uuids[i])
                except Exception as e:
                    logger().warning(f"  nRF {i+1}: unsubscribe: {e}")
                try:
                    nrf_ble.disconnect(self.target_address)
                except Exception as e:
                    logger().warning(f"  nRF {i+1}: disconnect: {e}")
            else:
                try:
                    nrf_ble.stop_advertising()
                except Exception as e:
                    logger().warning(f"  nRF {i+1}: stop_advertising: {e}")

            # Disconnect from DUT side
            try:
                if self.nrf_addrs[i]:
                    self.wifi_dut.interfaces.wifi.btc_disconnect(ble_address=self.nrf_addrs[i])
            except Exception as e:
                logger().warning(f"  nRF {i+1}: DUT disconnect: {e}")

            # Clear bonding data on the dongle
            try:
                nrf_ble.delete_bonding_data()
            except Exception as e:
                logger().warning(f"  nRF {i+1}: delete_bonding_data: {e}")
            time.sleep(1)

        # Stop ALL DUT advertising and scanning so the next test case starts from a
        # clean radio state. Leaving the DUT advertising makes the next test's
        # advertising start fail and silently kills its peripheral (phone) connections.
        self._stop_dut_adv_scan(reason="cleanup")
        time.sleep(2)

        logger().info("Cleanup complete!")


# =============================================================================
# TEST FUNCTIONS - 28 Scenarios (nRF dongle variant)
# =============================================================================

def test_C882936_nrf_ble_scanning_5c_2p_notifications(wifi_dut, nrf_ble_clients):
    """C882936: Verify the BLE scanning in the presence of 5 central(2 HT + 3LT)
    and 2 peripheral connections with Tx and Rx notifications on all the connections."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=5,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=2,
        num_lt_central=3,
        ble_scanning=True,
        test_case_id="C882936",
    )
    test.execute()


def test_C882970_nrf_ble_scanning_8c_2p_notifications(wifi_dut, nrf_ble_clients):
    """C882970: Verify the BLE scanning in the presence of 8 central (4HT+4LT)
    and 2 peripheral connections with Tx and Rx notifications on all the connections."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=8,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=4,
        num_lt_central=4,
        ble_scanning=True,
        test_case_id="C882970",
    )
    test.execute()


def test_C882972_nrf_ble_scanning_advertising_5c_0p_notifications(wifi_dut, nrf_ble_clients):
    """C882972: Verify BLE Scanning and BLE Advertising in the presence of 5 central
    (2HT+3LT) connections with Tx and Rx notifications on all the connections."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=5,
        num_peripheral_connections=0,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=2,
        num_lt_central=3,
        ble_scanning=True,
        ble_advertising=True,
        test_case_id="C882972",
    )
    test.execute()


def test_C882966_nrf_ble_scanning_advertising_8c_0p_notifications(wifi_dut, nrf_ble_clients):
    """C882966: Verify BLE Scanning and BLE Advertising in the presence of 8 central
    (4HT+4LT) connections with Tx and Rx notifications on all the connections."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=8,
        num_peripheral_connections=0,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=4,
        num_lt_central=4,
        ble_scanning=True,
        ble_advertising=True,
        test_case_id="C882966",
    )
    test.execute()


def test_C882973_nrf_ble_scanning_advertising_5c_1p(wifi_dut, nrf_ble_clients):
    """C882973: Verify BLE Scanning and BLE Advertising in the presence of 5 central
    (2HT+3LT) connections + 1 Peripheral connections."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=5,
        num_peripheral_connections=1,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=2,
        num_lt_central=3,
        ble_scanning=True,
        ble_advertising=True,
        test_case_id="C882973",
    )
    test.execute()


def test_C882967_nrf_ble_scanning_advertising_8c_1p(wifi_dut, nrf_ble_clients):
    """C882967: Verify BLE Scanning and BLE Advertising in the presence of 8 central
    (4HT+4LT) connections + 1 Peripheral connections."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=8,
        num_peripheral_connections=1,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=4,
        num_lt_central=4,
        ble_scanning=True,
        ble_advertising=True,
        test_case_id="C882967",
    )
    test.execute()


def test_C882976_nrf_ble_scanning_nonconn_adv_5c_2p(wifi_dut, nrf_ble_clients):
    """C882976: Verify BLE Scanning and BLE Advertising (Non-conn) in the presence of
    5 central (2HT+3LT) connections + 2 Peripheral connection."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=5,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=2,
        num_lt_central=3,
        ble_scanning=True,
        ble_advertising=True,
        non_connectable_adv=True,
        test_case_id="C882976",
    )
    test.execute()


def test_C882968_nrf_ble_scanning_nonconn_adv_8c_2p(wifi_dut, nrf_ble_clients):
    """C882968: Verify BLE Scanning and BLE Advertising (Non-conn) in the presence of
    8 central(4HT+4LT) connections + 2 Peripheral connection."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=8,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=4,
        num_lt_central=4,
        ble_scanning=True,
        ble_advertising=True,
        non_connectable_adv=True,
        test_case_id="C882968",
    )
    test.execute()


def test_C882977_nrf_5c_write_no_resp_rx_notif_2p_notifications(wifi_dut, nrf_ble_clients):
    """C882977: Verify BLE 5 Central (2HT+3LT) connections with GATT service
    Write-without-response & Rx Notifications and BLE 2 Peripheral connections
    with Tx & Rx notifications."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=5,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=2,
        num_lt_central=3,
        central_data_transfer_mode="write_without_response",
        peripheral_data_transfer_mode="notification",
        test_case_id="C882977",
    )
    test.execute()


def test_C882969_nrf_8c_write_no_resp_rx_notif_2p_notifications(wifi_dut, nrf_ble_clients):
    """C882969: Verify BLE 8 Central (4HT+4LT) connections with GATT service
    Write-without-response & Rx Notifications and BLE 2 Peripheral connections
    with Tx & Rx notifications."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=8,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=4,
        num_lt_central=4,
        central_data_transfer_mode="write_without_response",
        peripheral_data_transfer_mode="notification",
        test_case_id="C882969",
    )
    test.execute()


def test_C882978_nrf_5c_2p_indications_rx_notifications(wifi_dut, nrf_ble_clients):
    """C882978: Verify BLE 5 central(2HT+3LT) + 2 Peripheral connections with
    indications & Rx notifications enabled on them."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=5,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="indication",
        num_ht_central=2,
        num_lt_central=3,
        test_case_id="C882978",
    )
    test.execute()


def test_C882979_nrf_8c_2p_indications_rx_notifications(wifi_dut, nrf_ble_clients):
    """C882979: Verify BLE 8 central (4HT+4LT) + 2 Peripheral connections with
    indications & Rx notifications enabled on them."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=8,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="indication",
        num_ht_central=4,
        num_lt_central=4,
        test_case_id="C882979",
    )
    test.execute()


def test_C882980_nrf_5c_diff_payloads_2p_notifications(wifi_dut, nrf_ble_clients):
    """C882980: Verify BLE 5 Central(2HT+3LT) connections with different payloads on
    HT connections and on LT connections. Enable Tx and Rx notifications on central
    connections. And 20 bytes on 2 Peripheral connections with Tx & Rx notifications."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=5,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=2,
        num_lt_central=3,
        ht_data_size=232,
        lt_data_size=20,
        data_size=20,
        test_case_id="C882980",
    )
    test.execute()


def test_C882981_nrf_8c_diff_payloads_2p_notifications(wifi_dut, nrf_ble_clients):
    """C882981: Verify BLE 8 Central (4HT+4LT) connections with different payloads on
    HT connections and on LT connections. Enable Tx and Rx notifications on central
    connections. And 20 bytes on 2 Peripheral connections with Tx & Rx notifications."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=8,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=4,
        num_lt_central=4,
        ht_data_size=232,
        lt_data_size=20,
        data_size=20,
        test_case_id="C882981",
    )
    test.execute()


def test_C882982_nrf_5c_dle_ht_only_2p_notifications(wifi_dut, nrf_ble_clients):
    """C882982: Verify BLE 5 Central (2HT+3LT) connections with DLE enabled on HT
    and DLE disabled on LT with Tx & Rx notifications on them. And 2 Peripheral
    connections with Tx/Rx notifications."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=5,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=2,
        num_lt_central=3,
        dle_enabled="ht_only",
        test_case_id="C882982",
    )
    test.execute()


def test_C882989_nrf_8c_dle_ht_only_2p_notifications(wifi_dut, nrf_ble_clients):
    """C882989: Verify BLE 8 Central (4HT+4LT) connections with DLE enabled on HT
    and DLE disabled on LT with Tx & Rx notifications on them. And 2 Peripheral
    connections with Tx/Rx notifications."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=8,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=4,
        num_lt_central=4,
        dle_enabled="ht_only",
        test_case_id="C882989",
    )
    test.execute()


def test_C882990_nrf_5c_2p_dle_all_notifications(wifi_dut, nrf_ble_clients):
    """C882990: Verify BLE 5 Central (2HT+3LT) + 2 Peripheral connection with DLE
    enabled on all the connections with Tx& Rx notifications and Tx/Rx notifications
    on peripheral."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=5,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=2,
        num_lt_central=3,
        dle_enabled=True,
        test_case_id="C882990",
    )
    test.execute()


def test_C882991_nrf_8c_2p_dle_disabled_central_notifications(wifi_dut, nrf_ble_clients):
    """C882991: Verify BLE 8 Central (4HT+4LT) + 2 Peripheral connection with DLE
    disabled on all the central connections with Tx& Rx notifications and Tx/Rx
    notifications on peripheral."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=8,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=4,
        num_lt_central=4,
        dle_enabled="disabled_central",
        test_case_id="C882991",
    )
    test.execute()


def test_C882992_nrf_5c_2p_random_address_notifications(wifi_dut, nrf_ble_clients):
    """C882992: Verify BLE 5 Central (2HT+3LT) with data for Tx & Rx notifications
    and BLE 2 Peripheral connection with Tx/Rx notifications using the Random Address
    for DUT."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=5,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=2,
        num_lt_central=3,
        use_random_address=True,
        test_case_id="C882992",
    )
    test.execute()


def test_C882993_nrf_8c_2p_random_address_notifications(wifi_dut, nrf_ble_clients):
    """C882993: Verify BLE 8 Central(4HT+4LT) with data for Tx & Rx notifications
    and BLE 2 Peripheral connection with Tx/Rx notifications using the Random Address
    for DUT."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=8,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=4,
        num_lt_central=4,
        use_random_address=True,
        test_case_id="C882993",
    )
    test.execute()


def test_C882994_nrf_5c_2p_2m_phy_notifications(wifi_dut, nrf_ble_clients):
    """C882994: Verify BLE 5 Central(2HT+3LT) and 2 Peripheral connections with data
    on 2M phy rates on all the connections with Tx and Rx notifications and Tx/Rx
    notifications on peripheral connections."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=5,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=2,
        num_lt_central=3,
        phy_rate="2M",
        test_case_id="C882994",
    )
    test.execute()


def test_C882995_nrf_8c_2p_2m_phy_notifications(wifi_dut, nrf_ble_clients):
    """C882995: Verify BLE 8 Central(4HT+4LT) and 2 Peripheral connections with data
    on 2M phy rates on all the connections with Tx and Rx notifications and Tx/Rx
    notifications on peripheral connections."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=8,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=4,
        num_lt_central=4,
        phy_rate="2M",
        test_case_id="C882995",
    )
    test.execute()


def test_C882996_nrf_5c_2p_random_reconnect_notifications(wifi_dut, nrf_ble_clients):
    """C882996: Verify that BLE 5 central(2HT+3LT) connections are randomly connected
    with Tx/Rx notifications and 2 peripheral connections with Tx/Rx notifications.
    Perform random connect - reconnect of the central connections."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=5,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=2,
        num_lt_central=3,
        random_reconnect=True,
        test_case_id="C882996",
    )
    test.execute()


def test_C882997_nrf_8c_2p_random_reconnect_notifications(wifi_dut, nrf_ble_clients):
    """C882997: Verify that BLE 8 central(4HT+4LT) connections are randomly connected
    with Tx/Rx notifications and 2 peripheral connections with Tx/Rx notifications.
    Perform random connect - reconnect of the central connections."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=8,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=4,
        num_lt_central=4,
        random_reconnect=True,
        test_case_id="C882997",
    )
    test.execute()


def test_C958915_nrf_8c_2p_io_cap_0x00_notifications(wifi_dut, nrf_ble_clients):
    """C958915: Verify BLE 8 central (4HT+4LT) with I/O Capability 0X00 + 2 Peripheral
    connections with TX & Rx notifications enabled on them."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=8,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=4,
        num_lt_central=4,
        io_capability=0x00,
        nrf_io_capability=NRFBLEIoCapabilities.DISPLAY_ONLY,
        test_case_id="C958915",
    )
    test.execute()


def test_C958916_nrf_8c_2p_io_cap_0x01_notifications(wifi_dut, nrf_ble_clients):
    """C958916: Verify BLE 8 central (4HT+4LT) with I/O Capability 0X01 + 2 Peripheral
    connections with TX & Rx notifications enabled on them."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=8,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=4,
        num_lt_central=4,
        io_capability=0x01,
        nrf_io_capability=NRFBLEIoCapabilities.DISPLAY_YESNO,
        test_case_id="C958916",
    )
    test.execute()


def test_C958917_nrf_8c_2p_io_cap_0x04_notifications(wifi_dut, nrf_ble_clients):
    """C958917: Verify BLE 8 central (4HT+4LT) with I/O Capability 0X04 + 2 Peripheral
    connections with TX & Rx notifications enabled on them."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=8,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=4,
        num_lt_central=4,
        io_capability=0x04,
        nrf_io_capability=NRFBLEIoCapabilities.KEYBOARD_DISPLAY,
        test_case_id="C958917",
    )
    test.execute()


def test_C958918_nrf_8c_2p_io_cap_0x03_notifications(wifi_dut, nrf_ble_clients):
    """C958918: Verify BLE 8 central (4HT+4LT) with I/O Capability 0X03 + 2 Peripheral
    connections with TX & Rx notifications enabled on them."""
    test = BLEMultiDataTransferTestNRF(
        wifi_dut=wifi_dut,
        nrf_clients=nrf_ble_clients,
        num_central_connections=8,
        num_peripheral_connections=2,
        test_duration=300,
        data_transfer_mode="notification",
        num_ht_central=4,
        num_lt_central=4,
        io_capability=0x03,
        nrf_io_capability=NRFBLEIoCapabilities.NONE,
        test_case_id="C958918",
    )
    test.execute()
