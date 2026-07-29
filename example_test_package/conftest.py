import time
import subprocess
import sys

from utf import TestResultsModelAttrs, TestUserPropertiesSource
from utf.apis.test_rail import extract_test_case_id

from utf.env_settings import EnvironSettings
from utf.utils import (
    is_publish_test_results_enabled,
    is_test_results_source_api_enabled,
)
from utf.utils.test_management.test_definition_utils import (
    generate_base_test_definitions_yaml,
)
from utf_wiseconnect.interfaces.web.fixtures import *  # NOSONAR
from utf_wiseconnect.interfaces.sniffer_filter.fixtures import * # NOSONAR
from utf_wiseconnect.interfaces.power_analyzer.fixtures import * # NOSONAR
from utf_wiseconnect.interfaces.performance_data.fixtures import * # NOSONAR
from utf_wiseconnect.interfaces.sniffer_filter.fixtures import *  # NOSONAR
from utf_wiseconnect.interfaces.power_analyzer.fixtures import *  # NOSONAR

import pytest
import os
from utf.utils.firmware_manager import FirmwareManager
from utf.devices import Device
from typing import Generator, List
from utf.utils.logger import get_logger
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utf_config import UtfConfig
from utf.utils.fixtures import harness
from utf.harness.harness import Harness
from utf_wiseconnect.utils.rs_helper_commands import RSHelperCommands
from utf_wiseconnect_3.tests.interfaces.sl_collections import SLCollections
from utf_wifi_zephyr.interfaces.zephyr_wifi_collections import ZephyrWifiCollections
from utf_wiseconnect.utils.rs_helper_commands_ble import RSHelperCommandsBle
import utf.utils.commander as commander
from utf_wiseconnect.devices.rs911x import RS911X

from utf.utils.vault import VaultClient
from utf.utf_config import  get_or_create_reports_session_dir
from utf.utf_session import get_active_session
from utf.utf_queue_session import UtfQueueSession
from data_transform.generate_perf_data import generate_perf_data_files
from data_transform.send_perf_data_to_datalake import send_perf_data
from xray_integration.xray_mgmt import XrayMgmtSource
try:
    from executor.launch_utf_tests import get_milestone_branch_from_git_branch
except ImportError:
    pass

last_loaded_custom_app_name = None
last_test_mode = None
default_test_mode = None

# Constants for Vault and Jira/Xray configuration
VAULT_ADDR_KEY = "VAULT_ADDR"
VAULT_TOKEN_KEY = "VAULT_TOKEN"
JIRA_SECRET_PATH = "teams/infra-sw/app/jira_xray"
JIRA_SERVER_URL_KEY = "JIRA_SERVER_URL"
JIRA_API_TOKEN_KEY = "JIRA_API_TOKEN"
XRAY_PROJECT_KEY = "XRAY_TC_TS_PROJECT_KEY"


def _setup_jira_xray_credentials_from_vault():
    """
    Setup Jira/Xray credentials from Vault for both Docker and local runs.
    Retrieves credentials from Vault and sets them as environment variables.
    """
    try:
        env_settings = EnvironSettings()
        if env_settings.VAULT_ADDR and env_settings.VAULT_TOKEN:
            os.environ[VAULT_ADDR_KEY] = env_settings.VAULT_ADDR
            os.environ[VAULT_TOKEN_KEY] = env_settings.VAULT_TOKEN

            vault_client = VaultClient()
            jira_credentials = vault_client.get_secret_values(
                JIRA_SECRET_PATH,
                [JIRA_SERVER_URL_KEY, JIRA_API_TOKEN_KEY, XRAY_PROJECT_KEY]
            )

            # Set as environment variables for XraySettings to read
            if jira_credentials:
                os.environ[JIRA_SERVER_URL_KEY] = jira_credentials.get(JIRA_SERVER_URL_KEY, "")
                os.environ[JIRA_API_TOKEN_KEY] = jira_credentials.get(JIRA_API_TOKEN_KEY, "")
                os.environ[XRAY_PROJECT_KEY] = jira_credentials.get(XRAY_PROJECT_KEY, "")
                logger().info("Successfully loaded Jira/Xray credentials from Vault")
    except Exception as e:
        logger().warning(f"Unable to load Jira/Xray credentials from Vault: {e}")


def pytest_configure(config):
    """
    Ensure _metadata attribute is initialized for pytest-metadata plugin.
    Also sets up Jira/Xray credentials from Vault for the test session.
    """
    if not hasattr(config, "_metadata"):
        config._metadata = {}
    
    _setup_jira_xray_credentials_from_vault()


def logger():
    return get_logger(__name__)


@pytest.fixture(autouse=True, scope="function")
def sl_debug_log_capture(request):
    """
    Fixture to capture SL debug logs for each test case using subprocess to run Log_script_v2.py.
    
    This fixture automatically starts the log capture in a separate process at the beginning 
    of each test and stops it when the test completes. The logs are saved to a test-specific 
    output file with a timestamp.
    
    Configure via settings:
    - SL_DEBUG_LOG_ENABLE: Enable/disable log capture (default: False)
    - SL_DEBUG_LOG_DEVICE: J-Link device name (default: SiWG917M111M)
    
    Args:
        request: pytest FixtureRequest object providing test context
    
    Yields:
        subprocess.Popen: The log capture process
    """
    
    def _normalize_test_name(test_name):
        """Normalize test name for use in file paths."""
        return test_name.replace("[", "_").replace("]", "_").replace("::", "_")

    def _get_sl_debug_log_paths(request, workspace_root, test_name):
        """
        Build all necessary file paths for SL debug log capture.
        
        Args:
            request: pytest FixtureRequest object
            workspace_root: Workspace root directory path
            test_name: Normalized test name
            
        Returns:
            tuple: (log_script_path, output_file, descriptor_file, log_filename)
        """
        from datetime import datetime
        
        log_script_path = os.path.join(
            workspace_root, "utf_wiseconnect", "utf_wiseconnect", "utils", "sl_debug_log", "log_script_v2.py"
        )
        
        # Get manifest file path from pytest config
        manifest_file_path = request.config.getoption("manifest", default=None)
        
        if manifest_file_path:
            # Extract manifest directory from the provided path
            manifest_dir = os.path.dirname(manifest_file_path) if os.path.dirname(manifest_file_path) else os.path.join(workspace_root, "manifest")
            
            # Build full paths relative to workspace root if manifest path is relative
            if not os.path.isabs(manifest_file_path):
                manifest_dir = os.path.join(workspace_root, manifest_dir)
            
            output_file = os.path.join(manifest_dir, "test_agent.out")
            descriptor_file = os.path.join(manifest_dir, "SYSVIEW_CaptiveCore.txt")
        else:
            # Fallback to default manifest directory if not specified
            manifest_dir = os.path.join(workspace_root, "manifest")
            output_file = os.path.join(manifest_dir, "test_agent.out")
            descriptor_file = os.path.join(manifest_dir, "SYSVIEW_CaptiveCore.txt")
        
        # Get reports directory for log file
        try:
            reports_dir = get_or_create_reports_session_dir(request.config)
        except Exception as e:
            logger().warning(f"Could not get reports directory: {e}. Using current directory.")
            reports_dir = os.getcwd()
        
        # Generate timestamped log filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename = os.path.join(reports_dir, f"log_{test_name}_{timestamp}.txt")
        
        return log_script_path, output_file, descriptor_file, log_filename

    def _build_sl_debug_log_command(log_script_path, device_name, output_file, descriptor_file, log_filename):
        """
        Build the command list to run the SL debug log script.
        
        Args:
            log_script_path: Path to Log_script_v2.py
            device_name: J-Link device name
            output_file: ELF output file path
            descriptor_file: SYSVIEW descriptor file path
            log_filename: Log output file path
            
        Returns:
            list: Command list for subprocess
        """
        return [
            sys.executable,
            log_script_path,
            "--source", "rtt",
            "--device", device_name,
            "--out", output_file,
            "--descriptor", descriptor_file,
            "--max-args", "3",
            "--log-file", log_filename
        ]

    def _start_sl_debug_log_process(cmd, test_name, device_name, manifest_file_path, descriptor_file, log_filename, output_file):
        """
        Start the SL debug log capture process and validate it started successfully.
        
        Args:
            cmd: Command list for subprocess
            test_name: Test name for logging
            device_name: J-Link device name
            manifest_file_path: Manifest file path (optional)
            descriptor_file: SYSVIEW descriptor file path
            log_filename: Log output file path
            output_file: ELF output file path
            
        Returns:
            subprocess.Popen: The started process, or None if failed
        """
        try:
            # Start the log capture as a subprocess
            logger().info(f"Starting SL debug log capture for test: {test_name}")
            logger().info(f"J-Link device: {device_name}")
            if manifest_file_path:
                logger().info(f"Using manifest: {manifest_file_path}")
            logger().info(f"Descriptor file: {descriptor_file}")
            logger().info(f"Log output will be saved to: {log_filename}")
            logger().info(f"ELF output file: {output_file}")
            
            # Start the process without capturing stdout/stderr so it writes directly to files
            log_process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Give the log capture process time to initialize RTT connection
            time.sleep(3)
            
            # Check if process is still running
            if log_process.poll() is not None:
                _, stderr = log_process.communicate()
                logger().warning(f"Log capture process exited early. stderr: {stderr}")
                logger().warning("Continuing test execution without log capture...")
                return None
            else:
                logger().info("Log capture process is running successfully")
                return log_process
                
        except Exception as e:
            logger().error(f"Failed to start log capture: {e}")
            logger().warning("Continuing test execution without log capture...")
            return None

    def _stop_sl_debug_log_process(log_process, test_name, log_filename):
        """
        Terminate and kill the SL debug log capture process.
        
        Args:
            log_process: The subprocess.Popen object
            test_name: Test name for logging
            log_filename: Log output file path for logging
        """
        if log_process and log_process.poll() is None:
            logger().info(f"Test {test_name} completed.")
            logger().info("Stopping log capture process...")
            try:
                log_process.terminate()
                # Wait briefly for graceful termination
                try:
                    log_process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate gracefully
                    logger().warning("Log capture process did not terminate gracefully, force killing...")
                    log_process.kill()
                    log_process.wait()
                logger().info(f"Log capture complete. Log file saved to: {log_filename}")
            except Exception as e:
                logger().warning(f"Error while stopping log capture: {e}")
    
    env_settings = EnvironSettings()
    
    # Check if SL debug log capture is enabled
    if env_settings.SL_DEBUG_LOG_ENABLE.lower() not in ("true", "1", "yes"):
        yield None
        return
    
    # Build paths using os.path.join for consistency
    workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    test_name = _normalize_test_name(request.node.name)
    
    # Get all necessary file paths
    log_script_path, output_file, descriptor_file, log_filename = _get_sl_debug_log_paths(
        request, workspace_root, test_name
    )
    
    # Get device name from settings
    device_name = env_settings.SL_DEBUG_LOG_DEVICE
    
    # Build the command to run the log script as a subprocess
    cmd = _build_sl_debug_log_command(
        log_script_path, device_name, output_file, descriptor_file, log_filename
    )
    
    # Get manifest file path for logging
    manifest_file_path = request.config.getoption("manifest", default=None)
    
    # Start the log capture process
    log_process = _start_sl_debug_log_process(
        cmd, request.node.name, device_name, manifest_file_path, 
        descriptor_file, log_filename, output_file
    )
    
    try:
        yield log_process
    finally:
        # Clean up: terminate and kill the log capture process after test completes
        _stop_sl_debug_log_process(log_process, request.node.name, log_filename)


@pytest.fixture(autouse=True, scope="module")
def reset_wiseconnect_duts(request, harness):
    """
    This fixture creates devices from configuration specified under defaults and under
    wiseconnect_duts section and calls reset on each device at a module level

    Args:
        request: ``FixtureRequest`` This object provides information of requesting test case
        harness: ``Harness`` This object represents test bed configuration

    Returns:
        None
    """
    try:
        wiseconnect_duts = harness.create_devices_for_role("wiseconnect_duts", request)
        for dut in wiseconnect_duts:
            try:
                logger().info(
                    f"Calling device reset from module level fixture for device '{dut.name}'"
                )
                dut.reset()
                dut.release_resources()
            except Exception as e:
                logger().error(
                    f"Failed to reset from module level fixture for device '{dut.name}' - {e}"
                )
    except Exception as e:
        logger().error(f"Failed to reset from module level fixture - {e}")


@pytest.fixture()
def wiseconnect_duts(
        request: pytest.FixtureRequest, harness
) -> Generator[List[Device], None, None]:
    """
    This fixture creates devices from configuration specified under defaults and under wiseconnect_duts section

    Args:
        request: ``FixtureRequest`` This object provides information of requesting test case
        harness: ``Harness`` This object represents test bed configuration

    Returns:
        None
    """
    wiseconnect_duts = harness.create_devices_for_role(request.fixturename, request)

    yield wiseconnect_duts


@pytest.fixture()
def firmware_loader(request, wiseconnect_duts):
    """
    This fixture loads firmware on devices from configuration specified in manifest file under firmware_applications
    section under specified marker on test case

    Args:
        request: ``FixtureRequest`` This object provides context of requesting test case
        wiseconnect_duts: ``List[Device]`` list of devices on which firmware is loaded

    Returns:
        None
    """
    for mark in request.node.iter_markers("firmware_app"):
        app_name = mark.args[0]
        fw_mgr = FirmwareManager.get_instance()
        if fw_mgr is not None:
            fw_mgr.load_app_firmware(app_name, wiseconnect_duts)
            global last_loaded_custom_app_name
            last_loaded_custom_app_name = app_name
        yield fw_mgr


@pytest.fixture(autouse=True, scope="function")
def roll_back_to_default_firmware(request, wiseconnect_duts):
    global last_loaded_custom_app_name
    if (
            "firmware_loader" not in request.fixturenames
            and last_loaded_custom_app_name is not None
    ):
        fw_mgr = FirmwareManager.get_instance()
        fw_mgr.roll_back_to_default_firmware(
            last_loaded_custom_app_name, wiseconnect_duts
        )
        last_loaded_custom_app_name = None


@pytest.fixture(autouse=True, scope="session")
def store_environment_info(request, harness: Harness):
    milestone = os.environ.get("MILESTONE",None)
    if milestone is None:
        milestone = get_milestone_branch_from_git_branch()
    request.config._metadata["Milestone"] = milestone
    manifest_file: str = request.config.getoption("manifest")
    if manifest_file is not None:
        request.config._metadata["DUT Firmware Version"] = parse_version(manifest_file)
    else:
        request.config._metadata["DUT Firmware Version"] = "Firmware not loaded"
    dut = UtfConfig.instance().defaults.get("dut", {})
    dut_type = UtfConfig.instance().data.get("devices", {}).get(dut, {}).get("type", "")
    request.config._metadata["DUT Type"] = dut_type
    dut_subtype = (
        UtfConfig.instance().data.get("devices", {}).get(dut, {}).get("subtype", "")
    )
    request.config._metadata["DUT Sub Type"] = dut_subtype
    access_point = UtfConfig.instance().defaults.get("wifi_access_point")
    access_point_type = (
        UtfConfig.instance()
        .data.get("devices", {})
        .get(access_point, {})
        .get("interfaces", {})
        .get("wifi", {})
        .get("type", "")
    )
    access_point_type = access_point_type.split(".")[-1]
    request.config._metadata["Access point Type"] = access_point_type
    global default_test_mode
    default_test_mode = UtfConfig.instance().defaults.get("dut")
    global last_test_mode
    last_test_mode = default_test_mode


def pytest_collection_modifyitems(config, items):
    if config.option.collectonly:
        generate_base_test_definitions_yaml(os.getcwd(), items)


@pytest.fixture()
def rs_helper(request):
    yield RSHelperCommands.create_instance()


@pytest.fixture()
def sl_collections(request):
    yield SLCollections.create_instance()


@pytest.fixture()
def zephyr_wifi_collections(request):
    yield ZephyrWifiCollections.create_instance()


@pytest.fixture()
def rs_helper_ble(request):
    yield RSHelperCommandsBle.create_instance()


@pytest.fixture(autouse=True, scope="function")
def reset_on_test_mode_change(request, wiseconnect_duts, harness):
    """
    This fixture checks for change in test mode between last executed test case and current test case
    and does device reset on device if there is change

    Args:
        request: ``FixtureRequest`` This object provides context of requesting test case
        wiseconnect_duts: ``List[Device]`` list of devices on which reset happens
        harness: ``Harness`` This object represents test bed configuration

    Returns:
        None

    """
    markers_list = list(request.node.iter_markers(name="dut"))
    if markers_list:
        marker = markers_list[0]
        current_test_mode = marker.args[0]
    else:
        current_test_mode = default_test_mode
    global last_test_mode
    dut = harness.create_device(current_test_mode)
    for i in range(len(wiseconnect_duts)):
        if isinstance(wiseconnect_duts[i], RS911X):
            wiseconnect_duts[i] = dut
            break
    if current_test_mode != last_test_mode:
        for device in wiseconnect_duts:
            device.reset()
        last_test_mode = current_test_mode


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_protocol(item, nextitem):
    if is_publish_test_results_enabled() and is_test_results_source_api_enabled():
        module_name = "917"
        settings = EnvironSettings()
        case_id = extract_test_case_id(item.originalname)
        tool_chain = "GCC 10.3.1"
        if settings.TOOL_CHAIN:
            tool_chain = settings.TOOL_CHAIN

        custom_values = {
            TestResultsModelAttrs.module_name: module_name,
            TestResultsModelAttrs.tool_chain: tool_chain,
        }
        item.test_src_map_id = case_id
        item.user_properties.append((TestUserPropertiesSource.TEST_CASE_ID, case_id))
        item.user_properties.append(
            (TestUserPropertiesSource.TEST_CUSTOM_INFO, custom_values)
        )

        # Append Jira filters separately (for query filtering, not result properties)
        product_line = settings.PRODUCT_LINE if settings.PRODUCT_LINE else "917"
        item.user_properties.append(
            ("JIRA_FILTERS", {TestResultsModelAttrs.product_line: product_line})
        )

    yield

@pytest.fixture
def custom_performance_fixture(request, performance_fixture):
    performance_file_root_dir, performance_file_name = performance_fixture
    request.node.performance_file = os.path.join(
        performance_file_root_dir, f"{request.node.name}.csv"
    )
    performance_file_name = request.node.performance_file
    yield performance_file_root_dir, performance_file_name

def pytest_addoption(parser):
    parser.addoption("--generate_datalake_file", action="store",
    default="false", help="to generate datalake files")
    parser.addoption("--send_perf_data_to_datalake", action="store",
    default="false", help="to send performance data to datalake")

@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session, exitstatus) -> None:
    generate_datalake_file = session.config.getoption("--generate_datalake_file")
    if str(generate_datalake_file).upper() == "TRUE":
        try:
            reports_dir = get_or_create_reports_session_dir(session.config)
            utf_session = get_active_session()
            publish_test_results = isinstance(utf_session, UtfQueueSession)
            source_path, session_args_file, metadata_file_pattern = generate_perf_data_files(reports_dir, utf_session, publish_test_results)
            logger().info(f"Generated datalake files Successfully")
            logger().info(f"#" * 50)
            logger().info(f"--source_path - {source_path}")
            logger().info(f"--session_args_file - {session_args_file}")
            logger().info(f"--metadata_file_pattern - {metadata_file_pattern}")
            logger().info(f"#" * 50)
        except Exception as e:
            logger().error(f"Failed to Generate Perf Data Files - {e}")
            return
    send_perf_data_to_datalake  = session.config.getoption("--send_perf_data_to_datalake")
    if str(send_perf_data_to_datalake).upper() == "TRUE":
        try:
            env_settings = EnvironSettings()
            vault_addr = env_settings.VAULT_ADDR
            vault_token  = env_settings.VAULT_TOKEN
            os.environ["VAULT_ADDR"] = vault_addr
            os.environ["VAULT_TOKEN"] = vault_token
            tenant_key = VaultClient().get_secret_value(
                "teams/iot-sqa/app/datalake-tenants" , "key"
            )
        except Exception as e:
                logger().error(f"Unable to fetch tenant key from Vault {e}")
                return
        try:
            result = send_perf_data(source_path=source_path,
                session_args_file=session_args_file,
                metadata_file_pattern=metadata_file_pattern,
                datalake_env="dev",
                delete_data_files=False,
                tenant_key=tenant_key
                )
            if result:
                logger().info(f"Sent Performace files to datalake files Successfully")
        except Exception as e:
            logger().error(f"Failed to Send Perf Data to Datalake - {e}")
            
@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """
    This hook implementation is used to update user properties of test item with test management api source data before generating test report for the test item. This is required to make test management source data available in test report which is used by reporters for publishing test results to test management system.

    Args:
        item: pytest.Item object which represents the collected test case for which test report is being generated
        call: pytest.CallInfo object which represents the result of setup/call/teardown phase of the test case execution

    Returns:
        None
    """
    outcome = yield
    rep = outcome.get_result()
    if rep.when == "setup":
        # Only call XrayMgmtSource if XRAY is enabled
        test_results_source = os.environ.get("TEST_RESULTS_SOURCE_API", "").strip().upper()
        if test_results_source == "XRAY_API":
            test_case_id = ""
            custom_props = {}
            jira_filters = None
            for p in item.user_properties:
                if p[0] == TestUserPropertiesSource.TEST_CUSTOM_INFO:
                    custom_props = p[1]
                if p[0] == TestUserPropertiesSource.TEST_CASE_ID:
                    test_case_id = p[1]
                if p[0] == "JIRA_FILTERS":
                    jira_filters = p[1]

            _db_properties = XrayMgmtSource().fetch_test_results_properties(
                field_name="test_src_map_id",
                field_value=test_case_id,
                jira_filters=jira_filters,
                **custom_props
            )
            logger().info(
                f"Fetched test management source data for test case id - {test_case_id} and here it is - {_db_properties}")
            item.user_properties.append((TestUserPropertiesSource.TEST_CASE, _db_properties))
