import subprocess
import re
import urllib.parse
import urllib.request
import zipfile
import socket
import sys
import time
from pathlib import Path
from tempfile import NamedTemporaryFile

import click
import os

import requests
from opentelemetry.instrumentation.urllib3 import URLLib3Instrumentor
from requests.auth import HTTPBasicAuth

from utf.executor.launch_utf_tests import (
    UtfLauncher,
    UtfLaunchCommander,
    UtfLauncherCmdOption,
)
from utf.utils.artifactory_manager import UNC_PATH_PREPENDED

try:
    # Attempt to import get_version from utf, if it fails, define a fallback that returns None to support older versions of utf_core
    from utf import get_version
except ImportError:
    def get_version():
        return None

DOCKERFILE_PATH = "executor/Dockerfile"
WORKSPACE_ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
WINDOWS_MEDIA_SERVER_PORT = 5000
WINDOWS_MEDIA_SERVER_SCRIPT = os.path.join(
    WORKSPACE_ROOT,
    "example_test_package",
    "sqa_test_suites",
    "ble_wearables",
    "windows_player.py",
)


def _get_local_ip_for_target(target: str) -> str:
    """Return the Windows host address used to route traffic to the test target."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((target, 9))
        return sock.getsockname()[0]


def _wait_for_media_server(media_server_url: str, timeout_sec: int = 10) -> bool:
    """Wait until the Windows Media Player HTTP service accepts requests."""
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                f"{media_server_url}/status", timeout=1
            ) as response:
                if response.status == 200:
                    return True
        except Exception:
            time.sleep(0.25)
    return False


def _start_windows_media_server(target: str):
    """
    Start the Windows Media Player service for a Docker test run.

    The service is started on the Windows launch host, while the Docker test
    reaches it through the Windows address routed to ``target``.
    """
    if os.name != "nt":
        return None

    media_server_url = os.environ.get("WINDOWS_MEDIA_SERVER_URL")
    if not media_server_url:
        media_server_url = (
            f"http://{_get_local_ip_for_target(target)}:{WINDOWS_MEDIA_SERVER_PORT}"
        )
        os.environ["WINDOWS_MEDIA_SERVER_URL"] = media_server_url

    media_server_url = media_server_url.rstrip("/")
    if _wait_for_media_server(media_server_url, timeout_sec=1):
        print(f"Using existing Windows Media Player service: {media_server_url}")
        return None

    if not os.path.isfile(WINDOWS_MEDIA_SERVER_SCRIPT):
        raise FileNotFoundError(
            f"Windows Media Player service script not found: "
            f"{WINDOWS_MEDIA_SERVER_SCRIPT}"
        )

    print(f"Starting Windows Media Player service: {media_server_url}")
    media_server_process = subprocess.Popen(
        [sys.executable, WINDOWS_MEDIA_SERVER_SCRIPT],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )
    if not _wait_for_media_server(media_server_url):
        media_server_process.terminate()
        raise RuntimeError(
            "Windows Media Player service did not start. Verify pywin32 is "
            "installed and the configured audio file exists."
        )
    return media_server_process


def _stop_windows_media_server(media_server_process):
    """Stop the media service started by this launcher."""
    if media_server_process is None:
        return
    try:
        media_server_process.terminate()
        media_server_process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        media_server_process.kill()


def get_milestone_branch_from_git_branch():
    rc = subprocess.Popen(
        "git log", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    stdout, stderr = rc.communicate()
    get_all_milestone = []
    get_all_milestone = re.findall("release/milestone([0-9]+)", stdout.decode())
    milestone = [int(i) for i in get_all_milestone]
    milestone.sort()
    current_milestone = "release/milestone" + str(milestone[-1])
    return current_milestone


class AppUtfLauncher(UtfLauncher):
    def __init__(self, **kwargs):
        UtfLauncher.__init__(self, **kwargs)

    def get_params_defaults(self) -> dict:
        milestone_branch = os.environ.get("MILESTONE_BRANCH_NAME")
        if not milestone_branch:
            milestone_branch = get_milestone_branch_from_git_branch()
        framework_version = get_version() or "unknown"
        return {
            UtfLauncherCmdOption.workspace_root: WORKSPACE_ROOT,
            UtfLauncherCmdOption.reports_dir: os.path.join(WORKSPACE_ROOT, "reports"),
            UtfLauncherCmdOption.container_name: "wifitest_1",
            UtfLauncherCmdOption.docker_image_tag: "wifitest:latest",
            UtfLauncherCmdOption.docker_file_path: DOCKERFILE_PATH,
            UtfLauncherCmdOption.docker_flags: (
                f"-e MILESTONE={milestone_branch}, "
                f"-e FRAMEWORK_VERSION={framework_version}, "
                f"-e WINDOWS_MEDIA_SERVER_URL="
                f"{os.environ.get('WINDOWS_MEDIA_SERVER_URL', '')}"
            ),
            UtfLauncherCmdOption.docker_base_image: "utfsilabs/rpi_ubuntu_android:2025_10_24",
            UtfLauncherCmdOption.username: "pi",
            UtfLauncherCmdOption.password: "raspberry",
        }

    def prepare_and_download_binary_rps(self):
        try:
            branch_name = os.environ.get("BRANCH_NAME")
            sdk_build_num = os.environ.get("SDK_BUILD_NUM")
            artifactory_folder_url = f"https://artifactory.silabs.net/artifactory/gsdk-generic-development/{branch_name}/{sdk_build_num}/extension/wiseconnect.zip"
            rps_inner_dir = "connectivity_firmware/standard"
            destination_path = os.path.join(
                WORKSPACE_ROOT,
                "manifest",
            )
            downloaded_files_list = self.download_and_extract_rps_from_zip(
                zip_url=artifactory_folder_url,
                destination_dir=destination_path,
                inner_folder=rps_inner_dir,
            )
            if downloaded_files_list:
                return downloaded_files_list[0]
        except Exception as e:
            print(f"Failed to download the binary rps file due to {e}")

    @staticmethod
    def download_and_extract_rps_from_zip(zip_url, inner_folder, destination_dir):
        """Download a .zip file from Artifactory and extract only .rps files from a specific subfolder.

        Args:
            zip_url: Full URL to the .zip artifact in Artifactory.
            inner_folder: Subfolder path inside the zip to search for .rps files
                          (e.g. "connectivity_firmware/standard").
            destination_dir: Local directory where the .rps files should be saved.
            auth: Authentication credentials for Artifactory (tuple of username, password).

        :returns: True if at least one .rps file was extracted, False otherwise.

        """

        temp_zip_path = None

        try:
            print(f"Downloading zip from {zip_url}")
            # URLLib3Instrumentor().uninstrument()
            # Download the entire zip to memory first
            response = requests.get(zip_url, timeout=180)
            response.raise_for_status()
            zip_content = response.content

            # Ensure destination directory exists
            dest_dir_path = Path(UNC_PATH_PREPENDED + destination_dir)
            dest_dir_path.mkdir(parents=True, exist_ok=True)

            # Write zip content to temporary file
            with NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
                temp_zip_path = tmp.name
                tmp.write(zip_content)
                print(f"Wrote zip to {temp_zip_path}")

            # Normalize inner_folder path
            inner_folder_norm = inner_folder.replace("\\", "/").rstrip("/")
            print(f"Extracting .rps files from subfolder '{inner_folder_norm}'")
            extracted_count = 0
            try:
                with zipfile.ZipFile(temp_zip_path, "r") as zip_ref:
                    # List all files in the zip for debugging
                    all_files = zip_ref.namelist()
                    # Find matching files
                    matching_files = []
                    for filename in all_files:
                        # Normalize path
                        norm_filename = filename.replace("\\", "/")

                        # Check if in target subfolder and is .rps
                        if norm_filename.startswith(
                            inner_folder_norm + "/"
                        ) and norm_filename.lower().endswith(".rps"):
                            matching_files.append(filename)

                    print(
                        f"Found {len(matching_files)} .rps files in '{inner_folder_norm}'"
                    )

                    if len(matching_files) == 0:
                        print(
                            f"Available subfolders: {set([f.split('/')[0] for f in all_files])}"
                        )

                    # Extract matching files
                    for filename in matching_files:
                        rps_filename = Path(filename).name
                        target_path = dest_dir_path / rps_filename

                        # Read from zip and write to destination
                        content = zip_ref.read(filename)
                        with open(target_path, "wb") as f:
                            f.write(content)

                        print(f"Extracted: {rps_filename}")
                        extracted_count += 1

            except zipfile.BadZipFile as e:
                print(f"BadZipFile error: {e}")
                print(
                    f"Temp file: {temp_zip_path}, Size: {os.path.getsize(temp_zip_path)} bytes"
                )
                return False

            if extracted_count == 0:
                print(f"No .rps files found in '{inner_folder_norm}' folder")
                return False

            print(
                f"Successfully extracted {extracted_count} .rps file(s) to {dest_dir_path}"
            )
            return matching_files

        except requests.exceptions.HTTPError as e:
            print(f"HTTP error during download: {e}")
            print(f"Status code: {e.response.status_code}")
            print(f"Response: {e.response.text[:500]}")
            return False
        except requests.exceptions.RequestException as e:
            print(f"Request error while downloading zip: {e}")
            return False
        except Exception as e:
            print(f"Error while downloading/extracting zip: {e}")
            import traceback

            traceback.print_exc()
            return False
        finally:
            # URLLib3Instrumentor().instrument()
            if temp_zip_path and os.path.exists(temp_zip_path):
                try:
                    os.remove(temp_zip_path)
                except OSError:
                    pass

    def generate_keys_files_from_hwmux(self, hwmux_group_data):
        metadata = hwmux_group_data["metadata"]
        secure_keys = metadata.get("SECURITY_KEYS", None)
        if secure_keys is not None:
            self.logger.info("Generating keys files from HWMux metadata")
            output_dir = os.path.join(
                WORKSPACE_ROOT,
                "manifest",
                "secure_firmware_keys",
            )
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            for key, value in secure_keys.items():
                file_data = value
                file_path = os.path.join(output_dir, key)
                # Write the data to the file
                with open(file_path, "w") as file:
                    file.write(file_data)

    def transform_hwmux_data_to_template_kwargs(self, hwmux_group_data: dict) -> dict:
        """
        Transforms hwmux testbed group data to a dict containing variables to be used
        in rendering a harness template.

        Override this method in your `AppUtfLauncher` class as needed

        Args:
            hwmux_group_data:  dict with hwmux testbed group data

        Returns:
            dict containing transformed group data

        """
        binary_file_name_wit_path = self.prepare_and_download_binary_rps()
        self.generate_keys_files_from_hwmux(hwmux_group_data)
        if binary_file_name_wit_path:
            binary_file_name = str(os.path.basename(binary_file_name_wit_path))
            print(f"set efr binary_file_name in manifest as - {binary_file_name}")
            hwmux_group_data["binary_file_name"] = binary_file_name
        return hwmux_group_data


@click.command(cls=UtfLaunchCommander)
def main(**kwargs):
    if os.environ.get("UTF_QUEUE_SERVER_URL"):
        os.environ.pop("UTF_QUEUE_SERVER_URL")
        print(
            f"UTF_QUEUE_SERVER_URL is now set to {os.environ.get('UTF_QUEUE_SERVER_URL')}"
        )
    media_server_process = _start_windows_media_server(
        kwargs.get(UtfLauncherCmdOption.target)
    )
    try:
        launcher = AppUtfLauncher(**kwargs)
        launcher.execute()
    finally:
        _stop_windows_media_server(media_server_process)


if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
