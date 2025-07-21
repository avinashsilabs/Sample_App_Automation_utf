import subprocess
import re
import click
import os
import json
from utf.executor.launch_utf_tests import (
    UtfLauncher,
    UtfLaunchCommander,
    UtfLauncherCmdOption,
    UtfExecutorTypes,
)

DOCKERFILE_PATH = "executor/Dockerfile"
WORKSPACE_ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))


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
        return {
            UtfLauncherCmdOption.workspace_root: WORKSPACE_ROOT,
            UtfLauncherCmdOption.reports_dir: os.path.join(WORKSPACE_ROOT, "reports"),
            UtfLauncherCmdOption.container_name: "wifitest_1",
            UtfLauncherCmdOption.docker_image_tag: "wifitest:latest",
            UtfLauncherCmdOption.docker_file_path: DOCKERFILE_PATH,
            UtfLauncherCmdOption.docker_flags: f"-e MILESTONE={milestone_branch}",
            UtfLauncherCmdOption.docker_base_image: "utfsilabs/rpi_ubuntu_android:2025_07_17",
            UtfLauncherCmdOption.username: "pi",
            UtfLauncherCmdOption.password: "raspberry",
        }

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
        self.generate_keys_files_from_hwmux(hwmux_group_data)
        return hwmux_group_data


@click.command(cls=UtfLaunchCommander)
def main(**kwargs):
    launcher = AppUtfLauncher(**kwargs)
    launcher.execute()


if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
