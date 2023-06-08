import subprocess
import re
import click
import os
from utf.executor.launch_utf_tests import UtfLauncher, UtfLaunchCommander, UtfLauncherCmdOption, UtfExecutorTypes

DOCKERFILE_PATH = "executor/Dockerfile"
WORKSPACE_ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))



def get_milestone_branch_from_git_branch():
    rc = subprocess.Popen('git log', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout, stderr = rc.communicate()
    get_all_milestone = []
    get_all_milestone = (re.findall("release/milestone([0-9]+)", stdout.decode()))
    milestone = [int(i) for i in get_all_milestone]
    milestone.sort()
    current_milestone = "release/milestone" + str(milestone[-1])
    return current_milestone

class AppUtfLauncher(UtfLauncher):
    def __init__(self, **kwargs):
        UtfLauncher.__init__(self, **kwargs)

    def get_params_defaults(self) -> dict:
        return {
            UtfLauncherCmdOption.workspace_root: WORKSPACE_ROOT,
            UtfLauncherCmdOption.reports_dir:  os.path.join(WORKSPACE_ROOT, "reports"),
            UtfLauncherCmdOption.container_name: "wifitest_1",
            UtfLauncherCmdOption.docker_image_tag: "wifitest:latest",
            UtfLauncherCmdOption.docker_file_path: DOCKERFILE_PATH,
            UtfLauncherCmdOption.docker_flags: "-e MILESTONE=" + get_milestone_branch_from_git_branch(),
            UtfLauncherCmdOption.docker_base_image: "utfsilabs/rpi_ubuntu:2023_05_17_android_sdk",
            UtfLauncherCmdOption.username: "pi",
            UtfLauncherCmdOption.password: "raspberry",
        }


@click.command(cls=UtfLaunchCommander)
def main(**kwargs):
    launcher = AppUtfLauncher(**kwargs)
    launcher.execute()


if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
