import subprocess
import click
import os
from utf.executor.launch_utf_tests import UtfLauncher, UtfLaunchCommander, UtfLauncherCmdOption, UtfExecutorTypes

DOCKERFILE_PATH = "executor/Dockerfile"
WORKSPACE_ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))


def get_git_branch(path=None):
    if path is None:
        path = os.path.curdir
    command = 'git rev-parse --abbrev-ref HEAD'.split()
    branch = subprocess.Popen(command, stdout=subprocess.PIPE, cwd=path).stdout.read()
    return branch.strip().decode('utf-8')


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
            UtfLauncherCmdOption.docker_flags: "-e MILESTONE=" + get_git_branch(),
            UtfLauncherCmdOption.docker_base_image: "utfsilabs/rpi_ubuntu",
        }


@click.command(cls=UtfLaunchCommander)
def main(**kwargs):
    launcher = AppUtfLauncher(**kwargs)
    launcher.execute()


if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
