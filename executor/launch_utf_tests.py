import subprocess
from abc import ABC
import click
from typing import Tuple, Iterable
import os
from utf.executor.launch_utf_tests import UtfLauncher, UtfLaunchCommander, UtfLauncherCmdOption, UtfExecutorTypes
from utf.utils.executor.docker_manager import DockerManager, DockerImage
from utf.utils.executor.local_executor import LocalExecutor

DOCKERFILE_PATH = "executor/Dockerfile"
WORKSPACE_ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))


class DockerExecutor(DockerManager):
    def _internal_build_image(self) -> Tuple[DockerImage, Iterable[dict]]:
        image, logs = self.docker_client.images.build(
            path=WORKSPACE_ROOT,
            tag=self.docker_image_tag,
            dockerfile=DOCKERFILE_PATH,
        )
        return image, logs


def get_git_branch(path=None):
    if path is None:
        path = os.path.curdir
    command = 'git rev-parse --abbrev-ref HEAD'.split()
    branch = subprocess.Popen(command, stdout=subprocess.PIPE, cwd=path).stdout.read()
    return branch.strip().decode('utf-8')


class AppUtfLauncher(UtfLauncher, ABC):
    def __init__(self, **kwargs):
        UtfLauncher.__init__(self, **kwargs)

    def get_executor_types(self) -> dict:
        return {UtfExecutorTypes.local: LocalExecutor, UtfExecutorTypes.docker: DockerExecutor}

    def get_params_defaults(self) -> dict:
        return {
            UtfLauncherCmdOption.workspace_root: WORKSPACE_ROOT,
            UtfLauncherCmdOption.reports_dir:  os.path.join(WORKSPACE_ROOT, "reports"),
            UtfLauncherCmdOption.container_name: "railtest",
            UtfLauncherCmdOption.docker_image_tag: "railtest:latest",
            UtfLauncherCmdOption.docker_file_path: DOCKERFILE_PATH,
            UtfLauncherCmdOption.docker_flags: "-e MILESTONE=" + get_git_branch()
        }


@click.command(cls=UtfLaunchCommander)
def main(**kwargs):
    launcher = AppUtfLauncher(**kwargs)
    launcher.execute()


if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
