import subprocess
from abc import ABC
import click
from typing import Tuple, Iterable
import os
from utf.executor.launch_utf_tests import UtfLaunchTests, UtfLaunchCommander, UtfLaunchCommandOptionKeys
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


class LauncherTests(UtfLaunchTests, ABC):
    def __init__(self, **kwargs):
        UtfLaunchTests.__init__(self, **kwargs)

    def get_executor_types(self) -> dict:
        return {"local": LocalExecutor, "docker": DockerExecutor}

    def get_custom_params(self) -> dict:
        return {
            UtfLaunchCommandOptionKeys.docker_flags: " -e MILESTONE=" + get_git_branch()
        }


class UtfAppLaunchCommander(UtfLaunchCommander, ABC):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_docker_file_path(self) -> str:
        return DOCKERFILE_PATH

    def get_docker_image_tag(self) -> str:
        return "railtest:latest"

    def get_container_name(self) -> str:
        return "railtest_1"

    def get_reports_dir(self) -> str:
        return os.path.join(WORKSPACE_ROOT, "reports")

    def get_workspace_root(self) -> str:
        return WORKSPACE_ROOT


@click.command(cls=UtfAppLaunchCommander)
def main(**kwargs):
    launcher = LauncherTests(**kwargs)
    launcher.execute()


if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
