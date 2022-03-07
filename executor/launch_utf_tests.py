import click
from typing import Optional, Tuple, Iterable
import json
import logging
import os
from utf.utils.executor.docker_manager import DockerManager, BuildError, DockerImage

DOCKERFILE_PATH = "executor/Dockerfile"
WORKSPACE_ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

class WiFiDockerManager(DockerManager):
    def _internal_build_image(self) -> Tuple[DockerImage, Iterable[dict]]:
        image, logs = self.docker_client.images.build(
            path=WORKSPACE_ROOT,
            tag=self.docker_image_tag,
            dockerfile=DOCKERFILE_PATH,
        )
        return image, logs


@click.command()
@click.option(
    "--target",
    default=None,
    help="Hostname or address of test executor",
)
@click.option(
    "--harness",
    required=True,
    help="Name of harness",
)
@click.option(
    "--debug",
    default=False,
    help="Enable debug server on target",
)
@click.option(
    "--test_script",
    default="run_tests.sh",
    help="Script to launch on test executor",
)
@click.option(
    "--docker_flags",
    default="-t",
    help="Additional options to 'docker run' command, comma-delimited",
)
@click.option(
    "--container_name",
    default="wifitest_1",
    help="Name of docker container",
)
@click.option(
    "--pytest_command",
    default=None,
    help="Custom pytest command",
)
@click.option(
    "--hwmux_group_id",
    default=None,
    help="HWMux group ID",
)
@click.option(
    "--hwmux_token",
    default=None,
    help="HWMux API token",
)
@click.option(
    "--hwmux_group_json",
    default=None,
    help="HWMux group model as json string",
)
@click.option(
    "--reports_dir",
    default=os.path.join(WORKSPACE_ROOT, "reports"),
    help="Directory in which to save test reports",
)
def main(
    target: str,
    harness: str,
    debug: bool,
    test_script: str,
    docker_flags: str,
    container_name: str,
    reports_dir: str,
    pytest_command: Optional[str],
    hwmux_group_id: Optional[str],
    hwmux_token: Optional[str],
    hwmux_group_json: Optional[str],
) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(message)s")
    package_manifest = os.path.join(WORKSPACE_ROOT, "manifest", "manifest.yaml")
    container_run_options = DockerManager.parse_docker_flags(docker_flags)

    if "environment" in container_run_options and "PYTEST_COMMAND" in container_run_options["environment"]:
        pytest_command = container_run_options["environment"]["PYTEST_COMMAND"]

    docker_manager = WiFiDockerManager(
        target,
        harness,
        package_manifest,
        test_script,
        docker_image_tag="wifitest:latest",
        container_name=container_name,
        container_run_options=container_run_options,
        pytest_command=pytest_command,
        debug=debug,
        hwmux_group_id=hwmux_group_id,
        hwmux_token=hwmux_token,
        hwmux_group_data=json.loads(hwmux_group_json)
        if hwmux_group_json is not None
        else None,
        reports_dir=reports_dir,
    )
    docker_manager.logger.setLevel(logging.INFO)
    docker_manager.run()
    return docker_manager.exit_code


if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
