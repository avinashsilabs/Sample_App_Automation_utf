# UTF Configuration and Customization

The following directories inside this repo contain configuration files and scripts that you can modify to configure and customize UTF for your application

* `ci_scripts` Contains scripts related to integration with Jenkins
   * `Jenkinsfile` is a sample Jenkins CI pipeline that sets up the workspace and launches tests


* `config` Contains test bed definitions (harness `yaml` files) and a workspace configuration `yaml` file
   * The `config/harnesses` folder contains harness `yaml` files that are test bed definitions. See the relevant link under [Links](./Links.md) for more details on the harness `yaml` format.
   * The [`workspace.yaml`](../config/workspace.yaml) file contains metadata describing the workspace folder layout.  See the comments within that file for details on how to make modifications.


* `executor` contains files related to executing tests
  * The `Dockerfile` contains the definition of the Docker image that will be run on the execution target.  Likely the only things that would ever need to change in this file are the base image, and the set of UTF extensions that are copied into the image.
  * The `docker_startup.sh` script is run when the container is started.  Modify this file as necessary to start services, etc. within the docker container before the tests are executed.


* `manifest` contains firmware images and a `manifest.yaml` file
   * the `manifest.yaml` file contains the names of the firmware images to be flashed to devices within the test bed.  See the relevant link under [Links](./Links.md) for more details on the manifest file.


* `tests` contains the test source files and a library manifest `yaml` file
   * The `library_manifest.yaml` file contains a list of test cases and associated parameters for each.  It is used by the [UTF Sequence Manager](docs/RunningTests.md) to build the list of selectable test cases for execution.
     See the relevant link under [Links](./Links.md) for more details on the file format of the library manifest file.    

