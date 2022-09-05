# UTF Extension Repos

UTF extensions allow you to extend the functionality of UTF to support new devices & communication protocols without the need to modify `utf_core` itself.
It is most appropriate to add features to a UTF extension rather than the UTF core repo when the feature involves highly version-dependent functionality that may have a release lifecycle that is out-of-sync with the UTF core component lifecycle. 
Stability and reliability are important values in the UTF platform.  Thus, if a feature is likely to need frequent updates, or clients are likely to need differing versions of the feature, it is best to add the feature to an extension so that it can vary independently of the UTF core version.

UTF extensions should follow a uniform structure to maintain consistency and usability, and should follow the template laid out in the utf_extension_template repo.
Unit tests are highly encouraged to ensure that bugs can be caught early in the development cycle.
The UTF extension template comes with a jenkins CI script to automatically run unit tests, perform code coverage analysis and static analysis, and upload results to Sonarqube in order to reduce the effort required to gain visibility into the quality of the extension.

## Creating New Extensions
In order to create a new UTF extension, follow the instructions in the README file of the [utf_extension_template](https://stash.silabs.com/projects/IOT_INFRA_SW/repos/utf_extension_template/browse) repo.

## Adding Extensions to a UTF application repo
In order to add a UTF extension to your UTF application repo, follow these steps:
1. Add the extension as a submodule of your repo:
   
   ```git submodule add ../<name of extension repo> <destination_folder>```
   
   For example, to add the [utf_wiseconnect](https://stash.silabs.com/projects/IOT_INFRA_SW/repos/utf_wiseconnect/browse) extension to an application repo:

   ```git submodule add ../utf_wiseconnect utf_wiseconnect```


2. Modify the `Dockerfile` within the `executor` directory to copy the extension files when building the container and add the package to the PYTHONPATH.


3. Add the name of the directory containing the extension to the `extension_dirs` section of the [`workspace.yaml`](../config/workspace.yaml) configuration file. 

