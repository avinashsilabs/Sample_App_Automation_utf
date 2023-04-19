#!/usr/bin/python
import os

import yaml
import sys

directory = "./manifest"
for filename in os.listdir(directory):
    if filename.startswith("manifest") and filename.endswith("yaml"):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path):
            with open(file_path, "r+") as f:
                rs9116_package_name = sys.argv[1]
                chip_version = sys.argv[2]
                build_location = sys.argv[3]

                y=yaml.safe_load(f)

                if build_location != "source_code":
                    if rs9116_package_name != "Internal.rps":
                        # Since the Package name is ved from RS9116W.X.X.X.X to RS9116_WiSeConnect_SDK.X.X.X.X
                        # And the rps file name is not updated so we are updating package name here.
                        rs9116_package_name = rs9116_package_name.replace("_WiSeConnect_SDK", "W")
                        if chip_version == "1.4" or chip_version == "1.3":
                            rs9116_package_name = rs9116_package_name.replace("916", "9116")
                        if chip_version == "1.5":
                            rs9116_package_name = rs9116_package_name.replace("9116", "916")
                        y['firmware']['rs911x'] = rs9116_package_name

                y_new = yaml.dump(y, default_flow_style=False, sort_keys=False)
                f.seek(0)
                f.truncate(0)
                f.write(y_new)