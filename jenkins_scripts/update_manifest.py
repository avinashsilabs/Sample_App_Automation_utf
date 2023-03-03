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
                flash_rs9116 = sys.argv[2]
                chip_version = sys.argv[3]
                build_location = sys.argv[4]

                y=yaml.safe_load(f)

                if flash_rs9116 == 'true':
                    if build_location != "source_code":
                        if rs9116_package_name != "Internal.rps":
                            if chip_version == "1.4" or chip_version == "1.3":
                                rs9116_package_name = rs9116_package_name.replace("916", "9116")
                            y['firmware']['rs911x'] = rs9116_package_name
                else:
                    del y['firmware']['rs911x']

                y_new = yaml.dump(y, default_flow_style=False, sort_keys=False)
                f.seek(0)
                f.truncate(0)
                f.write(y_new)