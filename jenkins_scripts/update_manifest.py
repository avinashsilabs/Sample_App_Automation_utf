#!/usr/bin/python

import yaml
import sys

with open("./manifest/manifest.yaml", "r+") as f:
    rs9116_package_name = sys.argv[1]
    efr32_package_name = sys.argv[2]
    flash_rs9116 = sys.argv[3]
    flash_efr32 = sys.argv[4]
    chip_version = sys.argv[5]
    build_location = sys.argv[6]

    y=yaml.safe_load(f)

    if flash_rs9116 == 'true':
        if rs9116_package_name != "Internal.rps" or build_location != "source_code":
            if chip_version == "1.4" or chip_version == "1.3":
                rs9116_package_name = rs9116_package_name.replace("916", "9116")
            y['firmware']['rs911x'] = rs9116_package_name
    else:
        del y['firmware']['rs911x']

    if flash_efr32 == 'true':
        if efr32_package_name != "Internal.hex":
            y['firmware']['efx32'] = efr32_package_name
    else:
        del y['firmware']['efx32']

    y_new = yaml.dump(y, default_flow_style=False, sort_keys=False)
    f.seek(0)
    f.truncate(0)
    f.write(y_new)