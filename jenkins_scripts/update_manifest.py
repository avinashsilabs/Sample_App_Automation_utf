#!/usr/bin/python

import yaml
import sys

with open("./example_test_package/manifest.yaml", "r+") as f:
    rs9116_package_name = sys.argv[1]
    efr32_package_name = sys.argv[2]
    flash_rs9116 = sys.argv[3]
    flash_efr32 = sys.argv[4]

    y=yaml.safe_load(f)

    if flash_rs9116 == 'true':
        if rs9116_package_name != "Internal":
            y['firmware']['rs911x'] = rs9116_package_name
    else:
        del y['firmware']['rs911x']

    if flash_efr32 == 'true':
        if efr32_package_name != "Internal":
            y['firmware']['efx32'] = efr32_package_name
    else:
        del y['firmware']['efx32']

    y_new = yaml.dump(y, default_flow_style=False, sort_keys=False)
    f.seek(0)
    f.truncate(0)
    f.write(y_new)