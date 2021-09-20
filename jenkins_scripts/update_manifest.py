#!/usr/bin/python

import yaml
import sys

with open("./example_test_package/manifest.yaml", "r+") as f:
    y=yaml.safe_load(f)
    y['firmware']['rs911x'] = sys.argv[1]
    y['firmware']['efx32'] = sys.argv[2]
    y_new = yaml.dump(y, default_flow_style=False, sort_keys=False)
    f.seek(0)
    f.truncate(0)
    f.write(y_new)