import yaml
import json
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class TestBed:
    name: str
    harness_file: str
    host_ip: str
    metadata: Optional[dict] = None


DEFAULT_TEST_BEDS = [
    TestBed("UTF_Integration_Test_NB0015129", "../../config/harnesses/integration_test_1", "10.4.1.107"),
    TestBed("UTF_Integration_Test_AustinLab", "../../config/harnesses/integration_test_2", "10.100.124.23"),
    TestBed("UTF_Integration_Test_dev_team_hyd_1", "../../config/harnesses/integration_test_3", "10.207.16.81"),
    # TestBed("UTF_Development_NB0015129", "integration_test-dev", "10.4.1.210"),
]


def convert_yaml_to_json(test_beds: List[TestBed]):
    for test_bed in test_beds:
        with open(f"{test_bed.harness_file}.yaml") as f:
            d = yaml.safe_load(f)
        with open(f"{test_bed.harness_file}.json", "w") as f:
            metadata = {
                "host_ip": test_bed.host_ip,
                "utf_group": "utf_dev",
                "harness": d,
            }
            test_bed.metadata = metadata
            j = json.dumps(metadata, indent=3)
            f.write(j)
    return test_beds


if __name__ == "__main__":
    convert_yaml_to_json(DEFAULT_TEST_BEDS)
