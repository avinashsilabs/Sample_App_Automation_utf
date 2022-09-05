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
    # TestBed("UTF_Integration_Test_NB0015129", "../../config/harnesses/integration_test_1", "10.4.1.107"),
    # TestBed("UTF_Integration_Test_AustinLab", "../../config/harnesses/integration_test_2", "10.100.124.23"),
    # TestBed("UTF_Integration_Test_dev_team_hyd_1", "../../config/harnesses/integration_test_3", "10.207.16.81"),
    TestBed("utf-dev-team-hyd-2", "../../config/harnesses/utf-dev-team-hyd", "10.207.16.82"),
    TestBed("utf-dev-team-hyd-3", "../../config/harnesses/utf-dev-team-hyd", "10.207.16.83"),
    TestBed("utf-dev-team-hyd-4", "../../config/harnesses/utf-dev-team-hyd", "10.207.16.84"),
    TestBed("utf-dev-team-hyd-5", "../../config/harnesses/utf-dev-team-hyd", "10.207.16.85"),
    TestBed("utf-dev-team-hyd-6", "../../config/harnesses/utf-dev-team-hyd", "10.207.16.86"),
    TestBed("utf-dev-team-hyd-7", "../../config/harnesses/utf-dev-team-hyd", "10.207.16.87"),
    TestBed("utf-dev-team-hyd-8", "../../config/harnesses/utf-dev-team-hyd", "10.207.16.88"),
    TestBed("utf-dev-team-hyd-9", "../../config/harnesses/utf-dev-team-hyd", "10.207.16.89"),
    TestBed("utf-dev-team-hyd-10", "../../config/harnesses/utf-dev-team-hyd", "10.207.16.90"),
    TestBed("utf-dev-team-hyd-11", "../../config/harnesses/utf-dev-team-hyd", "10.207.16.91"),
    TestBed("utf-dev-team-hyd-12", "../../config/harnesses/utf-dev-team-hyd", "10.207.16.92"),
    TestBed("utf-dev-team-hyd-13", "../../config/harnesses/utf-dev-team-hyd", "10.207.16.93"),
    TestBed("utf-dev-team-hyd-14", "../../config/harnesses/utf-dev-team-hyd", "10.207.16.94"),
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
