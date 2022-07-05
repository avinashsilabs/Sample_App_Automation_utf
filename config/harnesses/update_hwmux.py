import os

from hwmux_client.hwmux_api import HwMuxApi
from hwmux_client.model.patched_device_group_serializer_with_device_pk import (
    PatchedDeviceGroupSerializerWithDevicePk,
)
from hwmux_client.model.nested_device_group import NestedDeviceGroup
from hwmux_client.model.write_only_device import (
    WriteOnlyDevice,
)
from hwmux_client.model.location_serializer_write_only import (
    LocationSerializerWriteOnly,
)

from convert_to_json import DEFAULT_TEST_BEDS, convert_yaml_to_json


def main():
    mux_api = HwMuxApi(user_token=os.environ["HWMUX_TOKEN"])
    test_beds = convert_yaml_to_json(DEFAULT_TEST_BEDS)
    for test_bed in test_beds:
        groups_list = mux_api.groups_api.groups_list(name=test_bed.name)
        if groups_list.count == 0:
            group = NestedDeviceGroup(
                test_bed.name,
                devices=[
                    WriteOnlyDevice(
                        location=LocationSerializerWriteOnly(room="unknown"),
                        part="unknown",
                        sn_or_name=test_bed.name,
                        is_wstk=False,
                        uri=test_bed.host_ip,
                    )
                ],
                metadata=test_bed.metadata,
                permission_groups=["utf-dev_team"],
            )
            _ = mux_api.groups_api.groups_create_with_devices_create(group)
        if groups_list.count == 1:
            mux_test_bed = groups_list.results[0]
            group_serializer = PatchedDeviceGroupSerializerWithDevicePk(
                metadata=test_bed.metadata
            )
            mux_api.groups_api.groups_partial_update(
                mux_test_bed.id,
                patched_device_group_serializer_with_device_pk=group_serializer,
            )


if __name__ == "__main__":
    main()
