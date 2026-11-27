"""Shared building blocks for the WLAN+BLE coexistence test suites.

Each example under `coex/<example>_test_scripts` keeps only what is specific to
it -- the serial strings it expects and the order of its steps -- and takes the
BLE provisioning, build/flash plumbing, button control, and MQTT verification
from here.
"""
