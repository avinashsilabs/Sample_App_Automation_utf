#!/usr/bin/env python3
"""BlueZ DisplayYesNo agent that auto-confirms the DUT's SMP request."""

from __future__ import print_function

import argparse
import os
import signal
import time

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

BLUEZ = "org.bluez"
AGENT_IFACE = "org.bluez.Agent1"
AGENT_MANAGER = "org.bluez.AgentManager1"


def log(message):
    print("[pi-ble] %s" % message, flush=True)


class Agent(dbus.service.Object):
    PATH = "/wcbs/agent"

    def __init__(self, bus, passkey_file):
        self.passkey_file = passkey_file
        dbus.service.Object.__init__(self, bus, self.PATH)

    def _read_passkey(self):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                with open(self.passkey_file, "r") as stream:
                    value = stream.read().strip()
                if value.isdigit() and len(value) == 6:
                    try:
                        os.unlink(self.passkey_file)
                    except OSError:
                        pass
                    return int(value)
            except OSError:
                pass
            time.sleep(0.1)
        raise RuntimeError("timed out waiting for DUT UART passkey")

    @dbus.service.method(AGENT_IFACE)
    def Release(self):
        log("Agent released")

    @dbus.service.method(AGENT_IFACE, in_signature="o", out_signature="s")
    def RequestPinCode(self, device):
        log("PAIRING: PIN requested for %s" % device)
        return "0000"

    @dbus.service.method(AGENT_IFACE, in_signature="o", out_signature="u")
    def RequestPasskey(self, device):
        log("PAIRING: passkey requested for %s" % device)
        value = self._read_passkey()
        log("PAIRING: entering DUT UART passkey %06d" % value)
        return dbus.UInt32(value)

    @dbus.service.method(AGENT_IFACE, in_signature="ouq")
    def DisplayPasskey(self, device, passkey, entered):
        log("PAIRING: display %06d for %s" % (passkey, device))

    @dbus.service.method(AGENT_IFACE, in_signature="ou")
    def RequestConfirmation(self, device, passkey):
        log("PAIRING_CONFIRMED: %06d for %s" % (passkey, device))

    @dbus.service.method(AGENT_IFACE, in_signature="o")
    def RequestAuthorization(self, device):
        log("PAIRING_AUTHORIZED: %s" % device)

    @dbus.service.method(AGENT_IFACE, in_signature="os")
    def AuthorizeService(self, device, uuid):
        log("SERVICE_AUTHORIZED: %s %s" % (device, uuid))

    @dbus.service.method(AGENT_IFACE)
    def Cancel(self):
        log("PAIRING_CANCELLED")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stop-file", default="")
    parser.add_argument("--passkey-file", required=True)
    args = parser.parse_args()
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    manager = dbus.Interface(bus.get_object(BLUEZ, "/org/bluez"), AGENT_MANAGER)
    agent = Agent(bus, args.passkey_file)
    try:
        manager.UnregisterAgent(agent.PATH)
    except Exception:
        pass
    manager.RegisterAgent(agent.PATH, "KeyboardOnly")
    manager.RequestDefaultAgent(agent.PATH)
    log("PAIRING_AGENT_READY: KeyboardOnly, awaiting UART passkey")
    loop = GLib.MainLoop()

    def check_stop():
        if args.stop_file and os.path.exists(args.stop_file):
            loop.quit()
            return False
        return True

    GLib.timeout_add(500, check_stop)
    signal.signal(signal.SIGTERM, lambda *_args: loop.quit())
    loop.run()
    try:
        manager.UnregisterAgent(agent.PATH)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
