#!/usr/bin/env python3
"""BlueZ HRS peripheral used by the DUT-central side of the AE coex test.

Requires the Raspberry Pi OS system packages python3-dbus and python3-gi.
It advertises SILABS_DEV and emits Heart Rate Measurement notifications so
the DUT can prove profile discovery, CCC enable, and received BLE data.
"""

from __future__ import print_function

import argparse
import os
import signal
import sys
import time

try:
    import dbus
    import dbus.exceptions
    import dbus.mainloop.glib
    import dbus.service
    from gi.repository import GLib
except ImportError as exc:
    print("[pi-ble] FAILED: install python3-dbus and python3-gi: %s" % exc, flush=True)
    raise SystemExit(2)


BLUEZ = "org.bluez"
OM_IFACE = "org.freedesktop.DBus.ObjectManager"
PROP_IFACE = "org.freedesktop.DBus.Properties"
GATT_MANAGER = "org.bluez.GattManager1"
ADV_MANAGER = "org.bluez.LEAdvertisingManager1"
GATT_SERVICE = "org.bluez.GattService1"
GATT_CHAR = "org.bluez.GattCharacteristic1"
ADV_IFACE = "org.bluez.LEAdvertisement1"
AGENT_IFACE = "org.bluez.Agent1"
AGENT_MANAGER = "org.bluez.AgentManager1"


def log(message):
    print("[pi-ble] %s" % message, flush=True)


class InvalidArgs(dbus.exceptions.DBusException):
    _dbus_error_name = "org.freedesktop.DBus.Error.InvalidArgs"


class NotSupported(dbus.exceptions.DBusException):
    _dbus_error_name = "org.bluez.Error.NotSupported"


class PairingAgent(dbus.service.Object):
    """Auto-confirm Numeric Comparison while preserving authenticated SMP."""

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
        log("Pairing agent released")

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


class Application(dbus.service.Object):
    def __init__(self, bus):
        self.path = "/wcbs"
        self.services = []
        dbus.service.Object.__init__(self, bus, self.path)

    def add_service(self, service):
        self.services.append(service)

    @dbus.service.method(OM_IFACE, out_signature="a{oa{sa{sv}}}")
    def GetManagedObjects(self):
        reply = {}
        for service in self.services:
            reply[service.get_path()] = service.get_properties()
            for char in service.characteristics:
                reply[char.get_path()] = char.get_properties()
        return reply


class Service(dbus.service.Object):
    def __init__(self, bus, index, uuid):
        self.path = "/wcbs/service%d" % index
        self.uuid = uuid
        self.characteristics = []
        dbus.service.Object.__init__(self, bus, self.path)

    def add_characteristic(self, characteristic):
        self.characteristics.append(characteristic)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def get_properties(self):
        return {GATT_SERVICE: {
            "UUID": self.uuid,
            "Primary": dbus.Boolean(True),
            "Characteristics": dbus.Array(
                [char.get_path() for char in self.characteristics], signature="o"
            ),
        }}

    @dbus.service.method(PROP_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != GATT_SERVICE:
            raise InvalidArgs()
        return self.get_properties()[GATT_SERVICE]


class Characteristic(dbus.service.Object):
    def __init__(self, bus, index, uuid, flags, service):
        self.path = service.path + "/char%d" % index
        self.uuid = uuid
        self.flags = flags
        self.service = service
        dbus.service.Object.__init__(self, bus, self.path)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def get_properties(self):
        return {GATT_CHAR: {
            "Service": self.service.get_path(),
            "UUID": self.uuid,
            "Flags": dbus.Array(self.flags, signature="s"),
            "Descriptors": dbus.Array([], signature="o"),
        }}

    @dbus.service.method(PROP_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != GATT_CHAR:
            raise InvalidArgs()
        return self.get_properties()[GATT_CHAR]

    @dbus.service.signal(PROP_IFACE, signature="sa{sv}as")
    def PropertiesChanged(self, interface, changed, invalidated):
        pass


class HeartRateMeasurement(Characteristic):
    def __init__(self, bus, service, interval_ms):
        Characteristic.__init__(
            self, bus, 0, "00002a37-0000-1000-8000-00805f9b34fb",
            ["notify"], service
        )
        self.notifying = False
        self.counter = 0
        self.interval_ms = interval_ms

    @dbus.service.method(GATT_CHAR, in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        return dbus.Array([dbus.Byte(0), dbus.Byte(60 + self.counter % 40)], signature="y")

    @dbus.service.method(GATT_CHAR)
    def StartNotify(self):
        if self.notifying:
            return
        self.notifying = True
        log("NOTIFY_SUBSCRIBED: DUT enabled Heart Rate notifications")
        GLib.timeout_add(self.interval_ms, self._emit)

    @dbus.service.method(GATT_CHAR)
    def StopNotify(self):
        self.notifying = False
        log("NOTIFY_UNSUBSCRIBED")

    def _emit(self):
        if not self.notifying:
            return False
        self.counter += 1
        value = dbus.Array(
            [dbus.Byte(0), dbus.Byte(60 + self.counter % 40)], signature="y"
        )
        self.PropertiesChanged(GATT_CHAR, {"Value": value}, [])
        if self.counter == 1 or self.counter % 40 == 0:
            log("HRS notifications sent=%d" % self.counter)
        return True


class HeartRateControlPoint(Characteristic):
    def __init__(self, bus, service):
        Characteristic.__init__(
            self, bus, 1, "00002a39-0000-1000-8000-00805f9b34fb",
            ["write"], service
        )

    @dbus.service.method(GATT_CHAR, in_signature="aya{sv}")
    def WriteValue(self, value, options):
        log("Heart Rate control point write: %s" % list(value))


class Advertisement(dbus.service.Object):
    PATH_BASE = "/wcbs/advertisement"

    def __init__(self, bus, name):
        self.path = self.PATH_BASE + "0"
        self.name = name
        dbus.service.Object.__init__(self, bus, self.path)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def properties(self):
        return {
            "Type": "peripheral",
            "ServiceUUIDs": dbus.Array(
                ["0000180d-0000-1000-8000-00805f9b34fb"], signature="s"
            ),
            "LocalName": dbus.String(self.name),
            "Discoverable": dbus.Boolean(True),
        }

    @dbus.service.method(PROP_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != ADV_IFACE:
            raise InvalidArgs()
        return self.properties()

    @dbus.service.method(ADV_IFACE)
    def Release(self):
        log("Advertisement released")


def adapter_path(bus, adapter):
    objects = dbus.Interface(bus.get_object(BLUEZ, "/"), OM_IFACE).GetManagedObjects()
    wanted = "/org/bluez/%s" % adapter
    if wanted not in objects:
        raise RuntimeError("Bluetooth adapter %s not found" % adapter)
    if GATT_MANAGER not in objects[wanted] or ADV_MANAGER not in objects[wanted]:
        raise RuntimeError("%s lacks BlueZ GATT/advertising support" % adapter)
    return wanted


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="SILABS_DEV")
    parser.add_argument("--adapter", default="hci0")
    parser.add_argument("--hold", type=float, default=240)
    parser.add_argument("--stop-file", default="")
    parser.add_argument("--passkey-file", required=True)
    parser.add_argument("--notify-ms", type=int, default=250)
    args = parser.parse_args()

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    path = adapter_path(bus, args.adapter)
    manager = dbus.Interface(bus.get_object(BLUEZ, path), GATT_MANAGER)
    adv_manager = dbus.Interface(bus.get_object(BLUEZ, path), ADV_MANAGER)
    agent_manager = dbus.Interface(bus.get_object(BLUEZ, "/org/bluez"), AGENT_MANAGER)

    app = Application(bus)
    service = Service(bus, 0, "0000180d-0000-1000-8000-00805f9b34fb")
    measurement = HeartRateMeasurement(bus, service, max(100, args.notify_ms))
    service.add_characteristic(measurement)
    service.add_characteristic(HeartRateControlPoint(bus, service))
    app.add_service(service)
    advertisement = Advertisement(bus, args.name)
    loop = GLib.MainLoop()
    agent = PairingAgent(bus, args.passkey_file)
    try:
        agent_manager.UnregisterAgent(agent.PATH)
    except Exception:
        pass
    agent_manager.RegisterAgent(agent.PATH, "KeyboardOnly")
    agent_manager.RequestDefaultAgent(agent.PATH)
    log("PAIRING_AGENT_READY: KeyboardOnly, awaiting UART passkey")

    manager.RegisterApplication(app.path, {},
        reply_handler=lambda: log("GATT_READY: Heart Rate service registered"),
        error_handler=lambda error: (log("FAILED: GATT registration: %s" % error), loop.quit()))
    adv_manager.RegisterAdvertisement(advertisement.get_path(), {},
        reply_handler=lambda: log("ADVERTISING: %s on %s" % (args.name, args.adapter)),
        error_handler=lambda error: (log("FAILED: advertising: %s" % error), loop.quit()))

    started = time.monotonic()

    def check_done():
        if args.stop_file and os.path.exists(args.stop_file):
            log("Stop requested by test runner")
            loop.quit()
            return False
        if time.monotonic() - started >= args.hold:
            if measurement.counter < 1:
                log("FAILED: DUT never subscribed to Heart Rate notifications")
                globals()["exit_code"] = 1
            else:
                log("PASS: peripheral data path sent %d notifications" % measurement.counter)
            loop.quit()
            return False
        return True

    GLib.timeout_add(500, check_done)
    signal.signal(signal.SIGTERM, lambda *_args: loop.quit())
    globals()["exit_code"] = 0
    loop.run()
    try:
        adv_manager.UnregisterAdvertisement(advertisement.get_path())
    except Exception:
        pass
    try:
        manager.UnregisterApplication(app.path)
    except Exception:
        pass
    try:
        agent_manager.UnregisterAgent(agent.PATH)
    except Exception:
        pass
    return globals()["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
