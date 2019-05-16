
from fido2.nfc import CtapNFCDevice
from fido2.pcsc import ACR1252UPCSCDevice
import time

dev = next(CtapNFCDevice.list_devices(pcscDevice=ACR1252UPCSCDevice))

print('CONNECT: %s' % dev)
pcscdev = dev.GetPCSC()
if pcscdev is not None:
    print('version: %s' % pcscdev.ReaderVersion())
    print('serial number: %s' % pcscdev.ReaderSerialNumber())
    print("")

    result, settings = pcscdev.WritePollingSettings(0x8B)
    print("write polling settings: %r 0x%x" % (result, settings))

    result, settings = pcscdev.ReadPollingSettings()
    print('polling settings: %r 0x%x' % (result, settings))
    setdesc = [[0, "Auto PICC Polling"],
               [1, "Turn off Antenna Field if no PICC is found"],
               [2, "Turn off Antenna Field if the PICC is inactive"],
               [3, "Activate the PICC when detected"],
               [7, "Enforce ISO 14443-A Part 4"]]
    for x in setdesc:
        print(x[1], "on" if settings & (1 << x[0]) else "off")
    intervaldesc = [250, 500, 1000, 2500]
    print("PICC Poll Interval for PICC", intervaldesc[(settings >> 4) & 0b11], "ms")
    print("")

    print('PICC operation parameter: %r 0x%x' % pcscdev.ReadPICCOperationParameter())
    print("")

    result, red, green = pcscdev.LEDControl(True, False)
    print("led control result:", result, "red:", red, "green:", green)

    result, red, green = pcscdev.LEDStatus()
    print("led state result:", result, "red:", red, "green:", green)

    time.sleep(1)
    pcscdev.LEDControl(False, False)
