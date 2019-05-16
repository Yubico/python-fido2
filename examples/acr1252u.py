
from fido2.nfc import CtapNFCDevice
from fido2.pcsc import ACR1252UPCSCDevice
import time

dev = next(CtapNFCDevice.list_devices(pcscDevice=ACR1252UPCSCDevice))

print('CONNECT: %s' % dev)
pcscdev = dev.GetPCSC()
if pcscdev is not None:
    print('version: %s' % pcscdev.ReaderVersion())
    print('serial number: %s' % pcscdev.ReaderSerialNumber())

    result, red, green = pcscdev.LEDControl(True, False)
    print("led control result:", result, "red:", red, "green:", green)

    result, red, green = pcscdev.LEDStatus()
    print("led state result:", result, "red:", red, "green:", green)
