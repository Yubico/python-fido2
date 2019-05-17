
from fido2.nfc import CtapNfcDevice
import time

dev = next(CtapNfcDevice.list_devices())

print('CONNECT: %s' % dev)
pcsc_device = dev.GetPCSC()
if pcsc_device is not None:
    pcsc_device.LED(False, True, 0)
    print('version: %s' % pcsc_device.ReaderVersion())
    pcsc_device.LED(True, False, 0)
    time.sleep(1)
    pcsc_device.LED(False, True, 3)
