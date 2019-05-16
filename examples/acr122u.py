
from fido2.nfc import CtapNFCDevice
import time

dev = next(CtapNFCDevice.list_devices())

print('CONNECT: %s' % dev)
pcscdev = dev.GetPCSC()
if pcscdev is not None:
    pcscdev.LED(False, True, 0)
    print('version: %s' % pcscdev.ReaderVersion())
    pcscdev.LED(True, False, 0)
    time.sleep(1)
    pcscdev.LED(False, True, 3)
