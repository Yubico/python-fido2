
from fido2.nfc import CtapNfcDevice
from fido2.pcsc import Acr122uPcscDevice
import time

dev = next(CtapNfcDevice.list_devices(pcscDevice=Acr122uPcscDevice))

print('CONNECT: %s' % dev)
pcsc_device = dev.get_pcsc_device()
if pcsc_device is not None:
    pcsc_device.led_control(False, True, 0)
    print('version: %s' % pcsc_device.reader_version())
    pcsc_device.led_control(True, False, 0)
    time.sleep(1)
    pcsc_device.led_control(False, True, 3)
