
from fido2.nfc import CtapNfcDevice
from fido2.pcsc import Acr1252uPcscDevice
import time

dev = next(CtapNfcDevice.list_devices(pcscDevice=Acr1252uPcscDevice))

print('CONNECT: %s' % dev)
pcsc_device = dev.get_pcsc_device()
if pcsc_device is not None:
    print('version: %s' % pcsc_device.reader_version())
    print('serial number: %s' % pcsc_device.reader_serial_number())
    print('')

    result, settings = pcsc_device.set_polling_settings(0x8B)
    print('write polling settings: %r 0x%x' % (result, settings))

    result, settings = pcsc_device.get_polling_settings()
    print('polling settings: %r 0x%x' % (result, settings))
    set_desc = [[0, 'Auto PICC Polling'],
                [1, 'Turn off Antenna Field if no PICC is found'],
                [2, 'Turn off Antenna Field if the PICC is inactive'],
                [3, 'Activate the PICC when detected'],
                [7, 'Enforce ISO 14443-A Part 4']]
    for x in set_desc:
        print(x[1], 'on' if settings & (1 << x[0]) else 'off')
    interval_desc = [250, 500, 1000, 2500]
    print('PICC Poll Interval for PICC',
          interval_desc[(settings >> 4) & 0b11],
          'ms')
    print('')

    print('PICC operation parameter: %r 0x%x' %
          pcsc_device.get_picc_operation_parameter())
    print('')

    result, red, green = pcsc_device.led_control(True, False)
    print('led control result:', result, 'red:', red, 'green:', green)

    result, red, green = pcsc_device.led_status()
    print('led state result:', result, 'red:', red, 'green:', green)

    time.sleep(1)
    pcsc_device.led_control(False, False)
