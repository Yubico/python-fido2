
from fido2.nfc import CtapNfcDevice
from fido2.pcsc import PCSCDevice
import time


class Acr122uPcscDevice(PCSCDevice):
    def reader_version(self):
        """
        Get reader's version from reader
        :return: string. Reader's version
        """

        if self.connection is not None:
            try:
                result, sw1, sw2 = self.apdu_exchange(b'\xff\x00\x48\x00\x00')
                if len(result) > 0:
                    str_result = result + bytes([sw1]) + bytes([sw2])
                    str_result = str_result.decode('utf-8')
                    return str_result
            except Exception as e:
                print('Get version error:', e)
                pass
        return 'n/a'

    def led_control(self, red=False, green=False,
                    blink_count=0, red_end_blink=False, green_end_blink=False):
        """
        Reader's led control
        :param red: boolean. red led on
        :param green: boolean. green let on
        :param blink_count: int. if needs to blink value > 0. blinks count
        :param red_end_blink: boolean.
        state of red led at the end of blinking
        :param green_end_blink: boolean.
        state of green led at the end of blinking
        :return:
        """

        if self.connection is not None:
            try:
                if blink_count > 0:
                    cbyte = 0b00001100 + \
                            (0b01 if red_end_blink else 0b00) + \
                            (0b10 if green_end_blink else 0b00)
                    cbyte |= (0b01000000 if red else 0b00000000) + \
                             (0b10000000 if green else 0b00000000)
                else:
                    cbyte = 0b00001100 + \
                            (0b01 if red else 0b00) + \
                            (0b10 if green else 0b00)

                apdu = b'\xff\x00\x40' + \
                       bytes([cbyte & 0xff]) + \
                       b'\4' + b'\5\3' + \
                       bytes([blink_count]) + \
                       b'\0'
                self.apdu_exchange(apdu)

            except Exception as e:
                print('LED control error:', e)
                pass
        return


dev = next(CtapNfcDevice.list_devices(pcsc_device=Acr122uPcscDevice))

print('CONNECT: %s' % dev)
pcsc_device = dev.get_pcsc_device()
if pcsc_device is not None:
    pcsc_device.led_control(False, True, 0)
    print('version: %s' % pcsc_device.reader_version())
    pcsc_device.led_control(True, False, 0)
    time.sleep(1)
    pcsc_device.led_control(False, True, 3)
