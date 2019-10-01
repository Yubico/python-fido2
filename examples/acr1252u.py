from fido2.pcsc import CtapPcscDevice
import time


# control codes:
# 3225264 - magic number!!!
# 0x42000000 + 3500 - cross platform way
C_CODE = 3225264


class Acr1252uPcscDevice(object):
    def __init__(self, pcsc_device):
        self.pcsc = pcsc_device

    def reader_version(self):
        try:
            res = self.pcsc.control_exchange(C_CODE, b"\xe0\x00\x00\x18\x00")

            if len(res) > 0 and res.find(b"\xe1\x00\x00\x00") == 0:
                reslen = res[4]
                if reslen == len(res) - 5:
                    strres = res[5 : 5 + reslen].decode("utf-8")
                    return strres
        except Exception as e:
            print("Get version error:", e)
        return "n/a"

    def reader_serial_number(self):
        try:
            res = self.pcsc.control_exchange(C_CODE, b"\xe0\x00\x00\x33\x00")

            if len(res) > 0 and res.find(b"\xe1\x00\x00\x00") == 0:
                reslen = res[4]
                if reslen == len(res) - 5:
                    strres = res[5 : 5 + reslen].decode("utf-8")
                    return strres
        except Exception as e:
            print("Get serial number error:", e)
        return "n/a"

    def led_control(self, red=False, green=False):
        try:
            cbyte = (0b01 if red else 0b00) + (0b10 if green else 0b00)
            result = self.pcsc.control_exchange(
                C_CODE, b"\xe0\x00\x00\x29\x01" + bytes([cbyte])
            )

            if len(result) > 0 and result.find(b"\xe1\x00\x00\x00") == 0:
                result_length = result[4]
                if result_length == 1:
                    ex_red = bool(result[5] & 0b01)
                    ex_green = bool(result[5] & 0b10)
                    return True, ex_red, ex_green
        except Exception as e:
            print("LED control error:", e)

        return False, False, False

    def led_status(self):
        try:
            result = self.pcsc.control_exchange(C_CODE, b"\xe0\x00\x00\x29\x00")

            if len(result) > 0 and result.find(b"\xe1\x00\x00\x00") == 0:
                result_length = result[4]
                if result_length == 1:
                    ex_red = bool(result[5] & 0b01)
                    ex_green = bool(result[5] & 0b10)
                    return True, ex_red, ex_green
        except Exception as e:
            print("LED status error:", e)

        return False, False, False

    def get_polling_settings(self):
        try:
            res = self.pcsc.control_exchange(C_CODE, b"\xe0\x00\x00\x23\x00")

            if len(res) > 0 and res.find(b"\xe1\x00\x00\x00") == 0:
                reslen = res[4]
                if reslen == 1:
                    return True, res[5]
        except Exception as e:
            print("Get polling settings error:", e)

        return False, 0

    def set_polling_settings(self, settings):
        try:
            res = self.pcsc.control_exchange(
                C_CODE, b"\xe0\x00\x00\x23\x01" + bytes([settings & 0xFF])
            )

            if len(res) > 0 and res.find(b"\xe1\x00\x00\x00") == 0:
                reslen = res[4]
                if reslen == 1:
                    return True, res[5]
        except Exception as e:
            print("Set polling settings error:", e)

        return False, 0

    def get_picc_operation_parameter(self):
        try:
            res = self.pcsc.control_exchange(C_CODE, b"\xe0\x00\x00\x20\x00")

            if len(res) > 0 and res.find(b"\xe1\x00\x00\x00") == 0:
                reslen = res[4]
                if reslen == 1:
                    return True, res[5]
        except Exception as e:
            print("Get PICC Operating Parameter error:", e)

        return False, 0

    def set_picc_operation_parameter(self, param):
        try:
            res = self.pcsc.control_exchange(
                C_CODE, b"\xe0\x00\x00\x20\x01" + bytes([param])
            )

            if len(res) > 0 and res.find(b"\xe1\x00\x00\x00") == 0:
                reslen = res[4]
                if reslen == 1:
                    return True, res[5]
        except Exception as e:
            print("Set PICC Operating Parameter error:", e)

        return False, 0


dev = next(CtapPcscDevice.list_devices())

print("CONNECT: %s" % dev)
pcsc_device = Acr1252uPcscDevice(dev)
if pcsc_device is not None:
    print("version: %s" % pcsc_device.reader_version())
    print("serial number: %s" % pcsc_device.reader_serial_number())
    print("")

    result, settings = pcsc_device.set_polling_settings(0x8B)
    print("write polling settings: %r 0x%x" % (result, settings))

    result, settings = pcsc_device.get_polling_settings()
    print("polling settings: %r 0x%x" % (result, settings))
    set_desc = [
        [0, "Auto PICC Polling"],
        [1, "Turn off Antenna Field if no PICC is found"],
        [2, "Turn off Antenna Field if the PICC is inactive"],
        [3, "Activate the PICC when detected"],
        [7, "Enforce ISO 14443-A Part 4"],
    ]
    for x in set_desc:
        print(x[1], "on" if settings & (1 << x[0]) else "off")
    interval_desc = [250, 500, 1000, 2500]
    print("PICC Poll Interval for PICC", interval_desc[(settings >> 4) & 0b11], "ms")
    print("")

    print(
        "PICC operation parameter: %r 0x%x" % pcsc_device.get_picc_operation_parameter()
    )
    print("")

    result, red, green = pcsc_device.led_control(True, False)
    print("led control result:", result, "red:", red, "green:", green)

    result, red, green = pcsc_device.led_status()
    print("led state result:", result, "red:", red, "green:", green)

    time.sleep(1)
    pcsc_device.led_control(False, False)
