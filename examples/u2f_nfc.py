from fido2.nfc import CtapNFCDevice
from fido2.utils import sha256
from fido2.ctap1 import CTAP1
import sys


dev = next(CtapNFCDevice.list_devices(), None)
if not dev:
    print('No NFC u2f device found')
    sys.exit(1)

chal = sha256(b"AAA")
appid = sha256(b"BBB")

ctap1 = CTAP1(dev)

print("version:", ctap1.get_version())

reg = ctap1.register(chal, appid)
print("register:", reg)

res = reg.verify(chal, appid)
print("verify result: ", res)

