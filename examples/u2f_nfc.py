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

try:
    reg = ctap1.register(chal, appid)
    print("register:", reg)
except:
    print("No U2F card in field.")
    sys.exit(2)


try:
    res = reg.verify(chal, appid)
    print("verify result: ", res)
except:
    print("Register message verify error.")


auth = ctap1.authenticate(chal, appid, reg.key_handle)
print("authenticate result: ", auth)

try:
    res = auth.verify(chal, appid, reg.public_key)
    print("verify result: ", res)
except:
    print("Authenticate message verify error.")
