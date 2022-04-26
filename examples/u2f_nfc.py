from fido2.pcsc import CtapPcscDevice
from fido2.utils import sha256
from fido2.ctap1 import Ctap1
import sys


dev = next(CtapPcscDevice.list_devices(), None)
if not dev:
    print("No NFC u2f device found")
    sys.exit(1)

chal = sha256(b"AAA")
appid = sha256(b"BBB")

ctap1 = Ctap1(dev)

print("version:", ctap1.get_version())

# True - make extended APDU and send it to key
# ISO 7816-3:2006. page 33, 12.1.3 Decoding conventions for command APDUs
# ISO 7816-3:2006. page 34, 12.2 Command-response pair transmission by T=0
# False - make group of short (less than 255 bytes length) APDU
# and send them to key. ISO 7816-3:2005, page 9, 5.1.1.1 Command chaining
dev.use_ext_apdu = False

reg = ctap1.register(chal, appid)
print("register:", reg)


reg.verify(appid, chal)
print("Register message verify OK")


auth = ctap1.authenticate(chal, appid, reg.key_handle)
print("authenticate result: ", auth)

res = auth.verify(appid, chal, reg.public_key)
print("Authenticate message verify OK")
