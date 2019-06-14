from fido2.pcsc import CtapPcscDevice
from fido2.utils import sha256
from fido2.ctap1 import CTAP1
import sys


dev = next(CtapPcscDevice.list_devices(), None)
if not dev:
    print('No NFC u2f device found')
    sys.exit(1)

chal = sha256(b'AAA')
appid = sha256(b'BBB')

ctap1 = CTAP1(dev)

print('version:', ctap1.get_version())

reg = ctap1.register(chal, appid)
print('register:', reg)


reg.verify(appid, chal)
print('Register message verify OK')


auth = ctap1.authenticate(chal, appid, reg.key_handle)
print('authenticate result: ', auth)

res = auth.verify(appid, chal, reg.public_key)
print('Authenticate message verify OK')
