# Copyright (c) 2018 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
Example demo server to use a supported web browser to call the WebAuthn APIs
to register and use a credential.

See the file README.adoc in this directory for details.

Navigate to https://localhost:5000 in a supported web browser.
"""
from __future__ import print_function, absolute_import, unicode_literals

from fido2.client import ClientData
from fido2.server import Fido2Server, RelyingParty
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2 import cbor
from flask import Flask, session, request, redirect, abort

import os


app = Flask(__name__, static_url_path='')
app.secret_key = os.urandom(32)  # Used for session.

rp = RelyingParty('localhost', 'Demo server')
server = Fido2Server(rp)


# Registered credentials are stored globally, in memory only. Single user
# support, state is lost when the server terminates.
credentials = []


@app.route('/')
def index():
    return redirect('/index.html')


@app.route('/api/register/begin', methods=['POST'])
def register_begin():
    registration_data, state = server.register_begin({
        'id': b'user_id',
        'name': 'a_user',
        'displayName': 'A. User',
        'icon': 'https://example.com/image.png'
    }, credentials, user_verification='discouraged')

    session['state'] = state
    print('\n\n\n\n')
    print(registration_data)
    print('\n\n\n\n')
    return cbor.encode(registration_data)


@app.route('/api/register/complete', methods=['POST'])
def register_complete():
    data = cbor.decode(request.get_data())
    client_data = ClientData(data['clientDataJSON'])
    att_obj = AttestationObject(data['attestationObject'])
    print('clientData', client_data)
    print('AttestationObject:', att_obj)

    auth_data = server.register_complete(
        session['state'],
        client_data,
        att_obj
    )

    credentials.append(auth_data.credential_data)
    print('REGISTERED CREDENTIAL:', auth_data.credential_data)
    return cbor.encode({'status': 'OK'})


@app.route('/api/authenticate/begin', methods=['POST'])
def authenticate_begin():
    if not credentials:
        abort(404)

    auth_data, state = server.authenticate_begin(credentials)
    session['state'] = state
    return cbor.encode(auth_data)


@app.route('/api/authenticate/complete', methods=['POST'])
def authenticate_complete():
    if not credentials:
        abort(404)

    data = cbor.decode(request.get_data())
    credential_id = data['credentialId']
    client_data = ClientData(data['clientDataJSON'])
    auth_data = AuthenticatorData(data['authenticatorData'])
    signature = data['signature']
    print('clientData', client_data)
    print('AuthenticatorData', auth_data)

    server.authenticate_complete(
        session.pop('state'),
        credentials,
        credential_id,
        client_data,
        auth_data,
        signature
    )
    print('ASSERTION OK')
    return cbor.encode({'status': 'OK'})


if __name__ == '__main__':
    print(__doc__)
    app.run(ssl_context='adhoc', debug=True)
