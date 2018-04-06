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

To run (using a virtualenv is recommended):
  $ pip install -r requirements.txt
  $ python server.py

Now navigate to https://localhost:5000 in a supported web browser.
"""
from __future__ import print_function, absolute_import, unicode_literals

from fido2.client import ClientData
from fido2.ctap2 import AttestationObject, AuthenticatorData
from flask import Flask, request
import os


HTML = """
<html>
<head><title>Fido 2.0 webauthn demo</title></head>
<body>
  <h1>Webauthn demo</h1>
  <p>
    <strong>This demo requires a browser supporting the WebAuthn API!</strong>
  </p>
  <hr>
  {content}
</body>
</html>
"""

INDEX_HTML = HTML.format(content="""
<a href="/register">Register</a><br>
<a href="/authenticate">Authenticate</a><br>
""")

REGISTER_HTML = HTML.format(content="""
<h2>Register a credential</h2>
<p>Touch your authenticator device now...</p>
<script>
  navigator.credentials.create({{
    publicKey: {{
      rp: {{
        id: document.domain,
        name: 'Demo server'
      }},
      user: {{
        id: {user_id},
        name: 'a_user',
        displayName: 'A. User',
        icon: 'https://example.com/image.png'
      }},
      challenge: {challenge},
      pubKeyCredParams: [
        {{
          alg: -7,
          type: 'public-key'
        }}
      ],
      excludeCredentials: [],
      attestation: 'direct',
      timeout: 60000
    }}
  }}).then(function(attestation) {{
    console.log(attestation);
    console.log(JSON.stringify({{
        attestationObject: Array.from(new Uint8Array(attestation.response.attestationObject)),
        clientData: Array.from(new Uint8Array(attestation.response.clientDataJSON))
      }}));
    fetch('/register', {{
      method: 'POST',
      body: JSON.stringify({{
        attestationObject: Array.from(new Uint8Array(attestation.response.attestationObject)),
        clientData: Array.from(new Uint8Array(attestation.response.clientDataJSON))
      }})
    }}).then(function() {{
        alert('Registration successful. More details in server log...');
        window.location = '/';
    }});
  }}, function(reason) {{
    console.log('Failed', reason);
  }});
</script>
""")  # noqa


AUTH_HTML = HTML.format(content="""
<h2>Authenticate using a credential</h2>
<p>Touch your authenticator device now...</p>
<script>
  navigator.credentials.get({{
    publicKey: {{
      rpId: document.domain,
      challenge: {challenge},
      allowCredentials: [
        {{
          type: 'public-key',
          id: {credential_id}
        }}
      ],
      timeout: 60000
    }}
  }}).then(function(attestation) {{
    console.log(attestation);
    fetch('/authenticate', {{
      method: 'POST',
      body: JSON.stringify({{
        authenticatorData: Array.from(new Uint8Array(attestation.response.authenticatorData)),
        clientData: Array.from(new Uint8Array(attestation.response.clientDataJSON)),
        signature: Array.from(new Uint8Array(attestation.response.signature))
      }})
    }}).then(function() {{
        alert('Authentication successful. More details in server log...');
        window.location = '/';
    }});
  }}, function(reason) {{
    console.log('Failed', reason);
  }});
</script>
""")  # noqa


def to_js_array(value):
    return 'new Uint8Array(%r)' % list(bytearray(value))


def from_js_array(value):
    return bytes(bytearray(value))


app = Flask(__name__)

global credential, last_challenge
credential, last_challenge = None, None


@app.route('/')
def index():
    return INDEX_HTML


@app.route('/register', methods=['GET', 'POST'])
def register():
    global credential, last_challenge
    if request.method == 'POST':
        data = request.get_json(force=True)
        client_data = ClientData(from_js_array(data['clientData']))
        att_obj = AttestationObject(from_js_array(data['attestationObject']))
        print('clientData', client_data)
        print('AttestationObject:', att_obj)

        # Verify the challenge
        if client_data.challenge != last_challenge:
            raise ValueError('Challenge mismatch!')

        # Verify the signature
        att_obj.verify(client_data.hash)
        credential = att_obj.auth_data.credential_data
        print('REGISTERED CREDENTIAL:', credential)
        return 'OK'

    last_challenge = os.urandom(32)
    return REGISTER_HTML.format(
        user_id=to_js_array(b'user_id'),
        challenge=to_js_array(last_challenge)
    )


@app.route('/authenticate', methods=['GET', 'POST'])
def authenticate():
    global credential, last_challenge
    if not credential:
        return HTML.format(content='No credential registered!')

    if request.method == 'POST':
        data = request.get_json(force=True)
        client_data = ClientData(from_js_array(data['clientData']))
        auth_data = AuthenticatorData(from_js_array(data['authenticatorData']))
        signature = from_js_array(data['signature'])
        print('clientData', client_data)
        print('AuthenticatorData', auth_data)

        # Verify the challenge
        if client_data.challenge != last_challenge:
            raise ValueError('Challenge mismatch!')

        # Verify the signature
        credential.public_key.verify(auth_data + client_data.hash, signature)
        print('ASSERTION OK')
        return 'OK'

    last_challenge = os.urandom(32)
    return AUTH_HTML.format(
        challenge=to_js_array(last_challenge),
        credential_id=to_js_array(credential.credential_id)
    )


if __name__ == '__main__':
    print(__doc__)

    app.run(ssl_context='adhoc', debug=True)
