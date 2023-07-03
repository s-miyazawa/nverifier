# Naive Verifier

Naive Verifier is a demo verifier application for TEEP protocol.

## Installing

```bash
git clone git@github.com:trasio-org/nverifier.git
cd nverifier
pip install -r requirements.txt
```

## Running an Naive Verifier

```bash
cd nverifier/src
python -m server.app
```

## Running an test Naive Verifier Client

```bash
cd nverifier/src
python -m client.end_entity
```

## Docker Container

```bash
docker build -t nverifier .
docker run --network=host -it nverifier
```

## Keys

### Keys for Naive Verifier

* `resources/verifier/private_1.key`
* `resources/verifier/public_1.key`

```openssl
read EC key
Private-Key: (256 bit)
priv:
    4b:fa:88:a2:fd:6c:d0:2c:c2:6d:d4:41:c7:df:09:
    60:b0:4b:84:35:d7:2d:aa:7c:e1:40:cf:54:4e:b0:
    00:50
pub:
    04:2a:fb:0a:bc:6a:31:86:81:22:e2:53:43:b6:b4:
    5a:5b:9b:f0:cc:b9:16:a2:dc:22:a0:07:49:ff:f6:
    92:8e:91:3a:26:02:c7:e9:5a:55:d4:b6:9d:82:a1:
    9a:4a:ee:80:81:e8:cf:e4:c7:71:2f:2f:06:01:0d:
    75:ec:0c:3d:2f
ASN1 OID: prime256v1
NIST CURVE: P-256
```

### Keys for EE

* `src/properties.py`

Specifying the public key files corresponding to `keyid` in `ee_pub_keys`.

```python
'verifier': {
    'verifier_private_key_file': '../resources/verifier/private_1.key',
    'db_file': '../data/verifier_db.json',
    'ee_pub_keys': {
        '101': '../resources/ee/public_1.key',
        '102': '../resources/ee/public_2.key'
    }
}
```

## License and Copyright

BSD 2-Clause License

Copyright (c) 2023 SECOM CO., LTD. All Rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
