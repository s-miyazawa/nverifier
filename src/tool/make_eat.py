# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2022, TRASIO
# Copyright (c) 2023, SECOM CO., LTD. All Rights reserved.

from cwt.cose_key_interface import COSEKeyInterface
from cwt import COSEKey
from cryptography import x509
from properties import Properties
from cryptography.hazmat.primitives import serialization

from common.ex_cwt import EXCWT


class CWT(object):

    def __init__(self, cert_pem_list, pkey_pem=None):
        self.__cert_pem_list = cert_pem_list
        if pkey_pem:
            self.__cose_prv_key: COSEKeyInterface = COSEKey.from_pem(pkey_pem, key_ops=['sign'])
        self.__excwt = EXCWT()

    def create(self, payload):
        cert_der_list = []
        for cert_pem in self.__cert_pem_list:
            cert = x509.load_pem_x509_certificate(cert_pem.encode())
            der = cert.public_bytes(encoding=serialization.Encoding.DER)
            cert_der_list.append(der)
        protected = {
            'x5chain': cert_der_list
        }
        cwt = self.__excwt.encode_and_sign(
            claims=payload,
            key=self.__cose_prv_key,
            protected=protected
        )
        return cwt

    def get_payload(self, cwt):
        protected = self.__excwt.get_protected(cwt)

        # getting a certificate of a signer from a protected header of EAT
        cert_der = protected[33][0]
        cert = x509.load_der_x509_certificate(cert_der)
        key = COSEKey.from_pem(cert.public_bytes(encoding=serialization.Encoding.PEM))

        # Successfully verified a signature
        payload = self.__excwt.decode(cwt, key)
        return payload


def main():
    Properties.set_profile('develop')
    with open(Properties.get_path('ca_certificate_file')) as ca_cert, \
            open(Properties.get_path('my_certificate_file')) as my_cert, \
            open(Properties.get_path('my_private_key_file')) as my_pkey:
        ca_cert_pem = ca_cert.read()
        my_cert_pem = my_cert.read()
        my_pkey_pem = my_pkey.read()

    gen = CWT([my_cert_pem, ca_cert_pem], my_pkey_pem)

    payload = {
        10: bytes.fromhex('948f8860d13a463e8e'),  # eat_nonce
        256: bytes.fromhex('0198f50a4ff6c05861c8860d13a638ea'),  # ueid
        258: bytes.fromhex('894823'),  # oemid
        259: bytes.fromhex('549dcecc8b987c737b44e40f7c635ce8'),  # hwmodel
        260: ['1.3.4', 1],  # hwversion
        273: [
            [60,
             {
                 1: 'https://example.com/manifest.cbor',
                 0: [
                     -16,
                     bytes.fromhex('a7fd6593eac32eb4be578278e6540c5c'),
                     bytes.fromhex('09cfd7d4d234973054833b2b93030609')
                 ]
             }]

        ]  # manifests
    }
    cwt = gen.create(payload)
    print(cwt.hex())

    payload = gen.get_payload(cwt)

    print(payload[273])

    # TODO: verifying a certificate


if __name__ == '__main__':
    main()
