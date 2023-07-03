# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2022, TRASIO
# Copyright (c) 2023, SECOM CO., LTD. All Rights reserved.

import copy
import urllib.request
from typing import Any, Dict, List

from cwt import COSEKey
from cwt.cose_key_interface import COSEKeyInterface

from common.ex_cwt import EXCWT
from properties import Properties


class EndEntity(object):
    def __init__(self):
        self.__conf = Properties.get('ee')
        self.__excwt = EXCWT()
        self.__cose_private_key = None

    def __load_credentials(self):
        if self.__cose_private_key is not None:
            return
        ee_private_key_file = Properties.get_path(self.__conf['ee_private_key_file'])
        if ee_private_key_file is None:
            return
        with open(ee_private_key_file) as f:
            data = f.read()
        self.__cose_private_key: COSEKeyInterface = \
            COSEKey.from_pem(data, key_ops=['sign'], kid='101', alg='ES256')

    def _get_nonce_from_verifier(self) -> bytes:
        server_url = self.__conf['verifier_url']
        with urllib.request.urlopen(server_url) as response:
            nonce = response.read()
        return nonce

    def _post_cwt_to_verifier(self, cwt: bytes) -> bytes:
        server_url = self.__conf['verifier_url']
        with urllib.request.urlopen(server_url, data=cwt) as response:
            attestation_result = response.read()
        return attestation_result

    def _get_eat_nonce_from_tam(self) -> bytes:
        server_url = self.__conf['tam_url']
        with urllib.request.urlopen(server_url) as response:
            eat_nonce = response.read()
        return eat_nonce

    def _collect_evidence(self) -> Dict[int, Any]:
        evidence = {
            1: 'End Entity',
            256: bytes.fromhex('0198f50a4ff6c05861c8860d13a638ea'),  # ueid
            258: bytes.fromhex('894823'),  # oemid
            262: True,  # oemboot
            263: 3,  # dbgstat
            260: ['3.1', 1],  # hwversion
        }
        return evidence

    def _make_cwt_for_attestation(self, nonce: bytes, eat_nonce: bytes, evidence: Dict[int, Any]) -> bytes:
        self.__load_credentials()
        claims = copy.copy(evidence)
        claims[10] = eat_nonce
        claims[-70000] = nonce
        cwt = self.__excwt.encode_and_sign(
            claims=claims,
            key=self.__cose_private_key
        )
        return cwt

    def _post_attestation_result_to_tam(self, attestation_result: bytes) -> Any:
        server_url = self.__conf['tam_url']
        with urllib.request.urlopen(server_url, attestation_result) as response:
            message = response.read()
        return message

    def _attestation(self, eat_nonce: bytes) -> bytes:
        evidence = self._collect_evidence()
        nonce = self._get_nonce_from_verifier()
        cwt = self._make_cwt_for_attestation(nonce, eat_nonce, evidence)
        attestation_result = self._post_cwt_to_verifier(cwt)
        return attestation_result

    def some_operation_with_tam(self):
        eat_nonce = self._get_eat_nonce_from_tam()
        attestation_result = self._attestation(eat_nonce)
        message_from_tam = self._post_attestation_result_to_tam(attestation_result)
        print(message_from_tam.decode())


def main():
    end_entity: EndEntity = EndEntity()
    end_entity.some_operation_with_tam()


if __name__ == '__main__':
    Properties.set_profile('develop')
    main()
