# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2022, TRASIO
# Copyright (c) 2023, SECOM CO., LTD. All Rights reserved.

from typing import Any, Dict, List, Optional, Union
from cwt import CWT
from cwt.cose_key_interface import COSEKeyInterface
from cwt.claims import Claims
from cwt.signer import Signer
from cbor2 import CBORTag

class EXCWT(CWT):
    def __init__(self):
        super().__init__()
        # self.cose.verify_kid = False
    def encode_and_sign(
            self,
            claims: Union[Claims, Dict[int, Any], bytes],
            key: Optional[COSEKeyInterface] = None,
            signers: List[Signer] = [],
            tagged: bool = False,
            protected: dict = {}
    ) -> bytes:
        return self.__ext_encode_and_sign(claims, key, signers, tagged, protected)

    def __ext_encode_and_sign(
            self,
            claims: Union[Claims, Dict[int, Any], bytes],
            key: Optional[COSEKeyInterface] = None,
            signers: List[Signer] = [],
            tagged: bool = False,
            protected: dict = {}
    ) -> bytes:
        if not isinstance(claims, Claims):
            self._validate(claims)
        else:
            claims = claims.to_dict()

        # adding exp:4, nbf:5, iat:6
        self._set_default_value(claims)

        b_claims = self._dumps(claims)

        res = self._cose.encode_and_sign(b_claims, key, protected, {}, signers=signers, out="cbor2/CBORTag")
        if tagged:
            return self._dumps(CBORTag(CWT.CBOR_TAG, res))
        return self._dumps(res)

    def get_protected(self, data: bytes):
        data_dict = self._loads(data)
        protected = self._loads(data_dict[0])
        return protected

    def get_unprotected(self, data: bytes):
        data_dict = self._loads(data)
        unprotected = data_dict.value[1]
        return unprotected