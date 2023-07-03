# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2022, TRASIO
# Copyright (c) 2023, SECOM CO., LTD. All Rights reserved.

import copy
import random
from typing import Union

from cwt import COSEKey
from cwt.cose_key_interface import COSEKeyInterface
from flask import Blueprint, make_response, request, abort
from flask_restful import Api, Resource

from tinydb import TinyDB, Query
from tinydb.storages import MemoryStorage
from common.ex_cwt import EXCWT
from properties import Properties
import sys
import logging

logging.basicConfig(stream=sys.stdout,
                    level=logging.DEBUG,
                    format="%(levelname)s %(asctime)s - %(message)s")


class Verifier(Resource):
    bp = Blueprint('verifier', __name__)
    __db = TinyDB(storage=MemoryStorage)

    def __init__(self):
        self.__conf = Properties.get('verifier')
        self.__excwt = EXCWT()
        self.__cert_der_list = []
        self.__cose_private_key: Union[COSEKeyInterface | None] = None
        self.__logger = logging.getLogger(__name__)
        # db_file = Properties.get_path('db_file')
        # self.__db = TinyDB(db_file)

    def get(self):
        """
        get challenge
        :return:
        """
        nonce = self._make_nonce()
        res = make_response(nonce)
        res.headers.set('Content-Type', 'application/octet-stream')
        return res

    def post(self):
        """
        POST EAT and get AR
        :return:
        """
        cwt = request.get_data()
        unprotected = self.__excwt.get_unprotected(cwt)
        kid = unprotected[4]
        kid_str = bytes.decode(kid)

        self.__logger.debug(f'cose unprotected:{unprotected}')

        ee_public_key_file = Properties.get_path(self.__conf['ee_pub_keys'][kid_str])
        with open(ee_public_key_file) as f:
            public_key = COSEKey.from_pem(f.read(), kid=kid)

        evidence_payload = self.__excwt.decode(cwt, public_key)
        self.__logger.debug(f'evidence:{evidence_payload}')

        ar_payload = copy.copy(evidence_payload)

        nonce = ar_payload[-70000]
        stored_nonce = self._pop_nonce(nonce)
        if stored_nonce is None:
            abort(406, "nonce is not match")

        print(ar_payload)
        ar_payload[1] = 'Naive Verifier'
        # adding cnf into AR
        # ar_payload[8] = {
        #     3: b'123'
        # }

        eat = self._make_attestation_result(ar_payload)
        res = make_response(eat)
        res.headers.set('Content-Type', 'application/octet-stream')
        return res

    def _make_nonce(self) -> bytes:
        nonce = random.randbytes(16)
        nonce_str = nonce.hex()
        self.__db.insert({'nonce': nonce_str})
        return nonce

    def _pop_nonce(self, nonce: bytes) -> Union[bytes | None]:
        nonce_str = nonce.hex()
        q = Query()
        elm = self.__db.get(q.nonce == nonce_str)
        if elm:
            self.__db.remove(doc_ids=[elm.doc_id])
            return bytes.fromhex(elm['nonce'])
        return None

    def _make_attestation_result(self, claims):
        self.__load_credentials()
        cwt = self.__excwt.encode_and_sign(
            claims=claims,
            key=self.__cose_private_key,
        )
        return cwt

    def __load_credentials(self):
        if self.__cose_private_key is not None:
            return

        verifier_private_key_file = Properties.get_path(self.__conf['verifier_private_key_file'])
        if verifier_private_key_file is None:
            return
        with open(verifier_private_key_file) as f:
            data = f.read()
            self.__cose_private_key: COSEKeyInterface = COSEKey.from_pem(data, key_ops=['sign'],
                                                                         kid='301',
                                                                         alg='ES256')


api = Api(Verifier.bp)
api.add_resource(Verifier, '')
