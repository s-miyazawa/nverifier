# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2022, TRASIO
# Copyright (c) 2023, SECOM CO., LTD. All Rights reserved.

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cwt import COSEKey
from flask import Blueprint, make_response, request
from flask_restful import Api, Resource
import json

from common.ex_cwt import EXCWT
from properties import Properties

EAT_NONCE = 'abcd8860d13a463e8e'

class Tam(Resource):
    bp = Blueprint('tam', __name__)

    def __init__(self):
        self.__conf = Properties.get('tam')

    def get(self):
        """
        get an challenge
        :return:
        """
        res = make_response(bytes.fromhex(EAT_NONCE))
        return res

    def post(self):
        """
        POST AR and get some data
        :return:
        """
        cwt = request.get_data()
        excwt = EXCWT()

        verifier_public_key_file = Properties.get_path(self.__conf['verifier_public_key_file'])
        if verifier_public_key_file is None:
            return
        with open(verifier_public_key_file) as f:
            public_key = COSEKey.from_pem(f.read(), kid='301')

        payload = excwt.decode(cwt, public_key)
        eat_nonce = payload[10]
        eat_nonce_str = eat_nonce.hex()
        if eat_nonce_str == EAT_NONCE:
            message = 'eat_nonce is match'
        else:
            message = 'eat_nonce is NOT match'

        text = str(payload)
        return {
            "message": message,
            "sample": text
        }


api = Api(Tam.bp)
api.add_resource(Tam, '')
