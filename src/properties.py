# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2022, TRASIO
# Copyright (c) 2023, SECOM CO., LTD. All Rights reserved.

import os


class Properties(object):
    __profile = None
    __properties = {
        '__default__': {
            'ee': {
                'ee_private_key_file': '../resources/ee/private_1.key',
                'verifier_url': 'http://127.0.0.1:5000/verify',
                'tam_url': 'http://127.0.0.1:5000/tam',
            },
            'tam': {
                'verifier_public_key_file': '../resources/verifier/public_1.key',
            },
            'verifier': {
                'verifier_private_key_file': '../resources/verifier/private_1.key',
                'db_file': '../data/verifier_db.json',
                'ee_pub_keys': {
                    '101': '../resources/ee/public_1.key',
                    '102': '../resources/ee/public_2.key'
                }
            },
        },
        'develop': {

        },
        'production': {

        }
    }

    @classmethod
    def set_profile(cls, profile: str):
        if cls.__profile is not None and cls.__profile != profile:
            raise Exception(f'can\'t change profile from {cls.__profile} to {profile}')
        else:
            cls.__profile = profile

    @classmethod
    def get_path(cls, rel_path) -> str | None:
        if rel_path is None:
            return None
        path = os.path.join(os.path.dirname(__file__), rel_path)
        return path

    @classmethod
    def get(cls, name) -> any: # type: ignore
        if cls.__profile is None:
            if 'PROFILE' in os.environ:
                cls.__profile = os.environ['PROFILE']

        result = None
        if cls.__profile in cls.__properties:
            result = cls.__properties[cls.__profile].get(name)

        if result is None:
            result = cls.__properties['__default__'].get(name)

        return result
