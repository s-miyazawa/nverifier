# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2022, TRASIO
# Copyright (c) 2023, SECOM CO., LTD. All Rights reserved.

from flask import Flask

from properties import Properties
from server.tam import Tam
from server.verifier import Verifier

app = Flask(__name__)
app.register_blueprint(Verifier.bp, url_prefix='/verify')
app.register_blueprint(Tam.bp, url_prefix='/tam')

if __name__ == '__main__':
    Properties.set_profile('develop')
    app.run(debug=True, host="0.0.0.0")
