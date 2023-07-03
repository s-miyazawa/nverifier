# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2022, TRASIO
# Copyright (c) 2023, SECOM CO., LTD. All Rights reserved.

FROM python:latest

WORKDIR /usr/src/verifier/

COPY requirements.txt /usr/src/verifier/
RUN pip install -r requirements.txt

COPY . /usr/src/verifier/

ENV PORT 5000
EXPOSE $PORT
WORKDIR /usr/src/verifier/src/
CMD [ "python", "-m", "server.app" ]
