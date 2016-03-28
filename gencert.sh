#!/bin/bash

SIZE=4096

openssl req -x509 -newkey rsa:$SIZE -keyout key.pem -out cert.pem
