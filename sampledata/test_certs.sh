#!/bin/bash

# just to make sure that the cert chain is valid
openssl verify -CAfile ./ca.crt -untrusted ./int.crt ./ak.crt
