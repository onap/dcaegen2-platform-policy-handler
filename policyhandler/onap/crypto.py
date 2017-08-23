"""ONAP specific encryption-decryption for passwords"""

# org.onap.dcae
# ================================================================================
# Copyright (c) 2017 AT&T Intellectual Property. All rights reserved.
# ================================================================================
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ============LICENSE_END=========================================================
#
# ECOMP is a trademark and service mark of AT&T Intellectual Property.

import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random

class Cipher(object):
    """class for AES-256 encryption and decryption of text using the salted password"""
    KEY_SIZE = 32      # AES-256
    KDF_ITERATIONS = 16384
    AES_MODE = AES.MODE_CFB

    @staticmethod
    def encrypt(password, plain_text):
        """
        encrypt the :plain_text: into :cipher_text: using the password

        :cipher_text: formatted as pbkdf2_salt + init_vector + encrypt(:plain_text:)
        then cipher_text is encoded as base64 to make it textable (non-binary)

        :pbkdf2_salt: has the fixed length of 32 (AES-256)
        :init_vector: has the fixed length of AES.block_size
        """
        pbkdf2_salt = Random.new().read(Cipher.KEY_SIZE)
        init_vector = Random.new().read(AES.block_size)
        derived_key = PBKDF2(password, pbkdf2_salt, Cipher.KEY_SIZE, Cipher.KDF_ITERATIONS)

        cipher = AES.new(derived_key, Cipher.AES_MODE, init_vector)
        cipher_text = base64.b64encode(pbkdf2_salt + init_vector + cipher.encrypt(plain_text))
        return cipher_text

    @staticmethod
    def decrypt(password, cipher_text):
        """
        decrypt the :cipher_text: into :plain_text: using the password

        :cipher_text: is expected to be encoded as base64 to make it textable (non-binary)
        inside of that it is expected to be formatted as
        pbkdf2_salt + init_vector + encrypt(:plain_text:)

        :pbkdf2_salt: has the fixed length of 32 (AES-256)
        :init_vector: has the fixed length of AES.block_size
        """
        cipher_text = base64.b64decode(cipher_text)
        pbkdf2_salt = cipher_text[: Cipher.KEY_SIZE]
        init_vector = cipher_text[Cipher.KEY_SIZE : Cipher.KEY_SIZE + AES.block_size]
        cipher_text = cipher_text[Cipher.KEY_SIZE + AES.block_size :]
        derived_key = PBKDF2(password, pbkdf2_salt, Cipher.KEY_SIZE, Cipher.KDF_ITERATIONS)

        cipher = AES.new(derived_key, Cipher.AES_MODE, init_vector)
        plain_text = cipher.decrypt(cipher_text).decode('utf-8')
        return plain_text
