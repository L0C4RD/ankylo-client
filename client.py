#!/usr/bin/env python3


import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import uuid

from keri.core import coring

from utils.crypto import Crypto



class Client:

    def __init__(self, url, algorithm):
        self.url = url
        self.session = requests.session()

        # Generate GLEIF AID
        self.aid = "lolol"
        self.gleif_key_algorithm = algorithm
        if algorithm in (coring.MtrDex.Ed25519, coring.MtrDex.Ed25519N):
            self.gleif_private_key = Ed25519PrivateKey.generate()
        elif algorithm in (coring.MtrDex.ECDSA_256r1, coring.MtrDex.ECDSA_256r1N):
            self.gleif_private_key = ec.generate_private_key(ec.SECP256R1())
        elif algorithm in (coring.MtrDex.ECDSA_256k1, coring.MtrDex.ECDSA_256k1N):
            self.gleif_private_key = ec.generate_private_key(ec.SECP256K1())

        # Generate credential keys
        self.credential_private_key_dh = mldsa.MLDSA44PrivateKey.generate()
        self.credential_private_key_rsa = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    def _post_data(self, endpoint, data:dict):
        response = self.session.post(f"{self.url}/{endpoint}", data=data)
        print(response.json())
        response.raise_for_status()
        return response.json()

    def create_new_user(self, username:str, password:str):

        print("Creating new user")
        print(f"{username}:{password}")

        data = self._post_data("api/user/create", {
            "username" : username,
            "password" : password
        })

        return data

    def logout(self):

        print("Logging out.")

        data = self._post_data("api/user/logout", {})

        return data

    def delete(self):

        print("Deleting currently logged in user.")

        data = self._post_data("api/user/delete", {})

        return data

    def verify_aid(self):

        # generate public key.

        print("Verifying aid.")

        public_key = self.gleif_private_key.public_key()

        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        public_key_b64 = self.gleif_key_algorithm + Crypto.bytes_to_base64(public_key_bytes)

        data = self._post_data("api/org/verification/challenge_request", {
            "aid": self.aid,
            "oobi": public_key_b64,
            "poc" : 1
        })

        challenge = data.get("challenge")
        challenge_id = data.get("challenge_id")

        # Sign the challenge with the private key
        if isinstance(self.gleif_private_key, Ed25519PrivateKey):
            signature = self.gleif_private_key.sign(challenge.encode())
        else:
            signature = self.gleif_private_key.sign(challenge.encode(), ec.ECDSA(hashes.SHA256()))

        return self._post_data("api/org/verification/challenge_response", {
            "challenge_id": challenge_id,
            "signatures": self.gleif_key_algorithm + Crypto.bytes_to_base64(signature)
        })


    def request_new_credential(self):

        print("Requesting new credential.")

        rsa_public_key = self.credential_private_key_rsa.public_key()
        mldsa_public_key = self.credential_private_key_dh.public_key()

        rsa_public_key_bytes = rsa_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        mldsa_public_key_bytes = mldsa_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        rsa_public_key_b64 = Crypto.bytes_to_base64(rsa_public_key_bytes)
        mldsa_public_key_b64 = Crypto.bytes_to_base64(mldsa_public_key_bytes)

        data = self._post_data("api/org/attributes/keys/challenge_request", {
            "aid" : self.aid,
            "rsa_pub_b64" : rsa_public_key_b64,
            "MLDSA_pub_b64" : mldsa_public_key_b64,
        })


        challenge = data.get("challenge")
        challenge_id = data.get("challenge_id")


        # Sign the challenge with the two private keys
        rsa_signature = self.credential_private_key_rsa.sign(challenge.encode(), padding.PKCS1v15(), hashes.SHA256())
        mldsa_signature = self.credential_private_key_dh.sign(challenge.encode())

        return self._post_data("api/org/attributes/keys/challenge_response", {
            "challenge_id": challenge_id,
            "rsa_signature" : Crypto.bytes_to_base64(rsa_signature),
            "MLDSA_signature" : Crypto.bytes_to_base64(mldsa_signature),
        })