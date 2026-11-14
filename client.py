#!/usr/bin/env python3


import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

from keri.core import coring

from utils.crypto import Crypto



class Client:

    def __init__(self, url, algorithm):
        self.url = url
        self.algorithm = algorithm

    # Generate GLEIF AID
        self.aid = "lolol"
        if algorithm in (coring.MtrDex.Ed25519, coring.MtrDex.Ed25519N):
            self.private_key = Ed25519PrivateKey.generate()
        elif algorithm in (coring.MtrDex.ECDSA_256r1, coring.MtrDex.ECDSA_256r1N):
            self.private_key = ec.generate_private_key(ec.SECP256R1())
        elif algorithm in (coring.MtrDex.ECDSA_256k1, coring.MtrDex.ECDSA_256k1N):
            self.private_key = ec.generate_private_key(ec.SECP256K1())

    def _post_data(self, endpoint, data:dict):
        response = requests.post(f"{self.url}/{endpoint}", data=data)
        response.raise_for_status()
        return response.json()


    def verify_aid(self):

        # generate public key.

        print(1)

        public_key = self.private_key.public_key()

        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        public_key_b64 = self.algorithm + Crypto.bytes_to_base64(public_key_bytes)

        print(2)

        data = self._post_data("api/user/verification/challenge_request", {
            "aid": self.aid,
            "oobi": public_key_b64,
            "poc" : 1
        })

        print(3)

        challenge = data.get("challenge")
        challenge_id = data.get("challenge_id")

        # Sign the challenge with the private key
        if isinstance(self.private_key, Ed25519PrivateKey):
            signature = self.private_key.sign(challenge.encode())
        else:
            signature = self.private_key.sign(challenge.encode(), ec.ECDSA(hashes.SHA256()))

        print(4)

        return self._post_data("api/user/verification/challenge_response", {
            "challenge_id": challenge_id,
            "signatures": self.algorithm + Crypto.bytes_to_base64(signature)
        })

if __name__ == "__main__":
    client = Client("http://localhost:5000", coring.MtrDex.Ed25519)
    print(client.verify_aid())