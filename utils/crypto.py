
import secrets
import string
import argon2
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric import ec

from keri.core import coring

class Crypto:

	RNG = secrets.SystemRandom()
	SESSION_TOKEN_LENGTH = 32
	HASH_OBJECT = argon2.PasswordHasher()

	GLEIF_VERIFIER_CHALLENGE_LENGTH = 32

	@staticmethod
	def generate_session_token() -> str:
		return ''.join(Crypto.RNG.choice(string.ascii_letters + string.digits) for _ in range(Crypto.SESSION_TOKEN_LENGTH))

	@staticmethod
	def salted_hash(password: str) -> str:
		return Crypto.HASH_OBJECT.hash(password)

	@staticmethod
	def verify_password(password: str, hashed: str) -> bool:
		try:
			Crypto.HASH_OBJECT.verify(hashed, password)
			return True
		except argon2.exceptions.VerifyMismatchError:
			return False

# --- Base64 functions

	@staticmethod
	def bytes_to_base64(data: bytes) -> str:
		return base64.b64encode(data).decode('utf-8')

	@staticmethod
	def string_to_base64(data: str) -> str:
		return Crypto.bytes_to_base64(data.encode('utf-8'))

	@staticmethod
	def bytes_from_base64(data_b64: str) -> bytes:
		return base64.b64decode(data_b64)
	
	@staticmethod
	def string_from_base64(data_b64: str) -> str:
		return Crypto.bytes_from_base64(data_b64).decode('utf-8')

# --- These are for GLEIF AID verification

	@staticmethod
	def generate_challenge() -> str:
		return ''.join(Crypto.RNG.choice(string.ascii_letters + string.digits) for _ in range(Crypto.GLEIF_VERIFIER_CHALLENGE_LENGTH))

	@staticmethod
	def verify_challenge(challenge: str, signatures: list[str], public_keys: tuple) -> bool:

		try:

			pubkeys = []

			for pk in public_keys:
				if pk.startswith(coring.MtrDex.Ed25519N) or pk.startswith(coring.MtrDex.Ed25519):
					pubkeys.append(Ed25519PublicKey.from_public_bytes(Crypto.bytes_from_base64(pk)))
				elif pk.startswith(coring.MtrDex.ECDSA_256r1N) or pk.startswith(coring.MtrDex.ECDSA_256r1):
					pubkeys.append(ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), Crypto.bytes_from_base64(pk)))
				elif pk.startswith(coring.MtrDex.ECDSA_256k1N) or pk.startswith(coring.MtrDex.ECDSA_256k1):
					pubkeys.append(ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), Crypto.bytes_from_base64(pk)))

			if signatures is None:
				return False

			responses = [Crypto.bytes_from_base64(r) for r in signatures]

			if len(responses) != len(pubkeys):
				return False

			for pubkey in pubkeys:

				found_index = None
				for i, response in enumerate(responses):
					try:
						pubkey.verify(response, challenge.encode('utf-8'))
						found_index = i
						break
					except Exception:
						continue
				if found_index is None:
					return False
				else:
					responses.pop(found_index)

		except Exception:
			return False

		return True
