"""Minimal Flask API for Ankylo Core.

Designed for Azure App Service: exposes a module-level `app` object so the
default startup command (`gunicorn app:app`) works without configuration.
"""


import os
import tempfile

from flask import Blueprint, Flask, jsonify, request, session
from handlers.user.user import UserManager
from handlers.gleif.aid import CompanyVerifier



def create_app() -> Flask:

	app = Flask(__name__)

	app.secret_key = os.environ["FLASK_SECRET_KEY"]

	app.config.update(
		SESSION_COOKIE_SAMESITE="Lax",   # browser won't attach the cookie to cross-site POSTs
		SESSION_COOKIE_HTTPONLY=True,    # Flask default, but explicit is better
		SESSION_COOKIE_SECURE=True,      # cookie only sent over HTTPS
	)

	@app.route("/health")
	def health():
		"""Health probe endpoint for Azure App Service."""
		return jsonify({"status": "ok"})

	@app.route("/", methods=["GET"])
	def index():

		from handlers.gleif.vlei import GLEIFManager, _ALGORITHMS_BY_CODE
		from pathlib import Path

		from handlers.gleif.GLEIF import AIDResolutionError
		from handlers.gleif.vlei import AIDVerificationError, GLEIFManager

		GLEIF_INTERNAL = "EFcrtYzHx11TElxDmEDx355zm7nJhbmdcIluw7UMbUIL"
		GLEIF_EXTERNAL = "EINmHd5g7iV-UldkkkKyBIH052bIyxZNBn9pq-zNrYoS"

		for i in _ALGORITHMS_BY_CODE:
			print(f"Algorithm code: {i}, details: {_ALGORITHMS_BY_CODE[i]}")

		with tempfile.TemporaryDirectory() as pin_dir:

			manager = GLEIFManager(Path(pin_dir) / "gleif-trust-pin.json")


			results = []
			for name, aid in (
				("GLEIF Internal", GLEIF_INTERNAL),
				("GLEIF External", GLEIF_EXTERNAL),
			):

				try:
					result = manager.resolve_aid(aid)
				except (AIDResolutionError, AIDVerificationError) as error:
					results.append({"name": name, "aid": aid, "error": str(error)})
					

					continue

				results.append({"name": name, "aid": aid, "result": result})
				print(f"{name} AID: {aid}")

		return jsonify({"status": "ok", "results": results}), 200
	return app


app = create_app()


if __name__ == "__main__":
	# Local development only; Azure App Service runs this via gunicorn.

	enable_debug = os.environ.get("FLASK_DEBUG", "0") == "1"

	app.run(host="127.0.0.1", port=5000, debug=enable_debug)
