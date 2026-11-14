#!/usr/bin/env bash
#
# run_in_venv.sh
#
# - Checks for a Python venv, creating it if missing
# - Activates the venv
# - Installs required packages from requirements.txt
# - Runs your code inside the venv
# - Deactivates the venv when done
#
# Usage:
#   ./run-in-venv.sh

set -euo pipefail

# ---- Configuration ----------------------------------------------------
VENV_DIR=".venv"                # Where the venv lives
SCRIPT_TO_RUN="client.py"    # The code you want to run inside the venv


# ------------------------------------------------------------------------

# 1. Check for the venv; create it if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo "Virtual environment not found at '$VENV_DIR'. Creating it..."
    python3 -m venv "$VENV_DIR"
else
    echo "Virtual environment already exists at '$VENV_DIR'."
fi

# 2. Activate the venv
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

# 3. Check whether the packages are installed; install them if not
pip install -r requirements.txt
pip install requests


# 4. Set environment variables (use an existing FLASK_SECRET_KEY if provided,
#    otherwise generate a random one for this run)
export FLASK_SECRET_KEY="${FLASK_SECRET_KEY:-$(openssl rand -hex 64)}"
export FLASK_DEBUG="${FLASK_DEBUG:-0}"

# 5. Run your code inside the venv
echo "Running ${SCRIPT_TO_RUN}..."
python "${SCRIPT_TO_RUN}"

# 6. Deactivate the venv
echo "Deactivating virtual environment..."
deactivate

echo "Done."