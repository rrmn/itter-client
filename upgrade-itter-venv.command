#!/bin/bash
# Upgrades asyncssh in the Python environment of the itter app next to this
# folder (../itter/itterapp/.venv) to what the app's requirements.txt asks for
# now: 2.24.1 or newer. That version offers the post-quantum SSH key exchange,
# and pip brings along the cryptography release it needs. Nothing else in the
# environment is touched, and the app's .env is not read.
#
# Double-click it in Finder, or run it from a terminal. It downloads the two
# packages from PyPI (under 10 MB).
#
# What was installed before is written to _run/venv-before.txt. To go back:
#   ../itter/itterapp/.venv/bin/python -m pip install -r _run/venv-before.txt
#
# Results: _run/upgrade.status and _run/upgrade.log.

cd "$(dirname "$0")" || exit 1
ROOT=$(pwd)
ITTERAPP="${ITTERAPP:-$ROOT/../itter/itterapp}"
PY="$ITTERAPP/.venv/bin/python"
WANT='asyncssh>=2.24.1,<3.0.0'
mkdir -p _run
rm -f _run/upgrade.done _run/upgrade.status
exec > >(tee _run/upgrade.log) 2>&1

echo "itter venv upgrade started $(date)"
finish() {
	echo "$1" > _run/upgrade.status
	echo
	echo "RESULT: $2"
	echo "finished $(date)"
	date > _run/upgrade.done
	exit "$3"
}
[ -x "$PY" ] || finish "upgrade=novenv" "no Python environment at $ITTERAPP/.venv" 1
if ! grep -q "^$WANT" "$ITTERAPP/requirements.txt" 2>/dev/null; then
	echo "Note: $ITTERAPP/requirements.txt does not ask for $WANT (yet)."
fi
versions() {
	"$PY" -c 'import asyncssh, cryptography
from asyncssh.crypto import mlkem_available
print("asyncssh", asyncssh.__version__, "| cryptography", cryptography.__version__, "| post-quantum key exchange:", "yes" if mlkem_available else "no")'
}
"$PY" --version
echo "before: $(versions)"
if [ ! -s _run/venv-before.txt ] || ! "$PY" -c 'import asyncssh, sys; sys.exit(0 if tuple(int(x) for x in asyncssh.__version__.split(".")[:3]) >= (2, 24, 1) else 1)'; then
	# Kept from the first run only: running this again must not overwrite
	# the record of what there was before the upgrade.
	"$PY" -m pip freeze > _run/venv-before.txt || finish "upgrade=nopip" "pip does not work in that environment" 1
fi

echo
echo "=== pip install --upgrade \"$WANT\""
"$PY" -m pip install --disable-pip-version-check --upgrade "$WANT"
rc=$?
echo
echo "=== pip check"
"$PY" -m pip check
chk=$?
"$PY" -m pip freeze > _run/venv-after.txt
echo
echo "=== what changed"
diff _run/venv-before.txt _run/venv-after.txt && echo "(nothing)"
echo
echo "after:  $(versions)"
if [ $rc -ne 0 ]; then
	finish "upgrade=$rc" "pip could not install it; the environment is as it was (see above)" 1
fi
if [ $chk -ne 0 ]; then
	finish "upgrade=0 check=$chk" "installed, but pip reports packages that do not fit together (see above). To go back: $PY -m pip install -r $ROOT/_run/venv-before.txt" 1
fi
if ! versions | grep -q "post-quantum key exchange: yes"; then
	finish "upgrade=0 check=0 pq=no" "installed, but this asyncssh still has no post-quantum key exchange" 1
fi
finish "upgrade=0 check=0 pq=yes" "done. Restart the itter app if it is running here; run-on-mac.command checks the rest" 0
