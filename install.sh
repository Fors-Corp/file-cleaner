#!/usr/bin/env bash
# Bootstraps a project-local virtual environment and installs File Cleaner
# into it. No system-wide changes, no sudo, no Homebrew/network dependency
# beyond PyPI for the (few, small) pure-Python packages this uses.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [ ! -d .venv ]; then
    echo "Creating virtual environment in .venv ..."
    python3 -m venv .venv
fi

echo "Installing File Cleaner (editable) + dev dependencies ..."
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -e ".[dev]"

mkdir -p bin
cat > fclean <<'EOF'
#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$DIR/.venv/bin/fclean" "$@"
EOF
chmod +x fclean

echo ""
echo "Done. Run it with:"
echo "  ./fclean --help"
echo ""
echo "(Optional) put it on your PATH for the current shell:"
echo "  export PATH=\"$(pwd):\$PATH\""
