#!/usr/bin/env bash
# Bootstraps a project-local virtual environment and installs File Cleaner
# into it. No system-wide changes, no sudo, no Homebrew/network dependency
# beyond PyPI for the (few, small) pure-Python packages this uses.
#
# If a Rust toolchain is present it also builds the optional native scan
# walker (native/fclean-walk), which makes large scans several times faster.
# Without one, File Cleaner works exactly the same, just walking in Python.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [ ! -d .venv ]; then
    echo "Creating virtual environment in .venv ..."
    python3 -m venv .venv
fi

echo "Installing File Cleaner (editable) + dev dependencies ..."
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -e ".[dev]"

if command -v cargo >/dev/null 2>&1; then
    echo "Building the native scan walker (cargo found) ..."
    if cargo build --release --quiet --manifest-path native/fclean-walk/Cargo.toml; then
        mkdir -p src/filecleaner/_bin
        cp native/fclean-walk/target/release/fclean-walk src/filecleaner/_bin/fclean-walk
    else
        echo "  ... the build failed; continuing without it (scans will walk in Python)."
    fi
else
    echo "No Rust toolchain found: skipping the optional native scan walker."
    echo "  (Install Rust from https://rustup.rs and re-run this script to enable it.)"
fi

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
