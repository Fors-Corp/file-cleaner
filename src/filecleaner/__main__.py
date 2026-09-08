"""Allow ``python -m filecleaner`` as an alternative to the ``fclean`` entry point."""

from filecleaner.cli import _entrypoint

if __name__ == "__main__":
    _entrypoint()
