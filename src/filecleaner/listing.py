"""List a directory, asking again when the listing is interrupted.

Inside another app's sandbox (``~/Library/Containers``, ``~/Library/Group
Containers``) macOS now and then hangs the opening of a directory for several
seconds and then fails it with EINTR; asked again it answers at once. Every
walk done in Python lists its directories through here, so that an
interrupted listing is retried instead of being taken for an unreadable
directory — which a scan would report as an error and leave unscanned, and a
file walk would leave out without a word.

This is also why none of those walks can be an ``os.walk``: it does the
``scandir`` itself and swallows its error, leaving the caller nothing to
retry.
"""

from __future__ import annotations

import os

LISTING_RETRIES = 8


def list_dir(path: str) -> list[os.DirEntry[str]]:
    """Every entry of ``path``. An interrupted listing is retried
    ``LISTING_RETRIES`` times; any other error, and an interruption that
    outlasts the retries, is the caller's to handle."""
    for _ in range(LISTING_RETRIES):
        try:
            with os.scandir(path) as it:
                return list(it)
        except InterruptedError:
            continue
    with os.scandir(path) as it:
        return list(it)
