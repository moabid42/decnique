#!/usr/bin/env python3
"""decnique — interactive front door.

    python3 run.py                              start the interactive shell
    python3 run.py blindspots iam.foo.bar        one-shot: run a single command and exit
    python3 run.py trace -e events.json rules/   (delegates to decnique.cli)

The shell holds a *session*: a loaded library of detections + candidates, an account model,
and an ordered event trace.  It answers three-valued (yes / no / don't-know) using the real
engine — never a reimplementation — and, for the coverage verbs (`blindspots`, `stealth`,
`chains`), narrates the actual checks and replays each witness through the concrete oracle.

The UI lives in :mod:`decnique.ui`; this file is only the launcher.
"""

from __future__ import annotations

import sys

from decnique.ui.repl import main

if __name__ == "__main__":
    sys.exit(main())
