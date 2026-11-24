"""Compatibility entry point for callers that still use cli.py or import cli."""
import sys

import websift

if __name__ == '__main__':
    raise SystemExit(websift.main())

sys.modules[__name__] = websift
