#!/bin/sh
PYTHONPATH="/usr/lib/rdheadless${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONPATH
exec /usr/bin/python3 -m rdheadless "$@"
