#!/bin/sh
set -eu
python -m compileall -q sealvault demo_support portal
python -m unittest discover -s tests -v
python -m sealvault replay fixtures/sealing.json
python demo_support/check.py
python demo_support/capture_drill.py
