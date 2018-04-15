#!/bin/bash

# Linting the project.
if [ "$SCRIPT" = "lint" ]; then
    flake8 virtualbox/
fi

# Making sure our distribution contains all files.
if [ "$SCRIPT" = "packaging" ]; then
    check-manifest --ignore *.yml,.github*,.travis*
    python setup.py check --metadata --restructuredtext --strict
fi

# Comparing latest VirtualBox API against virtualbox/_base.py
if [ "$SCRIPT" = "build" ]; then
    python build.py --build-against-master --force-download
fi

# Running all unit tests.
if [ "$SCRIPT" = "tests" ]; then
    pytest tests/ --cov virtualbox
fi
