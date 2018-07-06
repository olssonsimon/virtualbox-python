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

# Running all unit tests.
if [ "$SCRIPT" = "tests" ]; then
    pytest tests/ --cov virtualbox
fi
