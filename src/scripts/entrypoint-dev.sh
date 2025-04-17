#!/bin/bash
# Check if "venv" exists in the current directory.
if [ -d "venv" ]; then
    echo "Found venv in the current directory. Removing it..."
    rm -rf "venv"
fi

# Check if "venv" exists in the parent directory.
if [ -d "../venv" ]; then
    echo "Found venv in the parent directory. Moving it to the current directory..."
    mv "../venv" .
else
    echo "Error: venv folder not found in the parent directory." >&2
    exit 1
fi

exec /bin/bash --rcfile <(echo "source ~/.bashrc; source venv/bin/activate")

