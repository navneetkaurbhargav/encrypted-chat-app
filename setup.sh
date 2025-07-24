#!/bin/bash

echo "Setting up Secure Chat Application with CA Authority..."

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install requirements
pip install -r requirements.txt

# Create certificates directory
mkdir -p certs

echo "Setup complete!"
echo ""
echo "To run the application:"
echo "1. Activate virtual environment: source venv/bin/activate"
echo "2. Start server: python server.py"
echo "3. Start client: python client.py"
echo ""
echo "The CA Authority will automatically generate and validate certificates."
