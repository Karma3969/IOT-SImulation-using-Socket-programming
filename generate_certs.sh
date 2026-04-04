#!/bin/bash
# Script to generate Self-Signed SSL Certificates for the secure Smart Home Controller.
# Run this inside your WSL environment.

echo "Generating Self-Signed SSL Certificates for localhost..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout key.pem -out cert.pem -subj "/CN=localhost"
echo "Done! The files 'cert.pem' and 'key.pem' have been generated."
