#!/bin/bash

# Generate CA private key
openssl genrsa -out ca.key 4096

# Generate CA certificate
openssl req -new -x509 -days 365 -key ca.key -out ca.pem -subj "/CN=CoreDNS-CA"

# Generate server private key
openssl genrsa -out key.pem 4096

# Create extensions file for SAN
cat > server_ext.conf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names

[alt_names]
DNS.1=coredns
DNS.2=localhost
DNS.3=*.coredns.local
IP.1=127.0.0.1
EOF

# Generate server certificate signing request
openssl req -new -key key.pem -out server.csr -subj "/CN=coredns"

# Generate server certificate signed by CA with extensions
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out cert.pem -days 365 -extfile server_ext.conf

# Clean up
rm server.csr ca.key server_ext.conf
rm -f ca.srl

# Verify
echo "Generated files:"
ls -la cert.pem key.pem ca.pem

# Additional verification: Check key usage
echo "Certificate details:"
openssl x509 -in cert.pem -noout -text | grep -A 2 "Key Usage"
