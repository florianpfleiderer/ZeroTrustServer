# Generate the CA's private key
openssl genrsa -out ca_private_key.pem 4096

# Create the CA's self-signed certificate
openssl req -x509 -new -nodes -key ca_private_key.pem -sha256 -days 3650 -out ca_certificate.pem
