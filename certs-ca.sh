cd credentials/certs
openssl genpkey -algorithm rsa -out ca-rsa.key -pkeyopt rsa_keygen_bits:2048
openssl req -key ca-rsa.key -new -x509 -days 3650 -addext keyUsage=critical,keyCertSign,cRLSign -subj "/CN=toranokuni" -out ca-rsa.crt
openssl x509 -inform PEM -in ca-rsa.crt -out ca-rsa.der -outform DER
cd ..
mkdir wolfssl
perl ../gencertbuf.pl