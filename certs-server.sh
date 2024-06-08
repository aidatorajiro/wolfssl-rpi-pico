cd credentials/certs
. ../credentials.sh
openssl genpkey -algorithm rsa -out server-rsa.key -pkeyopt rsa_keygen_bits:2048

openssl req \
    -CA=ca-rsa.crt \
    -CAkey=ca-rsa.key \
    -key server-rsa.key \
    -addext keyUsage=digitalSignature,keyEncipherment \
    -addext basicConstraints=CA:FALSE \
    -addext "subjectAltName = DNS:$TEST_TCP_SERVER_NAME,DNS:$TEST_TCP_SERVER_IP" \
    -subj "/C=JP/ST=Chiba/O=toranokuni/CN=toranokuniserver" \
    -days 3650 -out server-rsa.crt -outform PEM
