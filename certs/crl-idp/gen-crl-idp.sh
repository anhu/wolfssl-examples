#!/bin/sh
# Generate the certificates and CRL used by tls/client-tls-unknownext.c and
# tls/server-tls-unknownext.c.
#
# Produces, in this directory:
#   ca-cert.pem / ca-key.pem                   self-signed root CA
#   server-cert.pem / server-key.pem           server cert, carries a
#                                              crlDistributionPoints extension
#                                              pointing at the CRL below
#   server-revoked-cert.pem / server-revoked-key.pem
#                                              same, but listed in the CRL
#   crl-idp.pem                                CRL signed by the CA, carrying a
#                                              critical Issuing Distribution
#                                              Point (IDP, OID 2.5.29.28)
#                                              extension
#
# wolfSSL does not decode the IDP extension. Because RFC 5280 requires IDP to
# be critical, loading crl-idp.pem fails with ASN_CRIT_EXT_E unless the
# application registers an unknown-extension callback on the certificate
# manager that accepts it. That is what the example demonstrates.
#
# Re-run this when the certs or the CRL get close to expiring:
#   openssl x509 -in server-cert.pem -noout -enddate
#   openssl crl  -in crl-idp.pem   -noout -nextupdate
#
# Requires: openssl (tested with OpenSSL 3.0)

set -e
cd "$(dirname "$0")"

CRL_URI="http://crl.example.com/crl-idp.crl"
DAYS=3650

# Scratch CA database, kept next to this script and removed on exit.
WORK=$(mktemp -d ./work.XXXXXX)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/newcerts"
: > "$WORK/index.txt"
echo 1000 > "$WORK/serial"
echo 1000 > "$WORK/crlnumber"

cat > "$WORK/openssl.cnf" <<CNF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir              = $WORK
database         = \$dir/index.txt
new_certs_dir    = \$dir/newcerts
serial           = \$dir/serial
crlnumber        = \$dir/crlnumber
default_md       = sha256
default_days     = $DAYS
default_crl_days = $DAYS
policy           = policy_any
copy_extensions  = none
unique_subject   = no
# Extensions added to every CRL this CA issues
crl_extensions   = crl_ext

[ policy_any ]
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[ req ]
distinguished_name = req_dn
prompt             = no

[ req_dn ]
CN = placeholder

# Self-signed root CA
[ ca_ext ]
basicConstraints       = critical, CA:TRUE
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

# End-entity server certificate. crlDistributionPoints tells a relying party
# where the CRL for this cert lives; its URI matches the IDP in the CRL.
[ server_ext ]
basicConstraints       = CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
subjectAltName         = DNS:www.wolfssl.com, DNS:localhost, IP:127.0.0.1
crlDistributionPoints  = URI:$CRL_URI

# CRL extensions. RFC 5280 5.2.5: the Issuing Distribution Point extension
# MUST be critical.
[ crl_ext ]
authorityKeyIdentifier   = keyid:always
issuingDistributionPoint = critical, @idp

[ idp ]
fullname = URI:$CRL_URI
onlyuser = TRUE
CNF

SUBJ_BASE="/C=US/ST=Montana/L=Bozeman/O=wolfSSL/OU=Support"

echo "== Generating CA"
openssl req -config "$WORK/openssl.cnf" -x509 -new -newkey rsa:2048 -nodes \
    -sha256 -days "$DAYS" -extensions ca_ext \
    -subj "$SUBJ_BASE/CN=wolfSSL CRL IDP Example CA/emailAddress=info@wolfssl.com" \
    -keyout ca-key.pem -out ca-cert.pem

issue() {
    # issue <name> <CN>
    name=$1; cn=$2
    echo "== Generating $name"
    openssl req -config "$WORK/openssl.cnf" -new -newkey rsa:2048 -nodes \
        -sha256 -subj "$SUBJ_BASE/CN=$cn/emailAddress=info@wolfssl.com" \
        -keyout "$name-key.pem" -out "$WORK/$name.csr"
    openssl ca -config "$WORK/openssl.cnf" -batch -notext \
        -keyfile ca-key.pem -cert ca-cert.pem -extensions server_ext \
        -in "$WORK/$name.csr" -out "$name-cert.pem"
}

issue server         "www.wolfssl.com"
issue server-revoked "revoked.wolfssl.com"

echo "== Revoking server-revoked-cert.pem"
openssl ca -config "$WORK/openssl.cnf" -keyfile ca-key.pem -cert ca-cert.pem \
    -revoke server-revoked-cert.pem -crl_reason keyCompromise

echo "== Generating CRL with Issuing Distribution Point"
openssl ca -config "$WORK/openssl.cnf" -keyfile ca-key.pem -cert ca-cert.pem \
    -gencrl -out crl-idp.pem

echo "== Verifying"
openssl verify -CAfile ca-cert.pem server-cert.pem server-revoked-cert.pem
openssl crl -in crl-idp.pem -CAfile ca-cert.pem -noout
openssl crl -in crl-idp.pem -noout -text | sed -n '/CRL extensions/,/Revoked Certificates/p'
