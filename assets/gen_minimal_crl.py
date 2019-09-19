"""Generates a DER encoded CRL with a single revoked serial and no extensions.
This exercises the optional-parsing functionalitites of `parse_crl_der`.
"""

import os.path as osp

from OpenSSL import crypto


def main():
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 2048)

    ca = crypto.X509()
    ca.set_version(2)
    ca.set_serial_number(1)
    ca.get_subject().CN = 'snakeoil'
    ca.set_notBefore(b'19700101000000Z')
    ca.set_notAfter(b'20991231235959Z')
    ca.set_issuer(ca.get_subject())
    ca.set_pubkey(pkey)
    ca.sign(pkey, 'sha256')

    revoked = crypto.Revoked()
    revoked.set_serial(b'2a')
    revoked.set_rev_date(b'19700101000000Z')
    revoked.set_reason(None)

    crl = crypto.CRL()
    crl.set_lastUpdate(b'19700101000000Z')
    crl.set_nextUpdate(b'20990101000000Z')
    crl.add_revoked(revoked)
    crl.sign(issuer_cert=ca, issuer_key=pkey, digest=b'sha256')

    with open(osp.join(osp.dirname(__file__), 'minimal.crl'), 'wb') as f_crl:
        f_crl.write(crypto.dump_crl(crypto.FILETYPE_ASN1, crl))


if __name__ == '__main__':
    main()
