import binascii
import os
from typing import List

from OpenSSL import crypto

from expose.models.auxiliary import IP_INFO
from expose.models.config import env


def _get_serial() -> bytes:
    """Generates a serial number for the self-signed SSL.

    See Also:
        - This function is not called, but it is here only as a just in case measure to insert serial number manually.
        - Serial Number is a unique identifier assigned by the CA which issued the certificate.

    Returns:
        bytes:
        Encoded serial number for the certificate.
    """
    serial_hex = binascii.hexlify(os.urandom(18)).decode().upper()
    return " ".join(serial_hex[i:i + 2] for i in range(0, len(serial_hex), 2)).encode('UTF-8')


def _generate_serial_hash(byte_size: int = 18, int_size: int = 36) -> int:
    """Generates a hashed serial number.

    Args:
        byte_size: Size of the bytes object containing random bytes.
        int_size: Size of the base int.

    Returns:
        int:
        Returns the hashed serial.
    """
    return int(binascii.hexlify(os.urandom(byte_size)).decode().upper(), int_size)


def generate_cert(common_name: str, san_list: List[str],
                  country_name: str = IP_INFO.get('country', 'US'),
                  locality_name: str = IP_INFO.get('city', 'New York'),
                  state_or_province_name: str = IP_INFO.get('region', 'New York'),
                  organization_unit_name: str = "Information Technology",
                  key_file: str = env.key_file,
                  cert_file: str = env.cert_file,
                  key_size: int = 2048) -> None:
    """Creates a self-signed certificate.

    Args:
        common_name: DNS name of the origin.
        country_name: Name of the country. Defaults to ``US``
        locality_name: Name of the city. Defaults to ``New York``
        state_or_province_name: Name of the state/province. Defaults to ``New York``
        organization_unit_name: Name of the organization unit. Defaults to ``Information Technology``
        key_file: Name of the key file.
        cert_file: Name of the certificate.
        key_size: Size of the public key. Defaults to 2048.
        san_list: List of Subject Alternative Names (SANs). Defaults to None.

    See Also:
        Use ``openssl x509 -inform pem -in public.pem -noout -text`` to look at the generated cert using openssl.
    """
    if key_size not in (2048, 4096):
        raise ValueError('Certificate key size should be either 2048 or 4096.')
    signature_bytes = 256 if key_size == 2048 else 512  # Refer: https://crypto.stackexchange.com/a/3508

    # Creates a key pair
    key = crypto.PKey()
    key.generate_key(type=crypto.TYPE_RSA, bits=key_size)

    # Creates a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = country_name
    cert.get_subject().ST = state_or_province_name
    cert.get_subject().L = locality_name
    cert.get_subject().O = env.organization or common_name[0].upper() + common_name.partition('.')[0][1:]  # noqa: E741
    cert.get_subject().OU = organization_unit_name
    cert.get_subject().CN = common_name
    cert.get_subject().emailAddress = env.email_address
    cert.set_serial_number(serial=cert.get_serial_number() or _generate_serial_hash())
    cert.gmtime_adj_notBefore(amount=0)
    cert.gmtime_adj_notAfter(amount=365 * 24 * 60 * 60)

    cert.add_extensions([
        crypto.X509Extension(
            b"keyUsage", False,
            b"digitalSignature, nonRepudiation, keyEncipherment"),
        crypto.X509Extension(
            b"basicConstraints", False, b"CA:FALSE"),
        crypto.X509Extension(
            b"extendedKeyUsage", True, b"serverAuth"),
        crypto.X509Extension(
            b"subjectAltName", False, ",".join(san_list).encode('utf-8'))
    ])

    cert.set_issuer(issuer=cert.get_subject())
    cert.set_pubkey(pkey=key)
    # noinspection PyTypeChecker
    cert.sign(pkey=key, digest=f'sha{signature_bytes}')

    # Writes the cert file into specified names
    with open(cert_file, "w") as f:
        f.write(crypto.dump_certificate(type=crypto.FILETYPE_PEM, cert=cert).decode("utf-8"))
        f.flush()
    with open(key_file, "w") as f:
        f.write(crypto.dump_privatekey(type=crypto.FILETYPE_PEM, pkey=key).decode("utf-8"))
        f.flush()
