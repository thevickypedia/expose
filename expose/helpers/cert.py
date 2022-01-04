import binascii
import json
from getpass import getuser
from os import rename, stat, urandom
from urllib.request import urlopen

from OpenSSL import crypto

from expose.helpers.auxiliary import sleeper

CERTIFICATE_INFO = {}


def get_public_ip() -> str:
    """Gets the public IP address from ``ipinfo.io`` or ``ip.jsontest.com``.

    Returns:
        str:
        Returns the public IP address.
    """
    if data := (json.load(urlopen('http://ipinfo.io/json')) or json.load(urlopen('http://ip.jsontest.com'))):
        CERTIFICATE_INFO.update({
            "city": data.get('city'),
            "country": data.get('country'),
            "region": data.get('region')
        })
    return data.get('ip')


def _get_serial() -> bytes:
    """Generates a serial number for the self-signed SSL.

    See Also:
        This function is not called, but it is here only as a just in case measure to insert serial number manually.

    Returns:
        bytes:
        Encoded serial number for the certificate.
    """
    serial_hex = binascii.hexlify(urandom(18)).decode().upper()
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
    return int(binascii.hexlify(urandom(byte_size)).decode().upper(), int_size)


def generate_cert(common_name: str,
                  email_address: str = None,
                  country_name: str = CERTIFICATE_INFO.get('country', 'US'),
                  locality_name: str = CERTIFICATE_INFO.get('city', 'New York'),
                  state_or_province_name: str = CERTIFICATE_INFO.get('region', 'New York'),
                  organization_name: str = None,
                  organization_unit_name: str = "Information Technology",
                  validity_start_in_seconds: int = 0,
                  validity_end_in_seconds: int = 10 * 365 * 24 * 60 * 60,
                  key_file: str = "key.key",
                  cert_file: str = "cert.crt") -> bool:
    """Creates a private/self-signed certificate.

    Args:
        common_name: DNS name of the origin.
        email_address: Contact email address for the cert. Defaults to ``USER@expose-localhost.com``
        country_name: Name of the country. Defaults to ``US``
        locality_name: Name of the city. Defaults to ``New York``
        state_or_province_name: Name of the state/province. Defaults to ``New York``
        organization_name: Name of the organization. Defaults to ``common_name``
        organization_unit_name: Name of the organization unit. Defaults to ``Information Technology``
        # serial_number: Unique identifier assigned by the CA which issued the certificate. Defaults to ``0``
        validity_start_in_seconds: From when the cert validity begins. Defaults to ``0``.
        validity_end_in_seconds: Expiration duration of the cert. Defaults to ``10 years``
        key_file: Name of the key file.
        cert_file: Name of the certificate.

    Returns:
        bool:
        Boolean flag to indicate whether ``cert.pem`` and ``key.pem`` files are empty.

    See Also:
        Use ``openssl x509 -inform pem -in cert.crt -noout -text`` to look at the generated cert using openssl.
    """
    organization_name = organization_name or common_name[0].upper() + common_name.partition('.')[0][1:]

    # Creates a key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 4096)

    # Creates a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = country_name
    cert.get_subject().ST = state_or_province_name
    cert.get_subject().L = locality_name
    cert.get_subject().O = organization_name  # noqa: E741
    cert.get_subject().OU = organization_unit_name
    cert.get_subject().CN = common_name
    cert.get_subject().emailAddress = email_address or f"{getuser()}@expose-localhost.com"
    cert.set_serial_number(serial=cert.get_serial_number() or _generate_serial_hash())
    cert.gmtime_adj_notBefore(amount=validity_start_in_seconds)
    cert.gmtime_adj_notAfter(amount=validity_end_in_seconds)
    cert.set_issuer(issuer=cert.get_subject())
    cert.set_pubkey(pkey=key)
    # noinspection PyTypeChecker
    cert.sign(pkey=key, digest='sha512')

    # Writes the cert file into specified names
    with open(cert_file, "w") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(key_file, "w") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode("utf-8"))

    cert_file_new, key_file_new = f"{cert_file.replace('.crt', '.pem')}", f"{key_file.replace('.key', '.pem')}"

    rename(src=cert_file, dst=cert_file_new)
    rename(src=key_file, dst=key_file_new)

    if stat(cert_file_new).st_size != 0 and stat(key_file_new).st_size != 0:
        sleeper(sleep_time=1)
        return True
