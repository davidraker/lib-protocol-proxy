"""TLS between a manager and a remote proxy, with the manager as an ephemeral certificate authority.

A manager that launches a proxy with ``tls=True`` creates (once) a CA key and certificate of its own, issues itself a
server certificate, and issues the proxy a certificate naming the proxy's id; it writes ``{"ca", "cert", "key"}`` as
one JSON line to the proxy's stdin after the tokens (and the AEAD key, if any). Both ends then require the other's
certificate to chain to that CA: the proxy verifies the manager's, the manager verifies the proxy's. Nothing touches
the disk except for the moment ``ssl`` needs the certificate chain in a file (a private temporary directory, removed
at once). Hostnames are not checked: the CA is private to one manager and the certificate's common name carries the
peer's id, which is what the connector verifies."""
import datetime
import json
import os
import ssl
import tempfile
from dataclasses import dataclass
from typing import Iterable
from uuid import UUID


@dataclass
class TlsMaterial:
    ca: str         # PEM certificate of the issuing CA
    cert: str       # PEM certificate of this end
    key: str        # PEM private key of this end

    def to_line(self) -> bytes:
        return (json.dumps({'ca': self.ca, 'cert': self.cert, 'key': self.key}) + '\n').encode('utf8')

    @classmethod
    def from_line(cls, line: bytes | str) -> 'TlsMaterial':
        fields = json.loads(line.decode('utf8') if isinstance(line, bytes) else line)
        return cls(ca=fields['ca'], cert=fields['cert'], key=fields['key'])


def _x509():
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
    except ImportError as e:    # pragma: no cover - cryptography is a dependency
        raise RuntimeError('TLS between proxies needs the "cryptography" package.') from e
    return x509, hashes, serialization, ec, NameOID


def _pem_key(key) -> str:
    _, _, serialization, _, _ = _x509()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode('ascii')


class Authority:
    """An in-memory CA, one per manager, issuing short certificates to the manager itself and to its proxies."""
    LIFETIME = datetime.timedelta(days=366)

    def __init__(self, name: str = 'protocol-proxy manager'):
        x509, hashes, serialization, ec, NameOID = _x509()
        self._key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        now = datetime.datetime.now(datetime.timezone.utc)
        self._cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                      .public_key(self._key.public_key()).serial_number(x509.random_serial_number())
                      .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + self.LIFETIME)
                      .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                      .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                                   content_commitment=False, key_encipherment=False,
                                                   data_encipherment=False, key_agreement=False, encipher_only=False,
                                                   decipher_only=False), critical=True)
                      .sign(self._key, hashes.SHA256()))
        self.ca_pem: str = self._cert.public_bytes(serialization.Encoding.PEM).decode('ascii')

    def issue(self, common_name: str, ip_addresses: Iterable[str] = ()) -> TlsMaterial:
        """A certificate and key for one end (``common_name`` is the peer's id), usable as server and client."""
        x509, hashes, serialization, ec, NameOID = _x509()
        import ipaddress
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
                   .issuer_name(self._cert.subject).public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + self.LIFETIME)
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                                                         x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False))
        names = [x509.DNSName(common_name)]
        for ip in ip_addresses:
            try:
                names.append(x509.IPAddress(ipaddress.ip_address(ip)))
            except ValueError:
                names.append(x509.DNSName(ip))
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
        cert = builder.sign(self._key, hashes.SHA256())
        return TlsMaterial(ca=self.ca_pem, cert=cert.public_bytes(serialization.Encoding.PEM).decode('ascii'),
                           key=_pem_key(key))


def _load_chain(context: ssl.SSLContext, material: TlsMaterial):
    """ssl wants the chain in files: write them to a private temporary directory for the duration of the load."""
    with tempfile.TemporaryDirectory(prefix='protocol-proxy-tls-') as directory:
        cert_path, key_path = os.path.join(directory, 'cert.pem'), os.path.join(directory, 'key.pem')
        for path, text in ((cert_path, material.cert), (key_path, material.key)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(text)
        context.load_cert_chain(cert_path, key_path)


def _context(purpose, material: TlsMaterial, context_class=ssl.SSLContext) -> ssl.SSLContext:
    context = context_class(ssl.PROTOCOL_TLS_SERVER if purpose == 'server' else ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cadata=material.ca)
    _load_chain(context, material)
    return context


def server_context(material: TlsMaterial, context_class=ssl.SSLContext) -> ssl.SSLContext:
    """For accepted connections: present our certificate, require the client's, both chaining to the CA."""
    return _context('server', material, context_class)


def client_context(material: TlsMaterial, context_class=ssl.SSLContext) -> ssl.SSLContext:
    """For dialled connections: present our certificate, require the server's, both chaining to the CA."""
    return _context('client', material, context_class)


def peer_common_name(sock) -> str | None:
    """The common name of the certificate the other end presented (its proxy id), or None without TLS."""
    try:
        cert = sock.getpeercert()
    except (AttributeError, ValueError, ssl.SSLError):
        return None
    for rdn in (cert or {}).get('subject', ()):
        for key, value in rdn:
            if key == 'commonName':
                return value
    return None


def is_tls_client_hello(first_byte: bytes) -> bool:
    """A TLS record starts with content type 0x16 (handshake); a protocol-proxy frame starts with a version word
    whose first byte is 0x00. The manager's listener tells the two apart by peeking one byte."""
    return first_byte[:1] == b'\x16'


def expect_proxy_id(sock, proxy_id: UUID | None) -> bool:
    """Whether the certificate at the other end names ``proxy_id`` (True when no id is expected)."""
    if proxy_id is None:
        return True
    return peer_common_name(sock) == proxy_id.hex
