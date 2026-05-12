from typing import Annotated
import typer
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from pathlib import Path


def generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def save_key(key, path: str):
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

def save_cert(cert, path: str):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def command(
    prefix: Annotated[
        str,
        typer.Option("--prefix", help="Prefix for generated files"),
    ] = "",
    ca_name: Annotated[
        str,
        typer.Option("--ca-name", help="Name"),
    ] = "MA",
    client_name: Annotated[
        str,
        typer.Option("--client-name", help="Name of the client"),
    ] = "external-client",
    server_name: Annotated[
        str,
        typer.Option("--server-name", help="IP or hostname of the server"),
    ] = "127.0.0.1",

):

    # File names
    ca_key_file, ca_crt_file = f"{prefix}ca.key", f"{prefix}ca.crt"
    server_key_file, server_crt_file, server_pem_file = f"{prefix}server.key", f"{prefix}server.crt", f"{prefix}server.pem"
    client_key_file, client_crt_file = f"{prefix}client.key", f"{prefix}client.crt"

    typer.echo(f"Generating compliant mTLS certificates with prefix: '{prefix}'")

    # 1. Create CA
    ca_key = generate_key()
    save_key(ca_key, ca_key_file)
    ca_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ca_name)])
    
    # IMPORTANT: The CA must have BasicConstraints(ca=True)
    ca_cert = x509.CertificateBuilder().subject_name(ca_subj).issuer_name(ca_subj).public_key(
        ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.utcnow()).not_valid_after(datetime.utcnow() + timedelta(days=365)).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(ca_key, hashes.SHA256())
    save_cert(ca_cert, ca_crt_file)

    # 2. Create Server Certificate
    server_key = generate_key()
    save_key(server_key, server_key_file)
    server_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, server_name)])
    
    server_cert = x509.CertificateBuilder().subject_name(server_subj).issuer_name(ca_subj).public_key(
        server_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.utcnow()).not_valid_after(datetime.utcnow() + timedelta(days=365)).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).sign(ca_key, hashes.SHA256())
    save_cert(server_cert, server_crt_file)
    
    # Combine for socat with explicit newline
    with open(server_pem_file, "wb") as pem_file:
        with open(server_crt_file, "rb") as crt, open(server_key_file, "rb") as key:
            pem_file.write(crt.read() + b"\n" + key.read())

    # 3. Create Client Certificate
    client_key = generate_key()
    save_key(client_key, client_key_file)
    client_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, client_name)])
    
    client_cert = x509.CertificateBuilder().subject_name(client_subj).issuer_name(ca_subj).public_key(
        client_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.utcnow()).not_valid_after(datetime.utcnow() + timedelta(days=365)).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).sign(ca_key, hashes.SHA256())
    save_cert(client_cert, client_crt_file)

    typer.echo("✅ Compliant Certificates generated.")


def cli():
    typer.run(command)

