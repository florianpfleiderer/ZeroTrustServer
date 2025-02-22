import logging
import subprocess
from pathlib import Path
from typing import NoReturn

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def rotate_server_certificate() -> NoReturn:
    cert_path = Path("data/server/certificates").absolute()
    ca_path = Path("data/certificates").absolute()
    config_file = Path.joinpath(cert_path, "server_cert_config.cnf")
    server_key = Path.joinpath(cert_path, "server_key.pem")
    server_cert = Path.joinpath(cert_path, "server_cert.pem")
    server_csr = Path.joinpath(cert_path, "server.csr.pem")
    ca_cert = Path.joinpath(ca_path, "ca_certificate.pem")
    ca_key = Path.joinpath(ca_path, "ca_private_key.pem")

    try:
        logger.info("Generating new server key...")
        subprocess.run(
            ["/usr/bin/openssl", "genrsa", "-out", server_key, "2048"],
            check=True,
        )

        logger.info("Generating new server CSR...")
        subprocess.run(
            [
                "/usr/bin/openssl",
                "req",
                "-new",
                "-key",
                server_key,
                "-out",
                server_csr,
                "-config",
                config_file,
            ],
            check=True,
        )

        logger.info("Signing new server certificate with CA...")
        subprocess.run(
            [
                "/usr/bin/openssl",
                "x509",
                "-req",
                "-in",
                server_csr,
                "-CA",
                ca_cert,
                "-CAkey",
                ca_key,
                "-CAcreateserial",
                "-out",
                server_cert,
                "-days",
                "3650",
                "-sha256",
                "-extfile",
                config_file,
                "-extensions",
                "req_ext",
            ],
            check=True,
        )

        logger.info("Cleaning up CSR and serial files...")
        Path.unlink(server_csr)
        serial_file = Path.joinpath(ca_path, "ca.srl")
        if Path.exists(serial_file):
            serial_file.unlink()

        logger.info("Certificate rotation completed successfully.")

    except subprocess.CalledProcessError as e:
        logger.error("An error occurred during certificate rotation: %s", e)
    except Exception as e:
        logger.error("Unexpected error: %s", e)


if __name__ == "__main__":
    rotate_server_certificate()
