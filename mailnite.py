from typing import Optional
import click
import base64
import os
import json
import re
from datetime import datetime
import dns.resolver

import email
from email import policy
from email.message import EmailMessage
import mimetypes

from ecdsa import SigningKey, SECP256k1
from ecdsa.ecdh import ECDH
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Automatically adds this prefix to subject
SUBJECT_PREFIX = "[Enc]"

# Generate a signing key using the SECP256k1 curve
#eph_sk = SigningKey.generate(curve=SECP256k1)

def b64u(x):
    return base64.urlsafe_b64encode(x).decode().rstrip("=")

def b64u_decode(x):
    """Accepts str or bytes, returns bytes."""
    if isinstance(x, bytes):
        x = x.decode()  # convert bytes to str
    x = x.strip()
    pad = '=' * (-len(x) % 4)
    return base64.urlsafe_b64decode(x + pad)

def compress_pubkey(pk):
    return pk.to_string("compressed")

def hkdf(shared_secret, salt=b"mailnite", length=32):
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=salt, info=b"mailnite"
    ).derive(shared_secret)

def extract_recipients(email_txt):
    # Extract all emails from 'To:' header (RFC822, comma-separated)
    match = re.search(r'^To:\s*(.+)$', email_txt, re.MULTILINE | re.IGNORECASE)
    if not match:
        return []
    recipients = [r.strip() for r in match.group(1).split(',') if r.strip()]
    return recipients

@click.group()
def cli():
    """Mailnite DNS PKI Email PoC CLI"""
    pass

@cli.command()
@click.option("--out", help="Private key file to save")
@click.option("--usr", help="External user field (usr=...)")
@click.option("--dns-name", required=True, help="alice.example.com")
def genkey(out, usr, dns_name):
    """Generate a keypair and DNS TXT record."""
    sk = SigningKey.generate(curve=SECP256k1)
    pk = sk.get_verifying_key()
    sk_bytes = sk.to_string()
    pk_bytes = compress_pubkey(pk)
    pk_b64u = b64u(pk_bytes)
    if not out:
        out = f"{dns_name}.key"
    with open(out, "wb") as f:
        f.write(sk_bytes)
    click.echo(f"Private key saved to: {out}")

    # Get current UTC date
    current_date = datetime.utcnow().date()

    # Add one year
    exp_date = current_date.replace(year=current_date.year + 1)

    txt = (
        f"v=1;pk={pk_b64u};alg=secp256k1;exp={exp_date};usr={usr or ''};pv=mailnite;"
    )
    click.echo("\nDNS TXT Record:\n")
    click.echo(txt)
    click.echo(f"\nPublish to: _mailpubkey.{dns_name}. IN TXT ...")

def parse_txt(txt):
    fields = {}
    for part in txt.split(';'):
        if '=' in part:
            k, v = part.split('=', 1)
            fields[k.strip()] = v.strip()
    return fields

def is_valid_subdomain(key: str) -> bool:
    # RFC1035: labels only allow a-z, 0-9, and '-' (not start/end with '-')
    return bool(re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$", key))

def lookup_pubkey(email_addr: str) -> Optional[dict]:
    """
    Look up the mailnite DNS TXT record for the recipient.
    Returns the parsed dict if found, otherwise None.
    """
    if '@' not in email_addr:
        return None
    local, domain = email_addr.split('@', 1)
    # Extract key: try after '+' or full local part if it's valid
    key = None
    if '+' in local:
        key = local.split('+', 1)[1]
    elif is_valid_subdomain(local):
        key = local
    if not key:
        return None

    # Compose DNS query
    name = f"_mailpubkey.{key}.{domain}"
    try:
        txts = dns.resolver.resolve(name, "TXT")
        for r in txts:
            txtval = ''.join(s.decode() if isinstance(s, bytes) else s for s in r.strings)
            if 'pk=' in txtval:
                return parse_txt(txtval)
    except Exception:
        return None
    return None

@cli.command()
@click.option("--out", required=True, help="Output plain email file")
@click.option("--recipients", required=True, help="Comma-separated recipient emails")
@click.option("--subject", required=True, help="Subject")
@click.option("--body", required=True, help="Body")
@click.option("--attachment", "attachments", multiple=True, type=click.Path(exists=True), help="Attachment file(s), can be used multiple times")
def create(out, recipients, subject, body, attachments):
    """
    Create a plaintext email file (with optional attachments) using EmailMessage.
    """
    msg = EmailMessage()
    rcpts = ', '.join([r.strip() for r in recipients.split(',') if r.strip()])
    msg['To'] = rcpts
    msg['Subject'] = subject
    msg.set_content(body)

    # Attach each file
    for fname in attachments:
        ctype, encoding = mimetypes.guess_type(fname)
        if ctype is None or encoding is not None:
            ctype = 'application/octet-stream'
        maintype, subtype = ctype.split('/', 1)
        with open(fname, 'rb') as af:
            msg.add_attachment(af.read(),
                              maintype=maintype,
                              subtype=subtype,
                              filename=os.path.basename(fname))
    with open(out, "w") as f:
        f.write(msg.as_string())
    click.echo(f"Plain email with attachments saved to {out}")


@cli.command()
@click.option("--in", "email_file", required=True, type=click.Path(exists=True), help="Plain email file")
def encrypt(email_file):
    """Encrypt the email for each recipient, outputting ECIES .eml files with encrypted attachment."""
    with open(email_file, "r") as f:
        email_txt = f.read()

    # Use default policy for proper parsing, especially for attachments
    msg = email.message_from_string(email_txt, policy=policy.default)
    subject = msg.get('Subject', '')
    recipients = msg.get('To', '').split(',')
    recipients = [r.strip() for r in recipients if r.strip()]
    if not recipients:
        click.echo("No recipients found in 'To:' header.")
        return

    # Serialize the entire original email (headers + all MIME parts)
    original_bytes = msg.as_bytes(policy=policy.default)

    for rcpt in recipients:
        rec = lookup_pubkey(rcpt)
        if rec is None:
            click.echo(f"Warning: No DNS public key record found for {rcpt}. Skipping this recipient.")
            continue
        try:
            recipient_pk_bytes = base64.urlsafe_b64decode(rec['pk'] + '=' * (-len(rec['pk']) % 4))
            # Ephemeral key for ECDH (ECIES)
            eph_sk = SigningKey.generate(curve=SECP256k1)
            eph_pk = eph_sk.get_verifying_key()
            # ECDH
            ecdh = ECDH(curve=SECP256k1, private_key=eph_sk)
            ecdh.load_received_public_key_bytes(recipient_pk_bytes)
            shared_secret = ecdh.generate_sharedsecret_bytes()
            aes_key = hkdf(shared_secret)
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)
            ct = aesgcm.encrypt(nonce, original_bytes, None)
            ciphertext_b64 = b64u(ct)

            # Automatically add [Nite] to Subject if not already present
            subject_with_enc = subject if subject.strip().startswith(SUBJECT_PREFIX) else f"{SUBJECT_PREFIX} {subject}"

            # Build new RFC822 message
            outmsg = EmailMessage()
            outmsg['To'] = rcpt
            outmsg['Subject'] = subject_with_enc
            outmsg['X-ECIES-EphemeralPK'] = b64u(compress_pubkey(eph_pk))
            outmsg['X-ECIES-Nonce'] = b64u(nonce)
            outmsg['X-ECIES-Alg'] = "ecies-aesgcm"
            outmsg['X-ECIES-Version'] = "1"

            # Human-readable body
            decrypt_url = "https://mailnite.com/decrypt"
            outmsg.set_content(
                f"This email was encrypted by Mailnite.\n\n"
                f"To decrypt, visit: {decrypt_url}\n"
                f"and upload this .eml file (with attachment: mailnite.enc).\n"
                f"\nIf you are a developer, see: https://github.com/mailnite/concept\n"
            )

            # Add ciphertext as an attachment
            outmsg.add_attachment(
                ciphertext_b64.encode(),  # bytes
                maintype="application",
                subtype="octet-stream",
                filename="mailnite.enc"
            )

            # Optionally preserve original From/Date/Cc/etc.
            for header in ['From', 'Cc', 'Date', 'Reply-To']:
                if msg.get(header):
                    outmsg[header] = msg.get(header)

            outfname = f"{email_file}.encrypted.{rcpt.replace('@','_at_')}.eml"
            with open(outfname, "w") as f:
                f.write(outmsg.as_string(policy=policy.default))
            click.echo(f"Encrypted .eml message for {rcpt} saved to {outfname}")

        except Exception as e:
            click.echo(f"Error encrypting for {rcpt}: {e}")



@cli.command()
@click.option("--priv", required=True, help="Recipient's private key file")
@click.option("--in", "infile", required=True, type=click.Path(exists=True), help="Input encrypted .eml file")
@click.option("--out", required=True, help="Output file for decrypted plaintext email")
def decrypt(priv, infile, out):
    """
    Decrypt an ECIES-encrypted .eml message file (with ciphertext as attachment)
    and write the original (fully restored) email to file.
    """
    with open(priv, "rb") as f:
        sk_bytes = f.read()
    sk = SigningKey.from_string(sk_bytes, curve=SECP256k1)

    with open(infile, "r") as f:
        raw_email = f.read()

    msg = email.message_from_string(raw_email, policy=policy.default)

    # Extract cryptographic metadata from headers
    eph_pk_b64 = msg['X-ECIES-EphemeralPK']
    nonce_b64 = msg['X-ECIES-Nonce']
    alg = msg['X-ECIES-Alg']
    version = msg['X-ECIES-Version']

    # Sanity checks
    if not all([eph_pk_b64, nonce_b64, alg, version]):
        click.echo("Missing ECIES headers, is this an encrypted message?")
        return

    # --- Find the ciphertext attachment (filename == mailnite.enc) ---
    ciphertext_b64 = None
    for part in msg.iter_attachments():
        filename = part.get_filename()
        if filename and filename.lower() == "mailnite.enc":
            ciphertext_b64 = part.get_content().strip()
            break
    if not ciphertext_b64:
        click.echo("Error: No ciphertext attachment (mailnite.enc) found!")
        return

    eph_pk_bytes = b64u_decode(eph_pk_b64)
    nonce = b64u_decode(nonce_b64)
    ct = b64u_decode(ciphertext_b64)

    # ECIES decryption
    from ecdsa.ecdh import ECDH
    ecdh = ECDH(curve=SECP256k1, private_key=sk)
    ecdh.load_received_public_key_bytes(eph_pk_bytes)
    shared_secret = ecdh.generate_sharedsecret_bytes()
    aes_key = hkdf(shared_secret)
    aesgcm = AESGCM(aes_key)
    pt = aesgcm.decrypt(nonce, ct, None)

    # The decrypted payload is the full, original email (including all attachments)
    # Write bytes (for non-UTF8 payloads, use wb if desired)
    with open(out, "wb") as f:
        f.write(pt)

    click.echo(f"Decrypted email written to {out}")



if __name__ == "__main__":
    cli()
