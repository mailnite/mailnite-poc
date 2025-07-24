from typing import Optional
import click
import base64
import os
import json
import re
from datetime import datetime
import dns.resolver
import hashlib

import email
from email import policy
from email.message import EmailMessage
import mimetypes

from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.ecdh import ECDH
from ecdsa.util import sigencode_string
from ecdsa.util import sigdecode_string

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import rlp


# Automatically adds this prefix to subject
SUBJECT_PREFIX = "[Enc]"

DEFAULT_BODY = """This email was encrypted by Mailnite.

To decrypt, visit: https://mailnite.com/decrypt
and upload attachment: mailnite.enc.

If you are a developer, see: https://github.com/mailnite/concept"""


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
@click.option("--sender-priv", type=click.Path(exists=True), help="Sender signing private key (secp256k1). Optional.")
@click.option("--sender-alg", default="secp256k1", show_default=True, help="Sender signing key algorithm to embed.")
def encrypt(email_file, sender_priv, sender_alg):
    """Encrypt the email for each recipient, outputting ECIES .eml files with an RLP envelope as attachment."""
    with open(email_file, "r") as f:
        email_txt = f.read()

    msg = email.message_from_string(email_txt, policy=policy.default)

    if msg.get('X-Mailnite-Encrypted', '').lower() == "yes":
        click.echo("This message already encrypted by Mailnite.")
        return

    subject = msg.get('Subject', '')
    recipients = msg.get('To', '').split(',')
    recipients = [r.strip() for r in recipients if r.strip()]
    if not recipients:
        click.echo("No recipients found in 'To:' header.")
        return

    # Serialize the entire original email (headers + all MIME parts)
    original_bytes = msg.as_bytes(policy=policy.default)

    # If we will sign, load sender key once
    sender_sk = None
    sender_pk_bytes = b""
    sender_sig_bytes = b""
    sender_alg_bytes = b""

    if sender_priv:
        with open(sender_priv, "rb") as f:
            sender_sk_bytes = f.read()
        sender_sk = SigningKey.from_string(sender_sk_bytes, curve=SECP256k1)
        sender_vk = sender_sk.get_verifying_key()
        sender_pk_bytes = compress_pubkey(sender_vk)           # compressed 33-byte SEC1
        sender_alg_bytes = sender_alg.encode()

    for rcpt in recipients:
        rec = lookup_pubkey(rcpt)
        if rec is None:
            click.echo(f"Warning: No DNS public key record found for {rcpt}. Skipping this recipient.")
            continue

        alg = rec.get("alg", "secp256k1")
        if alg != "secp256k1":
            click.echo(f"Warning: Unsupported ECIES algorithm '{alg}' for {rcpt}. Skipping.")
            continue

        enc = rec.get("enc", "aes256gcm")
        if enc != "aes256gcm":
            click.echo(f"Warning: Unsupported encryption algorithm '{enc}' for {rcpt}. Skipping.")
            continue

        usr = rec.get("usr") or ""
        key_id = rec.get("id") or ""
        iss = rec.get("iss") or ""

        try:
            recipient_pk_bytes = base64.urlsafe_b64decode(rec['pk'] + '=' * (-len(rec['pk']) % 4))

            # Ephemeral key for ECDH (ECIES)
            eph_sk = SigningKey.generate(curve=SECP256k1)
            eph_pk = eph_sk.get_verifying_key()

            from ecdsa.ecdh import ECDH
            ecdh = ECDH(curve=SECP256k1, private_key=eph_sk)
            ecdh.load_received_public_key_bytes(recipient_pk_bytes)
            shared_secret = ecdh.generate_sharedsecret_bytes()

            aes_key = hkdf(shared_secret)
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)
            ct = aesgcm.encrypt(nonce, original_bytes, None)

            # ---- Build base envelope (indexes 0..8) ----
            envelope_base = [
                1,                              # version            (0)
                b"secp256k1",                   # alg                (1)
                compress_pubkey(eph_pk),        # eph_pk             (2)
                b"aes256gcm",                   # enc                (3)
                nonce,                          # nonce              (4)
                ct,                             # ct                 (5)
                usr.encode(),                   # usr                (6)
                key_id.encode(),                # id                 (7)
                iss.encode(),                   # iss                (8)
            ]

            # ---- Optional sender fields ----
            sender_sig_bytes = b""
            if sender_sk:
                # Sign the RLP of the base envelope
                to_sign = rlp.encode(envelope_base)
                # Deterministic RFC6979 signature over SHA256 hash (or raw); pick one and stick with it.
                digest = hashlib.sha256(to_sign).digest()

               # 64-byte (r||s) signature:
                sender_sig_bytes = sender_sk.sign_deterministic(
                    digest,
                    hashfunc=hashlib.sha256,
                    sigencode=sigencode_string  # returns raw 64 bytes
                )

                if len(sender_sig_bytes) != 64:
                    raise ValueError("signature must be 64 bytes (r||s).")

            # Compose final envelope (fixed order!)
            envelope = envelope_base + [
                sender_alg_bytes if sender_sk else b"",  # sender_alg        (9)
                sender_pk_bytes if sender_sk else b"",   # sender_pk         (10)
                sender_sig_bytes if sender_sk else b"",  # sender_sig        (11)
            ]

            rlp_bytes = rlp.encode(envelope)

            # Subject prefix
            subject_with_enc = subject if subject.strip().startswith(SUBJECT_PREFIX) else f"{SUBJECT_PREFIX} {subject}"

            # Build email with instructions and RLP attachment
            outmsg = EmailMessage()
            outmsg['To'] = rcpt
            outmsg['Subject'] = subject_with_enc
            outmsg['X-Mailnite-Encrypted'] = "yes"
            outmsg.set_content(DEFAULT_BODY)
            outmsg.add_attachment(
                rlp_bytes,
                maintype="application",
                subtype="x-mailnite-enc",
                filename="mailnite.enc"
            )
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
@click.option("--key", "priv", required=True, help="Recipient's private key file")
@click.option("--in", "infile", required=True, type=click.Path(exists=True), help="Input encrypted .eml file")
@click.option("--out", required=True, help="Output file for decrypted plaintext email")
def decrypt(priv, infile, out):
    """
    Decrypt an ECIES-encrypted .eml message file (with RLP attachment)
    and write the original (fully restored) email to file,
    with SUBJECT_PREFIX removed from Subject if present.
    Also verifies optional sender signature if present.
    """

    # ---- Load recipient private key ----
    with open(priv, "rb") as f:
        sk_bytes = f.read()
    sk = SigningKey.from_string(sk_bytes, curve=SECP256k1)

    # ---- Load the encrypted email ----
    with open(infile, "r") as f:
        raw_email = f.read()

    msg = email.message_from_string(raw_email, policy=policy.default)

    if msg.get('X-Mailnite-Encrypted', '').lower() != "yes":
        click.echo("Error: This message does not appear to be Mailnite-encrypted.")
        return

    # ---- Extract the RLP attachment (first attachment, or prefer application/x-mailnite-enc) ----
    rlp_bytes = None
    chosen_part = None
    for part in msg.iter_attachments():
        payload = part.get_content()
        if isinstance(payload, str):
            payload = payload.encode('latin1')
        # Prefer our custom content-type, but accept first if not set
        if part.get_content_type() == 'application/x-mailnite-enc' or chosen_part is None:
            rlp_bytes = payload
            chosen_part = part
            if part.get_content_type() == 'application/x-mailnite-enc':
                break  # good enough, stop here

    if not rlp_bytes:
        click.echo("Error: No RLP envelope attachment found!")
        return

    # ---- Decode RLP ----
    try:
        decoded = rlp.decode(rlp_bytes)
    except rlp.DecodingError as e:
        click.echo(f"Error: Invalid RLP envelope ({e})")
        return

    # Basic length check (we need at least up to ct)
    if len(decoded) < 9:  # up to 'iss' is index 8
        click.echo("Error: Envelope too short; missing required fields.")
        return

    # Helper to get int regardless of rlp encoding
    def to_int(x):
        return x if isinstance(x, int) else int.from_bytes(x, 'big') if isinstance(x, (bytes, bytearray)) else int(x)

    # ---- Fixed-order extraction ----
    # 0..8 are required in your current schema
    version      = to_int(decoded[0])
    alg_bytes    = decoded[1]
    eph_pk_bytes = decoded[2]
    enc_bytes    = decoded[3]
    nonce        = decoded[4]
    ct           = decoded[5]
    usr_bytes    = decoded[6]
    id_bytes     = decoded[7]
    iss_bytes    = decoded[8]

    # Optional indices (might be missing or empty)
    sender_alg_bytes = decoded[9]  if len(decoded) > 9  else b""
    sender_pk_bytes  = decoded[10] if len(decoded) > 10 else b""
    sender_sig_bytes = decoded[11] if len(decoded) > 11 else b""

    # ---- Validate required fields ----
    if version != 1:
        click.echo(f"Error: Unsupported envelope version '{version}'!")
        return

    alg = alg_bytes.decode(errors='replace')
    if alg != "secp256k1":
        click.echo(f"Error: Unsupported ECIES algorithm '{alg}'!")
        return

    enc = enc_bytes.decode(errors='replace')
    if enc != "aes256gcm":
        click.echo(f"Error: Unsupported encryption algorithm '{enc}'!")
        return

    # ---- ECIES decryption ----
    ecdh = ECDH(curve=SECP256k1, private_key=sk)
    ecdh.load_received_public_key_bytes(eph_pk_bytes)
    shared_secret = ecdh.generate_sharedsecret_bytes()
    aes_key = hkdf(shared_secret)
    aesgcm = AESGCM(aes_key)

    try:
        pt = aesgcm.decrypt(nonce, ct, None)
    except Exception as e:
        click.echo(f"Error: Decryption failed ({e})")
        return

    # ---- Optional sender signature verification ----
    # Only verify if both sender_pk and sender_sig are present (non-empty)
    if sender_pk_bytes and sender_sig_bytes:
        sender_alg = sender_alg_bytes.decode(errors='replace') if sender_alg_bytes else "secp256k1"
        if sender_alg != "secp256k1":
            click.echo(f"Warning: Sender algorithm '{sender_alg}' not supported. Skipping signature verification.")
        else:
            try:
                # Re-encode ONLY the fields that were signed (0..8)
                base_envelope = decoded[:9]
                to_verify = rlp.encode(base_envelope)
                digest = hashlib.sha256(to_verify).digest()

                vk = VerifyingKey.from_string(sender_pk_bytes, curve=SECP256k1)
                # 64-byte raw (r||s) signature
                if len(sender_sig_bytes) != 64:
                    raise ValueError("sender_sig is not 64 bytes (r||s).")

                vk.verify(sender_sig_bytes, digest,
                          hashfunc=hashlib.sha256,
                          sigdecode=sigdecode_string)
                click.echo("Sender signature verified successfully.")
            except Exception as e:
                click.echo(f"Warning: Sender signature verification failed ({e}).")

    # ---- Restore original email ----
    orig_msg = email.message_from_bytes(pt, policy=policy.default)
    subject = orig_msg.get('Subject', '')

    if subject.startswith(SUBJECT_PREFIX):
        new_subject = subject[len(SUBJECT_PREFIX):].lstrip()
        orig_msg.replace_header('Subject', new_subject)

    # Clear marker header if you don't want to keep it
    if orig_msg.get('X-Mailnite-Encrypted'):
        del orig_msg['X-Mailnite-Encrypted']

    # ---- Save the result ----
    with open(out, "w") as f:
        f.write(orig_msg.as_string(policy=policy.default))

    click.echo(f"Decrypted email written to {out}")



if __name__ == "__main__":
    cli()
