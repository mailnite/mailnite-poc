# mailnite-poc

Mailnite Proof of Concept


## Example

1. Create email

```
python3 mailnite.py create --out=plain.eml --recipients=alice@mailnite.com,bob@mailnite.com --subject=Test --body="Test Body" --attachment requirements.txt
```

It should create file `plain.eml`

2. Encrypt the email file

```
python3 mailnite.py encrypt --in=plain.eml
```

It would skip encryption to bob, but make encryption for alice.
Bob does not have DNS record with public key.

It would produce the file
```
plain.eml.encrypted.alice_at_mailnite.com.eml
```

4. Decrypt the email

```
python3 mailnite.py decrypt --in=plain.eml.encrypted.alice_at_mailnite.com.eml --out=plain2.eml --priv=alice.mailnite.com.key
```

You should get `plain2.eml` identical to `plain.eml`.
