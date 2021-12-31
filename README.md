[![PyPI](https://img.shields.io/pypi/v/pyvaulty.svg)](https://pypi.python.org/pypi/pyvaulty/)
![Python](https://img.shields.io/badge/python-≥&nbsp;3.6-orange)
![Size](https://img.shields.io/github/languages/code-size/cmason3/vaulty?label=size)

## Vaulty
### Encrypt/Decrypt with ChaCha20-Poly1305

Vaulty is an extremely lightweight encryption/decryption tool which uses ChaCha20-Poly1305 to provide 256-bit authenticated symmetric encryption (AEAD) using Scrypt as the password based key derivation function as well as supporting public key (asymmetric) encryption via ECDH (Elliptic Curve Diffie-Hellman) and X448. It can be used to encrypt/decrypt files, or `stdin` if you don't specify any files.

If encrypting `stdin` then the output will be Base64 encoded whereas if encrypting a file then it won't and it will have a `.vlt` extension added to indicate it has been encrypted.

It relies on the [cryptography](https://pypi.org/project/cryptography/) Python module to provide the routines for ChaCha20-Poly1305, Scrypt and ECDH with X448.
 
#### Installation

```
python3 -m pip install --upgrade --user pyvaulty
```

#### Vaulty Usage

```
vaulty ...
  keygen
  keyinfo <public key>
  encrypt [-k <public key>] [file1[ file2[ ...]]]
  decrypt [-k <private key>] [file1[ file2[ ...]]]
  sha256 [file1[ file2[ ...]]]
```

#### Example Usage - Symmetric Encryption

```
echo "Hello World" | vaulty encrypt
$VAULTY;AY3eJ98NF6WFDMAP62lRdl58A2db5XJ2gNvKd0nmDs5ZrmNlJ8TSURpxc3bNF1iGw77dHA==

echo "$VAULTY;..." | vaulty decrypt
Hello World
```

```python
import getpass, vaulty

v = vaulty.Vaulty()

password = getpass.getpass('Vaulty Password: ').encode('utf-8')
ciphertext = v.encrypt('Hello World'.encode('utf-8'), password)

plaintext = v.decrypt(ciphertext, password).decode('utf-8')
if plaintext is None:
  print('error: invalid password or data not encrypted', file=sys.stderr)
```

#### Example Usage - Public Key (Asymmetric) Encryption

```
vaulty keygen

echo "Hello World" | vaulty encrypt -k ~/.vaulty/vaulty.pub
$VAULTY;QfIfowgIxGIpxD3wpk/p5/6wTHvxalHKqhodSuorNPvuvhmHqsybZ822x6nyPWdNsZnDVFKi
4nkSBTPnQS17Hexn1Fj85vyrARMc5oQ3ySLpB8QWGQJdjaYFeVyfRh2WwMZqkyAki09U2h7MMFBAbAc=

echo "$VAULTY;..." | vaulty decrypt -k ~/.vaulty/vaulty.key
Hello World
```

```python
import vaulty

v = vaulty.Vaulty()

private, public = v.generate_keypair()

ciphertext = v.encrypt_ecc('Hello World'.encode('utf-8'), public)

plaintext = v.decrypt_ecc(ciphertext, private).decode('utf-8')
if plaintext is None:
  print('error: invalid private key or data not encrypted', file=sys.stderr)
```

