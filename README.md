[![PyPI](https://img.shields.io/pypi/v/pyvaulty.svg)](https://pypi.python.org/pypi/pyvaulty/)
![Size](https://img.shields.io/github/languages/code-size/cmason3/vaulty?label=size)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)

## Vaulty
### Encrypt/Decrypt with ChaCha20-Poly1305

Vaulty is an extremely lightweight encryption/decryption tool which uses ChaCha20-Poly1305 to provide 256-bit authenticated encryption (AEAD) using Scrypt as the password based key derivation function. It can be used to encrypt/decrypt files, or `stdin` if you don't specify any files - it is written in Python and requires Python 3.

If encrypting `stdin` then the output will be Base64 encoded whereas if encrypting a file then it won't and it will have a `.vlt` extension added to indicate it has been encrypted.

It relies on the [cryptography](https://pypi.org/project/cryptography/) Python module to provide the routines for ChaCha20-Poly1305 and Scrypt.

#### Installation

```
python3 -m pip install --upgrade --user pyvaulty
```

#### Vaulty Usage

```
vaulty encrypt|decrypt [file1[ file2[ ...]]]
```

#### Example Usage

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
