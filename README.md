![Release](https://img.shields.io/github/v/release/cmason3/vaulty)
![Size](https://img.shields.io/github/languages/code-size/cmason3/vaulty?label=size)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[<img src="https://img.shields.io/pypi/v/pyvaulty.svg" align="right">](https://pypi.python.org/pypi/pyvaulty/)

## Vaulty
### Encrypt/Decrypt with ChaCha20-Poly1305

Vaulty is an extremely lightweight encryption/decryption tool which uses ChaCha20-Poly1305 to provide 256-bit authenticated encryption (AEAD) using Scrypt as the password based key derivation function. It can be used to encrypt/decrypt files, or `stdin` if you don't specify any files.

#### Installation

```
python3 -m pip install --upgrade --user pyvaulty
```

#### Vaulty Usage

```
vaulty encrypt|decrypt [file1[ file2[ ...]]]
```
