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
  chpass [file1[ file2[ ...]]]
  sha256 [file1[ file2[ ...]]]
```

#### Example Usage - Symmetric Encryption

Symmetric encryption is where encryption and decryption happens with the same password/key. If Alice is sharing an encrypted file with Bob then both [Alice and Bob](https://en.wikipedia.org/wiki/Alice_and_Bob) need to know the same password/key. With symmetric encryption both parties need a secure mechanism to exchange the password/key without anyone else (i.e. Eve) obtaining it (see "Public Key Encryption").

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

Public key encryption is asymmetric which means Alice no longer needs to share the same password/key with Bob. With asymmetric encryption Alice and Bob both generate a keypair which comprises of a private key and a public key. The private key (as the name suggests) must remain private and should be encrypted using symmetric encryption where the password is never shared. The public key should be given to anyone who wishes to securely communicate with you. There is a lot of complicated maths involved here using something called [Diffie-Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) that allows two parties to agree on a shared secret without ever exchanging that secret. If Alice wants to share an encrypted file with Bob then she needs to encrypt it using Bob's public key. Bob will then use his private key to decrypt it, as only the paired private key is able to decrypt it. In the opposite direction if Bob wishes to share an encrypted file with Alice then he would encrypt it using Alice's public key.

With symmetric encryption the challenge is securely exchanging the password/key, but with asymmetric encryption the challenge is proving what you think is Bob's public key actually is Bob's public key. What if Eve was sitting between Alice and Bob and when Bob sent his public key, Eve went and swapped it with hers? When exchanging public keys you must use another method to verify you are actually in possession of Bob's public key - in simplest terms Alice needs to verify Bob's public key fingerprint with Bob himself and vice versa.

```
vaulty keygen

echo "Hello World" | vaulty encrypt -k ~/.vaulty/vaulty.pub
$VAULTY;QfIfowgIxGIpxD3wpk/p5/6wTHvxalHKqhodSuorNPvuvhmHqsybZ822x6nyPWdNsZnDVFKi
4nkSBTPnQS17Hexn1Fj85vyrARMc5oQ3ySLpB8QWGQJdjaYFeVyfRh2WwMZqkyAki09U2h7MMFBAbAc=

echo "$VAULTY;..." | vaulty decrypt -k ~/.vaulty/vaulty.key
Hello World
```

##### Change Password of Private Key

```
vaulty chpass ~/.vaulty/vaulty.key
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

