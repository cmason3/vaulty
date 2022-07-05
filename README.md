[![PyPI](https://img.shields.io/pypi/v/pyvaulty.svg)](https://pypi.python.org/pypi/pyvaulty/)
![Python](https://img.shields.io/badge/python-≥&nbsp;3.6-brightgreen)

## Vaulty
### Encrypt/Decrypt with ChaCha20-Poly1305

Vaulty is an extremely lightweight encryption/decryption tool which uses ChaCha20-Poly1305 to provide 256-bit authenticated symmetric encryption (AEAD) using Scrypt as the password based key derivation function. It also supports public key (asymmetric) encryption via ECDH (Elliptic Curve Diffie-Hellman) using X448 and authentication via EdDSA (Edwards Curve Digital Signature Algorithm) using Ed25519.

It can be used to encrypt/decrypt files, or `stdin` if you don't specify any files. If encrypting `stdin` then the output will be Base64 encoded whereas if encrypting a file then it won't and it will have a `.vlt` extension added to indicate it has been encrypted.

It relies on the [cryptography](https://pypi.org/project/cryptography/) Python module to provide the routines for ChaCha20-Poly1305, Scrypt, ECDH with X448 and EdDSA with Ed25519.
 
#### Installation

```
python3 -m pip install --upgrade --user pyvaulty
```

#### Vaulty Usage

```
vaulty ...
  keygen
  keyinfo [public key]
  encrypt [-k <public key>] [file1] [file2] [...]
  decrypt [-k <private key>] [file1] [file2] [...]
  sign [-k <private key>] <file>
  verify -k <public key> <file> [signature]
  chpass [file1] [file2] [...]
  sha256|sha512 [file1|dir1] [file2|dir2] [...]
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

Public key encryption is asymmetric which means Alice no longer needs to share the same password/key with Bob. With asymmetric encryption Alice and Bob both generate a keypair which comprises of a private key and a public key. The private key (as the name suggests) must remain private and should be encrypted using symmetric encryption where the password is never shared. The public key should be given to anyone who wishes to securely communicate with you. There is a lot of complicated maths involved here using something called (EC) [Diffie-Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) that allows two parties to agree on a shared secret without ever exchanging that secret. If Alice wants to share an encrypted file with Bob then she needs to encrypt it using Bob's public key. Bob will then use his private key to decrypt it, as only the paired private key is able to decrypt it. In the opposite direction if Bob wishes to share an encrypted file with Alice then he would encrypt it using Alice's public key.

The specific method adopted here is based on [ECIES](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme) which uses an ephemeral key pair for ECDH. When Alice wants to encrypt something for Bob, she generates a new public/private key pair. She then performs ECDH with the newly generated private key and Bob's known public key, which is then expanded using HKDF to produce an encryption key that is passed to ChaCha20-Poly1305. When the ciphertext is sent to Bob, it includes the corresponding public key that was generated - Bob then performs ECDH using that public key and his private key to derive the same encryption key to decrypt the ciphertext. In this scenario Bob has no way to determine that it was indeed Alice that encrypted it and this is why Alice should sign the ciphertext with her actual private key and send the signature with the ciphertext so that Bob can validate with Alice's known public key.

With symmetric encryption the challenge is securely exchanging the password/key, but with asymmetric encryption the challenge is proving what you think is Bob's public key actually is Bob's public key. What if Eve was sitting between Alice and Bob and when Bob sent his public key, Eve went and swapped it with hers? When exchanging public keys you must use another method to verify you are actually in possession of Bob's public key - in simplest terms Alice needs to verify Bob's public key fingerprint with Bob himself and vice versa.

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

#### Example Usage - Public Key (Asymmetric) Authentication

Public Keys also support authentication by allowing us to sign a piece of data with our private key and letting other user's verify we have signed it using our public key. Let's assume Bob sent Alice a contract and asked Alice to sign it - how does Bob know that Alice actually signed it with her own hand and it wasn't Eve who knows what Alice's signature looks like? This is where public key authentication helps - if Alice was to create a signature of the contract using her private key (that is password protected) and then sent that signature to Bob, he would then be able to verify that signature using Alice's public key (which is public) to verify without doubt that Alice has indeed signed it.

You still have the same challenge as with Public Key Encryption in that you need to verify via another method that you have the correct public key for Alice!

```
vaulty keygen

vaulty sign -k ~/.vaulty/vaulty.key CONTRACT.md >CONTRACT.md.sig

cat CONTRACT.md.sig | vaulty verify -k ~/.vaulty/vaulty.pub CONTRACT.md 
```

```python
import vaulty

v = vaulty.Vaulty()

private, public = v.generate_keypair()

signature = v.sign_ecc('Hello World'.encode('utf-8'), private)

if v.verify_ecc('Hello World'.encode('utf-8'), public, signature):
  print('Signature Verified')
```

#### Change Password of Private Key (or Encrypted File)

```
vaulty chpass ~/.vaulty/vaulty.key
```
