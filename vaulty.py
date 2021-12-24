#!/usr/bin/env python3

# Vaulty - Encrypt/Decrypt with ChaCha20-Poly1305
# Copyright (c) 2021-2022 Chris Mason <chris@netnix.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import sys, os, base64, getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

__version__ = '1.1.0'

class Vaulty():
  def __init__(self):
    self.__prefix = '$VAULTY;'
    self.__kprefix = '$VPK;'
    self.__extension = '.vlt'
    self.__bufsize = 64 * 1024
    self.__kcache = {}

  def __derive_key(self, password, salt=None):
    ckey = (password, salt)

    if ckey in self.__kcache:
      return self.__kcache[ckey]

    if salt is None:
      salt = os.urandom(16)
  
    key = Scrypt(salt, 32, 2**16, 8, 1, default_backend()).derive(password)
    self.__kcache[ckey] = [salt, key]
    return salt, key

  def generate_keypair(self, version=b'\x41', armour=True):
    if version == b'\x41':
      private = X25519PrivateKey.generate()
      public = version + private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

      if armour:
        public = self.__kprefix.encode('utf-8') + base64.b64encode(public)
        public = b'\n'.join([public[i:i + 80] for i in range(0, len(public), 80)]) + b'\n'

      return private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()), public
  
  def encrypt(self, plaintext, password, cols=None, armour=True):
    version = b'\x01'
    salt, key = self.__derive_key(password)
    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)

    if armour:
      r = self.__prefix.encode('utf-8') + base64.b64encode(version + salt + nonce + ciphertext)

      if cols is not None:
        r = b'\n'.join([r[i:i + cols] for i in range(0, len(r), cols)])

      return r + b'\n'

    else:
      return version + salt + nonce + ciphertext
  
  def decrypt(self, ciphertext, password):
    try:
      if ciphertext.lstrip().startswith(self.__prefix.encode('utf-8')):
        ciphertext = base64.b64decode(ciphertext.strip()[len(self.__prefix)-1:])

      if len(ciphertext) > 29 and ciphertext.startswith(b'\x01'):
        key = self.__derive_key(password, ciphertext[1:17])[1]
        return ChaCha20Poly1305(key).decrypt(ciphertext[17:29], ciphertext[29:], None)

    except InvalidTag:
      pass

  def encrypt_ecc(self, plaintext, public_key, cols=None, armour=True):
    if public_key.lstrip().startswith(self.__kprefix.encode('utf-8')):
      public_key = base64.b64decode(public_key.strip()[len(self.__kprefix)-1:])

    if public_key.startswith(b'\x41'):
      private, public = self.generate_keypair(public_key[:1], False)
      salt = os.urandom(16)
  
      key = X25519PrivateKey.from_private_bytes(private).exchange(X25519PublicKey.from_public_bytes(public_key[1:]))
      key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b'vaulty').derive(key)
  
      nonce = os.urandom(12)
      ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
  
      if armour:
        r = self.__prefix.encode('utf-8') + base64.b64encode(public_key[:1] + salt + public[1:] + nonce + ciphertext)
  
        if cols is not None:
          r = b'\n'.join([r[i:i + cols] for i in range(0, len(r), cols)])
  
        return r + b'\n'
  
      else:
        return public_key[:1] + salt + public[1:] + nonce + ciphertext

  def decrypt_ecc(self, ciphertext, private_key):
    try:
      if ciphertext.lstrip().startswith(self.__prefix.encode('utf-8')):
        ciphertext = base64.b64decode(ciphertext.strip()[8:])

      if len(ciphertext) > 61 and ciphertext.startswith(b'\x41'):
        key = X25519PrivateKey.from_private_bytes(private_key).exchange(X25519PublicKey.from_public_bytes(ciphertext[17:49]))
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=ciphertext[1:17], info=b'vaulty').derive(key)
        return ChaCha20Poly1305(key).decrypt(ciphertext[49:61], ciphertext[61:], None)

    except InvalidTag:
      pass

  def hash(self, data, algorithm):
    digest = hashes.Hash(getattr(hashes, algorithm.upper())())
    digest.update(data)
    return digest.finalize().hex().encode('utf-8')

  def __encrypt_file(self, filepath, pdata, method):
    if os.path.getsize(filepath) < 2**31:
      with open(filepath, 'rb') as fh:
        ciphertext = getattr(self, method)(fh.read(), pdata, None, False)

      if ciphertext is not None:
        with open(filepath, 'wb') as fh:
          fh.write(ciphertext)

        os.rename(filepath, filepath + self.__extension)
        return True

  def __decrypt_file(self, filepath, pdata, method):
    with open(filepath, 'rb') as fh:
      plaintext = getattr(self, method)(fh.read(), pdata)

    if plaintext is not None:
      with open(filepath, 'wb') as fh:
        fh.write(plaintext)

      if filepath.endswith(self.__extension):
        os.rename(filepath, filepath[:-len(self.__extension)])

      return True

  def encrypt_file(self, filepath, password):
    return self.__encrypt_file(filepath, password, 'encrypt')

  def decrypt_file(self, filepath, password):
    return self.__decrypt_file(filepath, password, 'decrypt')

  def encrypt_file_ecc(self, filepath, public_key):
    return self.__encrypt_file(filepath, public_key, 'encrypt_ecc')

  def decrypt_file_ecc(self, filepath, private_key):
    return self.__decrypt_file(filepath, private_key, 'decrypt_ecc')

  def hash_file(self, filepath, algorithm):
    digest = hashes.Hash(getattr(hashes, algorithm.upper())())

    with open(filepath, 'rb') as fh:
      for data in iter(lambda: fh.read(self.__bufsize), b''):
        digest.update(data)
      
      return digest.finalize().hex().encode('utf-8')


def __args():
  if len(sys.argv) >= 2:
    m = sys.argv[1].lower()
    if len(sys.argv) == 2 or all([os.path.isfile(f) for f in sys.argv[2:]]):
      if m.lower() == 'encrypt'[0:len(m)]:
        return 'encrypt'
      elif m.lower() == 'decrypt'[0:len(m)]:
        return 'decrypt'
      elif m.lower() == 'keygen'[0:len(m)]:
        return 'keygen'
      elif m.lower() == 'sha256'[0:len(m)]:
        return 'sha256'

def main(m=__args(), cols=80, v=Vaulty()):
  if m is not None:
    if m == 'keygen':
      private_key_file = os.getenv('HOME') + '/.vaulty/vaulty_' + getpass.getuser() + '.key'
      private_key_file = (input('Private Key (' + private_key_file + '): ') or private_key_file).strip()

      if len(private_key_file):
        public_key_file = (private_key_file[:-4] if private_key_file.endswith('.key') else private_key_file) + '.pub'
        print('Public Key is ' + public_key_file)

        password = getpass.getpass('\nPrivate Key Password: ').encode('utf-8')
        if len(password) > 0:
          if password == getpass.getpass('Password Verification: ').encode('utf-8'):
            private, public = v.generate_keypair()
            private = v.encrypt(private, password, None, False)
      
          else:
            print('\x1b[1;31merror: password verification failed\x1b[0m', file=sys.stderr)
      
        else:
          print('\x1b[1;31merror: password is mandatory\x1b[0m', file=sys.stderr)

    else:
      if len(sys.argv) == 2:
        data = sys.stdin.buffer.read()

      if m == 'sha256':
        if len(sys.argv) == 2:
          print(v.hash(data, m).decode('utf-8'))
  
        else:
          for f in sys.argv[2:]:
            print(v.hash_file(f, m).decode('utf-8') + '  ' + f)
  
      else:
        password = getpass.getpass('Vaulty Password: ').encode('utf-8')
        if len(password) > 0:
          if m == 'encrypt':
            if password == getpass.getpass('Password Verification: ').encode('utf-8'):
              if len(sys.argv) == 2:
                print(v.encrypt(data, password, cols).decode('utf-8'), flush=True, end='')
          
              else:
                print()
                for f in sys.argv[2:]:
                  print('encrypting ' + f + '... ', flush=True, end='')
    
                  if os.path.abspath(sys.argv[0]) == os.path.abspath(f):
                    print('\x1b[1;31mfailed\nerror: file prohibited from being encrypted\x1b[0m', file=sys.stderr)
                    
                  else:
                    if v.encrypt_file(f, password) is None:
                      print('\x1b[1;31mfailed\nerror: file is too big to be encrypted (max size is <2gb)\x1b[0m', file=sys.stderr)
    
                    else:
                      print('\x1b[1;32mok\x1b[0m')
      
            else:
              print('\x1b[1;31merror: password verification failed\x1b[0m', file=sys.stderr)
      
          elif m == 'decrypt':
            if len(sys.argv) == 2:
              plaintext = v.decrypt(data, password)
              if plaintext is not None:
                print(plaintext.decode('utf-8'), flush=True, end='')
      
              else:
                print('\x1b[1;31merror: invalid password or data not encrypted\x1b[0m', file=sys.stderr)
      
            else:
              print()
              for f in sys.argv[2:]:
                print('decrypting ' + f + '... ', flush=True, end='')
                if v.decrypt_file(f, password) is None:
                  print('\x1b[1;31mfailed\nerror: invalid password or file not encrypted\x1b[0m', file=sys.stderr)
    
                else:
                  print('\x1b[1;32mok\x1b[0m')
    
        else:
          print('\x1b[1;31merror: password is mandatory\x1b[0m', file=sys.stderr)

  else:
    print('usage: ' + os.path.basename(sys.argv[0]) + ' encrypt|decrypt|keygen|sha256 [file1[ file2[ ...]]]', file=sys.stderr)


if __name__ == '__main__':
  try:
    main()

  except KeyboardInterrupt:
    pass
