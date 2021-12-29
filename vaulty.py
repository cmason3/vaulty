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
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey
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

  def generate_keypair(self, version=b'\x41', armour_public=True, comment=b''):
    if version == b'\x41':
      private = X448PrivateKey.generate()
      public = version + private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) + comment

      if armour_public:
        public = self.__kprefix.encode('utf-8') + base64.b64encode(public)
        public = b'\n'.join([public[i:i + 80] for i in range(0, len(public), 80)]) + b'\n'

      return private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()), public
  
  def public_key_info(self, public_key):
    if public_key.lstrip().startswith(self.__kprefix.encode('utf-8')):
      public_key = base64.b64decode(public_key.strip()[len(self.__kprefix)-1:])

    digest = hashes.Hash(hashes.SHAKE128(8))
    digest.update(public_key)

    return digest.finalize().hex(':').encode('utf-8'), public_key[57:]

  def encrypt_ecc(self, plaintext, public_key, cols=None, armour=True):
    if public_key.lstrip().startswith(self.__kprefix.encode('utf-8')):
      public_key = base64.b64decode(public_key.strip()[len(self.__kprefix)-1:])

    if public_key.startswith(b'\x41'):
      private, public = self.generate_keypair(public_key[:1], False)
      salt = os.urandom(16)
  
      key = X448PrivateKey.from_private_bytes(private).exchange(X448PublicKey.from_public_bytes(public_key[1:57]))
      key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b'vaulty').derive(key)
  
      nonce = os.urandom(12)
      ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
  
      if armour:
        r = self.__prefix.encode('utf-8') + base64.b64encode(public_key[:1] + salt + public[1:57] + nonce + ciphertext)
  
        if cols is not None:
          r = b'\n'.join([r[i:i + cols] for i in range(0, len(r), cols)])
  
        return r + b'\n'
  
      else:
        return public_key[:1] + salt + public[1:57] + nonce + ciphertext

  def decrypt_ecc(self, ciphertext, private_key):
    try:
      if ciphertext.lstrip().startswith(self.__prefix.encode('utf-8')):
        ciphertext = base64.b64decode(ciphertext.strip()[8:])

      if len(ciphertext) > 85 and ciphertext.startswith(b'\x41'):
        key = X448PrivateKey.from_private_bytes(private_key).exchange(X448PublicKey.from_public_bytes(ciphertext[17:73]))
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=ciphertext[1:17], info=b'vaulty').derive(key)
        return ChaCha20Poly1305(key).decrypt(ciphertext[73:85], ciphertext[85:], None)

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


def main(cols=80, v=Vaulty()):
  def args(k=None):
    if len(sys.argv) >= 2:
      m = sys.argv[1].lower()
  
      if m.lower() == 'encrypt'[0:len(m)]: m = 'encrypt'
      elif m.lower() == 'decrypt'[0:len(m)]: m = 'decrypt'
      elif m.lower() == 'keygen'[0:len(m)]: m = 'keygen'
      elif m.lower() == 'sha256'[0:len(m)]: m = 'sha256'
  
      if m == 'encrypt' or m == 'decrypt':
        if len(sys.argv) >= 4 and sys.argv[2] == '-k':
          if os.path.isfile(sys.argv[3]):
            with open(sys.argv[3], 'rb') as fh:
              k = fh.read()
  
            del sys.argv[3], sys.argv[2]
  
      if len(sys.argv) == 2 or all([os.path.isfile(f) for f in sys.argv[2:]]):
        return m, k
  
  def encrypt_files(v, files, pdata, method):
    print()
    for f in files:
      print('encrypting ' + f + '... ', flush=True, end='')
      
      if os.path.abspath(sys.argv[0]) == os.path.abspath(f):
        print('\x1b[1;31mfailed\nerror: file prohibited from being encrypted\x1b[0m', file=sys.stderr)
        
      else:
        if getattr(v, method)(f, pdata) is None:
          print('\x1b[1;31mfailed\nerror: file is too big to be encrypted (max size is <2gb)\x1b[0m', file=sys.stderr)
      
        else:
          print('\x1b[1;32mok\x1b[0m')
  
  def decrypt_files(v, files, pdata, method):
    print()
    for f in files:
      print('decrypting ' + f + '... ', flush=True, end='')
      if getattr(v, method)(f, pdata) is None:
        print('\x1b[1;31mfailed\nerror: invalid ' + ('private key' if 'ecc' in method else 'password') + ' or file not encrypted\x1b[0m', file=sys.stderr)
      
      else:
        print('\x1b[1;32mok\x1b[0m')

  m = args()

  if m is not None:
    if m[0] == 'keygen':
      private_key_file = os.getenv('HOME') + '/.vaulty/vaulty_' + getpass.getuser() + '.key'
      private_key_file = os.path.expanduser((input('Private Key (' + private_key_file + '): ') or private_key_file).strip())

      if len(private_key_file):
        if not os.path.isfile(private_key_file):
          public_key_file = (private_key_file[:-4] if private_key_file.endswith('.key') else private_key_file) + '.pub'
          print('Public Key is ' + public_key_file)

          fullname = input('\nFull Name: ').strip()
          if len(fullname):
            email = input('email Address: ').strip()
            if len(email):
              comment = fullname + ' <' + email + '>'
              password = getpass.getpass('\nPrivate Key Password: ').encode('utf-8')
              if len(password) > 0:
                if password == getpass.getpass('Password Verification: ').encode('utf-8'):
                  private, public = v.generate_keypair(comment=comment.encode('utf-8'))
                  private = v.encrypt(private, password, cols, True)
    
                  if len(os.path.dirname(private_key_file)):
                    os.makedirs(os.path.dirname(private_key_file), exist_ok=True)
    
                  with open(os.open(private_key_file, os.O_CREAT|os.O_WRONLY, 0o600), 'wb') as fh:
                    fh.write(private)
    
                  with open(public_key_file, 'wb') as fh:
                    fh.write(public)
    
                  pkinfo = v.public_key_info(public)
                  print('\nPublic Key // ' + pkinfo[1].decode('utf-8'))
                  print('Public Key Fingerprint is ' + pkinfo[0].decode('utf-8'))
                  print('\x1b[1;32mok\x1b[0m')
          
                else:
                  print('\x1b[1;31merror: password verification failed\x1b[0m', file=sys.stderr)
          
              else:
                print('\x1b[1;31merror: password is mandatory\x1b[0m', file=sys.stderr)

        else:
          print('\x1b[1;31merror: private key file already exists\x1b[0m', file=sys.stderr)

    else:
      if len(sys.argv) == 2:
        data = sys.stdin.buffer.read()

      if m[0] == 'sha256':
        if len(sys.argv) == 2:
          print(v.hash(data, m[0]).decode('utf-8'))
  
        else:
          for f in sys.argv[2:]:
            print(v.hash_file(f, m[0]).decode('utf-8') + '  ' + f)
  
      elif m[1] is None:
        password = getpass.getpass('Vaulty Password: ').encode('utf-8')
        if len(password) > 0:
          if m[0] == 'encrypt':
            if password == getpass.getpass('Password Verification: ').encode('utf-8'):
              if len(sys.argv) == 2:
                print(v.encrypt(data, password, cols).decode('utf-8'), flush=True, end='')
          
              else:
                encrypt_files(v, sys.argv[2:], password, 'encrypt_file')
      
            else:
              print('\x1b[1;31merror: password verification failed\x1b[0m', file=sys.stderr)
      
          elif m[0] == 'decrypt':
            if len(sys.argv) == 2:
              plaintext = v.decrypt(data, password)
              if plaintext is not None:
                print(plaintext.decode('utf-8'), flush=True, end='')
      
              else:
                print('\x1b[1;31merror: invalid password or data not encrypted\x1b[0m', file=sys.stderr)
      
            else:
              decrypt_files(v, sys.argv[2:], password, 'decrypt_file')
    
        else:
          print('\x1b[1;31merror: password is mandatory\x1b[0m', file=sys.stderr)

      else:
        if m[0] == 'encrypt':
          pkinfo = v.public_key_info(m[1])
          print('Public Key // ' + pkinfo[1].decode('utf-8'), file=sys.stderr)
          print('Public Key Fingerprint is ' + pkinfo[0].decode('utf-8'), file=sys.stderr)

          if len(sys.argv) == 2:
            print(v.encrypt_ecc(data, m[1], cols).decode('utf-8'), flush=True, end='')

          else:
            encrypt_files(v, sys.argv[2:], m[1], 'encrypt_file_ecc')

        elif m[0] == 'decrypt':
          password = getpass.getpass('Private Key Password: ').encode('utf-8')
          if len(password) > 0:
            private = v.decrypt(m[1], password)
            if private is not None:
              if len(sys.argv) == 2:
                plaintext = v.decrypt_ecc(data, private)
                if plaintext is not None:
                  print(plaintext.decode('utf-8'), flush=True, end='')

                else:
                  print('\x1b[1;31merror: invalid private key or data not encrypted\x1b[0m', file=sys.stderr)

              else:
                decrypt_files(v, sys.argv[2:], private, 'decrypt_file_ecc')

            else:
              print('\x1b[1;31merror: invalid private key password\x1b[0m', file=sys.stderr)

          else:
            print('\x1b[1;31merror: password is mandatory\x1b[0m', file=sys.stderr)

  else:
    print('usage:', file=sys.stderr)
    print('  ' + os.path.basename(sys.argv[0]) + ' encrypt [-k <public key>] [file1[ file2[ ...]]]', file=sys.stderr)
    print('  ' + os.path.basename(sys.argv[0]) + ' decrypt [-k <private key>] [file1[ file2[ ...]]]', file=sys.stderr)
    print('  ' + os.path.basename(sys.argv[0]) + ' sha256 [file1[ file2[ ...]]]', file=sys.stderr)
    print('  ' + os.path.basename(sys.argv[0]) + ' keygen', file=sys.stderr)


if __name__ == '__main__':
  try:
    main()

  except KeyboardInterrupt:
    pass
