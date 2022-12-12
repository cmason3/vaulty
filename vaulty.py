#!/usr/bin/env python3

# Vaulty - Encrypt/Decrypt with ChaCha20-Poly1305
# Copyright (c) 2021-2023 Chris Mason <chris@netnix.org>
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.exceptions import InvalidTag

__version__ = '1.3.3'

class Vaulty():
  def __init__(self):
    self.__prefix = '$VAULTY;'
    self.__kprefix = '$VPK;'
    self.__sprefix = '$VSIG;'
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
        ciphertext = base64.b64decode(ciphertext.strip()[len(self.__prefix):])

      if ciphertext.startswith(b'\x01') and len(ciphertext) > 29:
        key = self.__derive_key(password, ciphertext[1:17])[1]
        return ChaCha20Poly1305(key).decrypt(ciphertext[17:29], ciphertext[29:], None)

      elif ciphertext.startswith(b'\x41'):
        raise Exception('wrong method - public key based encryption')

    except InvalidTag:
      pass

  def chpass(self, ciphertext, opassword, npassword, cols=None, armour=True):
    plaintext = self.decrypt(ciphertext, opassword)
    if plaintext is not None:
      return self.encrypt(plaintext, npassword, cols, armour)

  def generate_keypair(self, version=b'\x41', armour_public=True, comment=b''):
    if version == b'\x41':
      private_x448 = X448PrivateKey.generate()
      public_x448 = private_x448.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
      private = private_x448.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())

      private_ed25519 = Ed25519PrivateKey.generate()
      public_ed25519 = private_ed25519.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
      private = version + b'\x01' + private + private_ed25519.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())

      public = version + b'\x02' + public_x448 + public_ed25519 + comment

      if armour_public:
        public = self.__kprefix.encode('utf-8') + base64.b64encode(public)
        public = b'\n'.join([public[i:i + 80] for i in range(0, len(public), 80)]) + b'\n'

      return private, public
  
  def public_key_info(self, public_key):
    if public_key.lstrip().startswith(self.__kprefix.encode('utf-8')):
      public_key = base64.b64decode(public_key.strip()[len(self.__kprefix):])

    if public_key.startswith(b'\x41\x02'):
      digest = hashes.Hash(hashes.SHAKE128(8))
      digest.update(public_key)
      fprint = digest.finalize().hex()
      fprint = ':'.join([fprint[i:i + 4] for i in range(0, len(fprint), 4)])
      return fprint.encode('utf-8'), public_key[90:], b'ECDH/X448, EdDSA/Ed25519'

  def encrypt_ecc(self, plaintext, public_key, cols=None, armour=True):
    if public_key.lstrip().startswith(self.__kprefix.encode('utf-8')):
      public_key = base64.b64decode(public_key.strip()[len(self.__kprefix):])

    if public_key.startswith(b'\x41\x02'):
      private, public = self.generate_keypair(b'\x41', False)
      salt = os.urandom(16)
  
      key = X448PrivateKey.from_private_bytes(private[2:58]).exchange(X448PublicKey.from_public_bytes(public_key[2:58]))
      key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b'vaulty').derive(key)
  
      nonce = os.urandom(12)
      ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
  
      if armour:
        r = self.__prefix.encode('utf-8') + base64.b64encode(b'\x41\x03' + salt + public[2:58] + nonce + ciphertext)
  
        if cols is not None:
          r = b'\n'.join([r[i:i + cols] for i in range(0, len(r), cols)])
  
        return r + b'\n'
  
      else:
        return b'\x41\x03' + salt + public[2:58] + nonce + ciphertext

    else:
      raise Exception('public key required')

  def decrypt_ecc(self, ciphertext, private_key):
    try:
      if ciphertext.lstrip().startswith(self.__prefix.encode('utf-8')):
        ciphertext = base64.b64decode(ciphertext.strip()[8:])

      if private_key.startswith(b'\x41\x01'):
        if ciphertext.startswith(b'\x41\x03') and len(ciphertext) > 86:
          key = X448PrivateKey.from_private_bytes(private_key[2:58]).exchange(X448PublicKey.from_public_bytes(ciphertext[18:74]))
          key = HKDF(algorithm=hashes.SHA256(), length=32, salt=ciphertext[2:18], info=b'vaulty').derive(key)
          return ChaCha20Poly1305(key).decrypt(ciphertext[74:86], ciphertext[86:], None)

        elif ciphertext.startswith(b'\x01'):
          raise Exception('wrong method - password based encryption')

      else:
        raise Exception('private key required')

    except InvalidTag:
      pass

  def sign_ecc(self, data, private_key, cols=None):
    if private_key.startswith(b'\x41\x01'):
      key = Ed25519PrivateKey.from_private_bytes(private_key[58:])
      r = self.__sprefix.encode('utf-8') + base64.b64encode(b'\x41\x04' + key.sign(data))

      if cols is not None:
        r = b'\n'.join([r[i:i + cols] for i in range(0, len(r), cols)])

      return r + b'\n'

    else:
      raise Exception('private key required')

  def sign_file_ecc(self, filepath, private_key, cols=None):
    if os.path.isfile(filepath):
      if os.path.getsize(filepath) < 2**31:
        with open(filepath, 'rb') as fh:
          return self.sign_ecc(fh.read(), private_key, cols)

      else:
        raise Exception('file is too big to be signed (max size is <2gb)')

    elif not os.path.exists(filepath):
      raise Exception('unable to sign file - file not found')

    else:
      raise Exception('unable to sign file - unsupported file type')

  def verify_ecc(self, data, public_key, signature):
    if public_key.lstrip().startswith(self.__kprefix.encode('utf-8')):
      public_key = base64.b64decode(public_key.strip()[len(self.__kprefix):])

    if public_key.startswith(b'\x41\x02'):
      if signature.lstrip().startswith(self.__sprefix.encode('utf-8')):
        signature = base64.b64decode(signature.strip()[len(self.__sprefix):])

        if signature.startswith(b'\x41\x04'):
          try:
            key = Ed25519PublicKey.from_public_bytes(public_key[58:90])
            key.verify(signature[2:], data)
            return True

          except InvalidSignature:
            pass

    else:
      raise Exception('public key required')

  def verify_file_ecc(self, filepath, public_key, signature):
    if os.path.isfile(filepath):
      if os.path.getsize(filepath) < 2**31:
        with open(filepath, 'rb') as fh:
          return self.verify_ecc(fh.read(), public_key, signature)

      else:
        raise Exception('file is too big to be verified (max size is <2gb)')

    elif not os.path.exists(filepath):
      raise Exception('unable to verify file - file not found')

    else:
      raise Exception('unable to verify file - unsupported file type')

  def hash(self, data, algorithm):
    digest = hashes.Hash(getattr(hashes, algorithm.upper())())
    digest.update(data)
    return digest.finalize().hex().encode('utf-8')

  def encrypt_file(self, filepath, password):
    return self.__encrypt_file(filepath, password, 'encrypt')

  def decrypt_file(self, filepath, password):
    return self.__decrypt_file(filepath, password, 'decrypt')

  def chpass_file(self, filepath, opassword, npassword, cols=None, armour=False):
    with open(filepath, 'rb') as fh:
      ciphertext = fh.read()

    if ciphertext is not None:
      if ciphertext.lstrip().startswith(self.__prefix.encode('utf-8')):
        cols = len(ciphertext.lstrip().splitlines()[0].strip())
        armour = True

      ciphertext = self.chpass(ciphertext, opassword, npassword, cols, armour)
      if ciphertext is not None:
        with open(filepath, 'wb') as fh:
          fh.write(ciphertext)

        return True

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
      elif m.lower() == 'keygen'[0:len(m)] and len(m) > 3: m = 'keygen'
      elif m.lower() == 'keyinfo'[0:len(m)] and len(m) > 3: m = 'keyinfo'
      elif m.lower() == 'sign'[0:len(m)] and len(m) > 1: m = 'sign'
      elif m.lower() == 'verify'[0:len(m)]: m = 'verify'
      elif m.lower() == 'chpass'[0:len(m)]: m = 'chpass'
      elif m.lower() == 'sha256'[0:len(m)] and len(m) > 3: m = 'sha256'
      elif m.lower() == 'sha512'[0:len(m)] and len(m) > 3: m = 'sha512'
      else: return None
  
      if m == 'keyinfo':
        if len(sys.argv) == 2:
          sys.argv.append(os.getenv('HOME') + '/.vaulty/vaulty_' + getpass.getuser() + '.pub')

        if len(sys.argv) == 3:
          if os.path.isfile(sys.argv[2]):
            with open(sys.argv[2], 'rb') as fh:
              k = fh.read()
              return m, k

          else:
            print('\x1b[1;31merror: unable to open file \'' + sys.argv[2] + '\'\x1b[0m', file=sys.stderr)
            sys.exit(0)
      
      else:
        if m == 'encrypt' or m == 'decrypt':
          if len(sys.argv) >= 4 and sys.argv[2] == '-k':
            if os.path.isfile(sys.argv[3]):
              with open(sys.argv[3], 'rb') as fh:
                k = fh.read()
                del sys.argv[3], sys.argv[2]

            else:
              print('\x1b[1;31merror: unable to open file \'' + sys.argv[3] + '\'\x1b[0m', file=sys.stderr)
              sys.exit(0)
  
        elif m == 'sign':
          if len(sys.argv) == 3 and sys.argv[2] != '-k':
            default_private_key_file = os.getenv('HOME') + '/.vaulty/vaulty_' + getpass.getuser() + '.key'
            sys.argv[2:2] = ['-k', default_private_key_file]

          if len(sys.argv) == 5 and sys.argv[2] == '-k':
            if os.path.isfile(sys.argv[3]):
              with open(sys.argv[3], 'rb') as fh:
                k = fh.read()
                del sys.argv[3], sys.argv[2]

            else:
              print('\x1b[1;31merror: unable to open file \'' + sys.argv[3] + '\'\x1b[0m', file=sys.stderr)
              sys.exit(0)

          else:
            return None
        
        elif m == 'verify':
          if 5 <= len(sys.argv) <= 6 and sys.argv[2] == '-k':
            if os.path.isfile(sys.argv[3]):
              with open(sys.argv[3], 'rb') as fh:
                k = fh.read()
                del sys.argv[3], sys.argv[2]

            else:
              print('\x1b[1;31merror: unable to open file \'' + sys.argv[3] + '\'\x1b[0m', file=sys.stderr)
              sys.exit(0)

          else:
            return None

        return m, k
  
  def encrypt_files(v, files, pdata, method):
    if 'ecc' not in method:
      print()

    for f in files:
      if os.path.isfile(f):
        print('encrypting ' + f + '... ', flush=True, end='')
      
        try:
          if getattr(v, method)(f, pdata) is None:
            print('\x1b[1;31mfailed\nerror: file is too big to be encrypted (max size is <2gb)\x1b[0m', file=sys.stderr)
      
          else:
            print('\x1b[1;32mok\x1b[0m')

        except Exception as e:
          print('\x1b[1;31mfailed\nerror: ' + str(e) + '\x1b[0m', file=sys.stderr)

      elif not os.path.exists(f):
        print('encrypting ' + f + '... \x1b[1;31mnot found\x1b[0m')

      else:
        print('encrypting ' + f + '... \x1b[1;33munsupported\x1b[0m')
  
  def decrypt_files(v, files, pdata, method):
    print()
    for f in files:
      if os.path.isfile(f):
        print('decrypting ' + f + '... ', flush=True, end='')
        
        try:
          if getattr(v, method)(f, pdata) is None:
            print('\x1b[1;31mfailed\nerror: invalid ' + ('private key' if 'ecc' in method else 'password') + ' or file not encrypted\x1b[0m', file=sys.stderr)
      
          else:
            print('\x1b[1;32mok\x1b[0m')

        except Exception as e:
          print('\x1b[1;31mfailed\nerror: ' + str(e) + '\x1b[0m', file=sys.stderr)

      elif not os.path.exists(f):
        print('decrypting ' + f + '... \x1b[1;31mnot found\x1b[0m')

      else:
        print('decrypting ' + f + '... \x1b[1;33munsupported\x1b[0m')

  def chpass_files(v, files, opassword, npassword):
    print()
    for f in files:
      if os.path.isfile(f):
        print('updating ' + f + '... ', flush=True, end='')
        
        try:
          if v.chpass_file(f, opassword, npassword) is None:
            print('\x1b[1;31mfailed\nerror: invalid password or file not encrypted\x1b[0m', file=sys.stderr)
      
          else:
            print('\x1b[1;32mok\x1b[0m')

        except Exception as e:
          print('\x1b[1;31mfailed\nerror: ' + str(e) + '\x1b[0m', file=sys.stderr)

      elif not os.path.exists(f):
        print('updating ' + f + '... \x1b[1;31mnot found\x1b[0m')

      else:
        print('updating ' + f + '... \x1b[1;33munsupported\x1b[0m')

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
                  print('\nPublic Key is "' + pkinfo[1].decode('utf-8') + '"')
                  print('Public Key Fingerprint is ' + pkinfo[0].decode('utf-8'))
                  print('Public Key Algorithms are ' + pkinfo[2].decode('utf-8'))
                  print('\x1b[1;32mok\x1b[0m')
          
                else:
                  print('\x1b[1;31merror: password verification failed\x1b[0m', file=sys.stderr)
          
              else:
                print('\x1b[1;31merror: password is mandatory\x1b[0m', file=sys.stderr)

        else:
          print('\x1b[1;31merror: private key file already exists\x1b[0m', file=sys.stderr)

    elif m[0] == 'keyinfo':
      pkinfo = v.public_key_info(m[1])
      if pkinfo is not None:
        print('Public Key is "' + pkinfo[1].decode('utf-8') + '"')
        print('Public Key Fingerprint is ' + pkinfo[0].decode('utf-8'))
        print('Public Key Algorithms are ' + pkinfo[2].decode('utf-8'))

      else:
        print('\x1b[1;31merror: public key required\x1b[0m', file=sys.stderr)

    elif m[0] == 'sign':
      password = getpass.getpass('Private Key Password: ').encode('utf-8')
      if len(password) > 0:
        private = v.decrypt(m[1], password)
        if private is not None:
          try:
            print(v.sign_file_ecc(sys.argv[2], private, cols).decode('utf-8'), flush=True, end='')

          except Exception as e:
            print('\x1b[1;31merror: ' + str(e) + '\x1b[0m', file=sys.stderr)

        else:
          print('\x1b[1;31merror: invalid private key password or key not private\x1b[0m', file=sys.stderr)

      else:
        print('\x1b[1;31merror: password is mandatory\x1b[0m', file=sys.stderr)

    elif m[0] == 'verify':
      if len(sys.argv) == 3:
        signature = sys.stdin.buffer.read()

      else:
        if os.path.isfile(sys.argv[3]):
          with open(sys.argv[3], 'rb') as fh:
            signature = fh.read()

        else:
          print('\x1b[1;31merror: unable to open file \'' + sys.argv[3] + '\'\x1b[0m', file=sys.stderr)
          sys.exit(0)

      try:
        if v.verify_file_ecc(sys.argv[2], m[1], signature):
          print('\x1b[1;32mok\x1b[0m')

        else:
          print('\x1b[1;31merror: verification failed\x1b[0m', file=sys.stderr)

      except Exception as e:
        print('\x1b[1;31merror: ' + str(e) + '\x1b[0m', file=sys.stderr)

    else:
      if len(sys.argv) == 2:
        data = sys.stdin.buffer.read()

      if m[0] == 'sha256' or m[0] == 'sha512':
        if len(sys.argv) == 2:
          print(v.hash(data, m[0]).decode('utf-8'))
  
        else:
          length = 64 if m[0] == 'sha256' else 128

          for f in sys.argv[2:]:
            if os.path.isfile(f):
              try:
                if os.access(f, os.R_OK):
                  print(v.hash_file(f, m[0]).decode('utf-8') + '  ' + f)

                else:
                  print('\x1b[1;31mpermission denied' + (' ' * (length - 15)) + f + '\x1b[0m')

              except Exception:
                print('\x1b[1;31mfailed' + (' ' * (length - 4)) + f + '\x1b[0m')

            elif os.path.isdir(f):
              for root, dirs, files in os.walk(f):
                for fn in files:
                  try:
                    ffn = os.path.join(root, fn)
                    if os.path.isfile(ffn):
                      if os.access(ffn, os.R_OK):
                        print(v.hash_file(ffn, m[0]).decode('utf-8') + '  ' + ffn)

                      else:
                        print('\x1b[1;31mpermission denied' + (' ' * (length - 15)) + ffn + '\x1b[0m')

                    else:
                      print('\x1b[1;33munsupported' + (' ' * (length - 9)) + ffn + '\x1b[0m')
                      
                  except Exception:
                    print('\x1b[1;31mfailed' + (' ' * (length - 4)) + ffn + '\x1b[0m')

            elif not os.path.exists(f):
              print('\x1b[1;31mnot found' + (' ' * (length - 7)) + f + '\x1b[0m')

            else:
              print('\x1b[1;33munsupported' + (' ' * (length - 9)) + f + '\x1b[0m')

      elif m[0] == 'chpass':
        opassword = getpass.getpass('Old Vaulty Password: ').encode('utf-8')
        if len(opassword) > 0:
          npassword = getpass.getpass('\nNew Vaulty Password: ').encode('utf-8')
          if len(npassword) > 0:
            if npassword == getpass.getpass('Password Verification: ').encode('utf-8'):
              if len(sys.argv) == 2:
                try:
                  ciphertext = v.chpass(data, opassword, npassword, cols)
                  if ciphertext is not None:
                    print(ciphertext.decode('utf-8'), flush=True, end='')

                  else:
                    print('\x1b[1;31merror: invalid password or data not encrypted\x1b[0m', file=sys.stderr)

                except Exception as e:
                  print('\x1b[1;31merror: ' + str(e) + '\x1b[0m', file=sys.stderr)

              else:
                chpass_files(v, sys.argv[2:], opassword, npassword)

            else:
              print('\x1b[1;31merror: password verification failed\x1b[0m', file=sys.stderr)

          else:
            print('\x1b[1;31merror: password is mandatory\x1b[0m', file=sys.stderr)

        else:
          print('\x1b[1;31merror: password is mandatory\x1b[0m', file=sys.stderr)

      elif m[1] is None:
        password = getpass.getpass('Vaulty Password: ').encode('utf-8')
        if len(password) > 0:
          if m[0] == 'encrypt':
            if password == getpass.getpass('Password Verification: ').encode('utf-8'):
              if len(sys.argv) == 2:
                try:
                  print(v.encrypt(data, password, cols).decode('utf-8'), flush=True, end='')

                except Exception as e:
                  print('\x1b[1;31merror: ' + str(e) + '\x1b[0m', file=sys.stderr)
          
              else:
                encrypt_files(v, sys.argv[2:], password, 'encrypt_file')
      
            else:
              print('\x1b[1;31merror: password verification failed\x1b[0m', file=sys.stderr)
      
          elif m[0] == 'decrypt':
            if len(sys.argv) == 2:
              try:
                plaintext = v.decrypt(data, password)
                if plaintext is not None:
                  print(plaintext.decode('utf-8'), flush=True, end='')

                else:
                  print('\x1b[1;31merror: invalid password or data not encrypted\x1b[0m', file=sys.stderr)

              except Exception as e:
                print('\x1b[1;31merror: ' + str(e) + '\x1b[0m', file=sys.stderr)
      
            else:
              decrypt_files(v, sys.argv[2:], password, 'decrypt_file')
    
        else:
          print('\x1b[1;31merror: password is mandatory\x1b[0m', file=sys.stderr)

      else:
        if m[0] == 'encrypt':
          if len(sys.argv) == 2:
            try:
              print(v.encrypt_ecc(data, m[1], cols).decode('utf-8'), flush=True, end='')

            except Exception as e:
              print('\x1b[1;31merror: ' + str(e) + '\x1b[0m', file=sys.stderr)

          else:
            encrypt_files(v, sys.argv[2:], m[1], 'encrypt_file_ecc')

        elif m[0] == 'decrypt':
          password = getpass.getpass('Private Key Password: ').encode('utf-8')
          if len(password) > 0:
            private = v.decrypt(m[1], password)
            if private is not None:
              if len(sys.argv) == 2:
                try:
                  plaintext = v.decrypt_ecc(data, private)
                  if plaintext is not None:
                    print(plaintext.decode('utf-8'), flush=True, end='')

                  else:
                    print('\x1b[1;31merror: invalid private key or data not encrypted\x1b[0m', file=sys.stderr)

                except Exception as e:
                  print('\x1b[1;31merror: ' + str(e) + '\x1b[0m', file=sys.stderr)

              else:
                decrypt_files(v, sys.argv[2:], private, 'decrypt_file_ecc')

            else:
              print('\x1b[1;31merror: invalid private key password or key not private\x1b[0m', file=sys.stderr)

          else:
            print('\x1b[1;31merror: password is mandatory\x1b[0m', file=sys.stderr)

  else:
    print('Vaulty v' + __version__, file=sys.stderr)
    print('Usage: ' + os.path.basename(sys.argv[0]) + ' keygen', file=sys.stderr)
    print(' ' * (len(os.path.basename(sys.argv[0])) + 7) + ' keyinfo [public key]', file=sys.stderr)
    print(' ' * (len(os.path.basename(sys.argv[0])) + 7) + ' encrypt [-k <public key>] [file1] [file2] [...]', file=sys.stderr)
    print(' ' * (len(os.path.basename(sys.argv[0])) + 7) + ' decrypt [-k <private key>] [file1] [file2] [...]', file=sys.stderr)
    print(' ' * (len(os.path.basename(sys.argv[0])) + 7) + ' sign [-k <private key>] <file>', file=sys.stderr)
    print(' ' * (len(os.path.basename(sys.argv[0])) + 7) + ' verify -k <public key> <file> [signature]', file=sys.stderr)
    print(' ' * (len(os.path.basename(sys.argv[0])) + 7) + ' chpass [file1] [file2] [...]', file=sys.stderr)
    print(' ' * (len(os.path.basename(sys.argv[0])) + 7) + ' sha256|sha512 [file1|dir1] [file2|dir2] [...]', file=sys.stderr)


if __name__ == '__main__':
  try:
    main()

  except KeyboardInterrupt:
    pass
