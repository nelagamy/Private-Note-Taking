import pickle
import os
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

class PrivNotes:
  MAX_NOTE_LEN = 2000;

  def __init__(self, password, data = None, checksum = None):
    """Constructor.
    
    Args:
      password (str) : password for accessing the notes
      data (str) [Optional] : a hex-encoded serialized representation to load
                              (defaults to None, which initializes an empty notes database)
      checksum (str) [Optional] : a hex-encoded checksum used to protect the data against
                                  possible rollback attacks (defaults to None, in which
                                  case, no rollback protection is guaranteed)

    Raises:
      ValueError : malformed serialized format
    """

    self.counter = 0

    if data is None:
      print('create new database')
      # adding notes
      self.kvs = {}
      # getting the password_HMAC_key
      #derive source key from password
      self.my_salt = os.urandom(16)
      self.source_key = PrivNotes.derive_source_key(self, password)


    else:
         serialized_data = bytes.fromhex(data)
         loaded_data = pickle.loads(serialized_data)
         self.my_salt = loaded_data[1]
         self.source_key = PrivNotes.derive_source_key(self, password)
         self.password_HMAC_key = PrivNotes.passord_HMAC(password,self.source_key)
         sha256_hash = hashes.Hash(hashes.SHA256())
         sha256_hash.update(bytes.fromhex(data))
         hash_value = sha256_hash.finalize()
         if checksum != hash_value:
             raise ('Provided data is malformed')
         self.source_key = PrivNotes.derive_source_key(self, password)
         new_source_key_hmac = PrivNotes.derive_NEW_HMAC_key(self.source_key)

         # check if the password is correct
         if new_source_key_hmac != loaded_data[2]:
              raise ValueError('Wrong password')
         
         self.kvs = loaded_data[0]
    self.AE_key = PrivNotes.derive_AE_key(self.source_key)
    self.HMAC_key = PrivNotes.derive_HMAC_key(self.source_key)


  def dump(self):
    """Computes a serialized representation of the notes database
       together with a checksum.
    
    Returns:
      data (str) : a hex-encoded serialized representation of the contents of the notes
                   database (that can be passed to the constructor)
      checksum (str) : a hex-encoded checksum for the data used to protect
                       against rollback attacks (up to 32 characters in length)
    """
    source_key_HMAC = PrivNotes.derive_NEW_HMAC_key(self.source_key)
    data = pickle.dumps((self.kvs, self.my_salt, source_key_HMAC)).hex()
    sha256_hash = hashes.Hash(hashes.SHA256())
    sha256_hash.update(bytes.fromhex(data))
    hash_value = sha256_hash.finalize()

    # TESTING
    print('LOADED CHECKSUM IN DUMPS: ', hash_value)
 
    return data, hash_value

  def get(self, title):
    """Fetches the note associated with a title.
    
    Args:
      title (str) : the title to fetch
    
    Returns: 
      note (str) : the note associated with the requested title if
                       it exists and otherwise None
    """
    #get the hash of the title
    note_title_hashed = PrivNotes.note_title_hash(title, self.HMAC_key)

    if note_title_hashed in self.kvs:
      encrypted_note_with_nonce = self.kvs[note_title_hashed]
      original_note_content = PrivNotes.auth_decrypt(encrypted_note_with_nonce, self.AE_key, note_title_hashed)
      return original_note_content
    return None

  def set(self, title, note):
    """Associates a note with a title and adds it to the database
       (or updates the associated note if the title is already
       present in the database).
       
       Args:
         title (str) : the title to set
         note (str) : the note associated with the title

       Returns:
         None

       Raises:
         ValueError : if note length exceeds the maximum
    """
    if len(note) > self.MAX_NOTE_LEN:
      raise ValueError('Maximum note length exceeded')
    
    #get the hash of the title
    note_title_hashed = PrivNotes.note_title_hash(title, self.HMAC_key)
    #encrypt the note
    ready_to_encrypt = PrivNotes.prepare_note_to_encrypt(note)
    encrypted_note = PrivNotes.auth_encrypt(self,ready_to_encrypt, self.AE_key,note_title_hashed)
    #store the encrypted note
    self.kvs[note_title_hashed] = encrypted_note


  def remove(self, title):
    """Removes the note for the requested title from the database.
       
       Args:
         title (str) : the title to remove

       Returns:
         success (bool) : True if the title was removed and False if the title was
                          not found
    """
    #get the hash of the title
    note_title_hashed = PrivNotes.note_title_hash(title, self.HMAC_key)

    if note_title_hashed in self.kvs:
      del self.kvs[note_title_hashed]
      return True

    return False
  
  def passord_HMAC(password, HMAC_key):
    h = hmac.HMAC(HMAC_key, hashes.SHA256())
    password_byte = bytes(password, 'ascii')
    h.update(password_byte)
    user_password_HMAC = h.finalize()
    return user_password_HMAC
  
  def derive_source_key(self,password):
    salt = self.my_salt
    kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = salt,
    iterations = 2000000, backend = default_backend())
    source_key = kdf.derive(bytes(password, 'ascii'))
    return source_key

  def derive_AE_key(source_key):
    h = hmac.HMAC(source_key, hashes.SHA256())
    String_rep = "AE_key"
    h.update(bytes(String_rep, 'ascii'))
    AE_key = h.finalize()
    return AE_key
  
  def derive_HMAC_key(source_key):
    h = hmac.HMAC(source_key, hashes.SHA256())
    h.update(b'HMAC_key')
    HMAC_key = h.finalize()
    return HMAC_key
  
  def derive_NEW_HMAC_key(source_key):
    h = hmac.HMAC(source_key, hashes.SHA256())
    h.update(b'NEW_HMAC_key')
    NEW_HMAC_key = h.finalize()
    return NEW_HMAC_key
  
  def note_title_hash(note_title, HMAC_key):
    h = hmac.HMAC(HMAC_key, hashes.SHA256())
    note_title_byte = bytes(note_title, 'ascii')
    h.update(note_title_byte)
    note_title_hashed = h.finalize()
    return note_title_hashed
  
  def derive_AE_key(source_key):
    h = hmac.HMAC(source_key, hashes.SHA256())
    String_rep = "AE_key"
    h.update(bytes(String_rep, 'ascii'))
    AE_key = h.finalize()
    return AE_key
  
  def prepare_note_to_encrypt(note_content):
    #the first four bytes in ready_to_encrypt are preserved for the length of the note content
    #convert the note content to bytes
    #get the length of the note content
    #convert the length to 4 bytes
    #append the length to ready_to_encrypt
    #then append the note cotent to ready_to_encrypt
    #then pad ready_to_encrypt with zeroes at the end till the ready_to_encrypt reaches 2048 bytes
    note_content_byte = bytes(note_content, 'ascii')
    note_length = len(note_content)
    note_length_bytes = note_length.to_bytes(4, 'little')
    ready_to_encrypt = note_length_bytes + note_content_byte
    ready_to_encrypt = ready_to_encrypt + b'\x00' * (2048 - len(ready_to_encrypt))
    return ready_to_encrypt
  
  def auth_encrypt(self,ready_to_encrypt, AE_key,note_title_hashed):
    nonce = self.counter.to_bytes(12, 'little')
    self.counter += 1
    aesgcm = AESGCM(AE_key)
    encrypted_note = aesgcm.encrypt(nonce, ready_to_encrypt, note_title_hashed)
    #add 96 bit nonce at the end of encrypted_note
    encrypted_note_with_nonce = encrypted_note + nonce
    return encrypted_note_with_nonce
  
  def auth_decrypt(encrypted_note_with_nonce, AE_key,note_title_hashed): 
    nonce = encrypted_note_with_nonce[-12:]
    encrypted_note = encrypted_note_with_nonce[:-12]
    aesgcm = AESGCM(AE_key)
    note_content = aesgcm.decrypt(nonce,encrypted_note,note_title_hashed)
    note_length_bytes = note_content[:4]
    note_length = int.from_bytes(note_length_bytes, 'little')
    original_note_content = note_content[4:4 + note_length]
    original_note_content=original_note_content.decode('ascii')
    return original_note_content
