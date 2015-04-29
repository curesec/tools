####
#
# taken from an online ressource
# slightly modified
#
# http://code.activestate.com/recipes/576980/
# PyCrypto-based authenticated symetric encryption
###

import os
import hmac
import hashlib
from Crypto.Cipher import AES

class AuthenticationError(Exception): pass

class Crypticle(object):
	"""Authenticated encryption class
	
	Encryption algorithm: AES-CBC
	Signing algorithm: HMAC-SHA256

	"""

	AES_BLOCK_SIZE = 16
	SIG_SIZE = hashlib.sha256().digest_size

	def __init__(self, key_string, key_size=192):
		self.keys = self.extract_keys(key_string, key_size)
		self.key_size = key_size

	@classmethod
	def generate_key_string(cls, key_size=192):
		key = os.urandom(key_size / 8 + cls.SIG_SIZE)
		return key.encode("base64").replace("\n", "")

	@classmethod
	def extract_keys(cls, key_string, key_size):
		key = key_string.decode("base64")
		assert len(key) == key_size / 8 + cls.SIG_SIZE, "invalid key"
		return key[:-cls.SIG_SIZE], key[-cls.SIG_SIZE:]

	def encrypt(self, data):
		"""encrypt data with AES-CBC and sign it with HMAC-SHA256"""
		aes_key, hmac_key = self.keys
		pad = self.AES_BLOCK_SIZE - len(data) % self.AES_BLOCK_SIZE
		data = data + pad * chr(pad)
		iv_bytes = os.urandom(self.AES_BLOCK_SIZE)
		cypher = AES.new(aes_key, AES.MODE_CBC, iv_bytes)
		data = iv_bytes + cypher.encrypt(data)
		sig = hmac.new(hmac_key, data, hashlib.sha256).digest()
		return data + sig

	def decrypt(self, data):
		"""verify HMAC-SHA256 signature and decrypt data with AES-CBC"""
		aes_key, hmac_key = self.keys
		sig = data[-self.SIG_SIZE:]
		data = data[:-self.SIG_SIZE]
		if hmac.new(hmac_key, data, hashlib.sha256).digest() != sig:
			return -1
			raise AuthenticationError("message authentication failed")
		else:
			iv_bytes = data[:self.AES_BLOCK_SIZE]
			data = data[self.AES_BLOCK_SIZE:]
			cypher = AES.new(aes_key, AES.MODE_CBC, iv_bytes)
			data = cypher.decrypt(data)
			return data[:-ord(data[-1])]

	def dumps(self, obj):
		""" argl """
		return self.encrypt(obj)
	
	def loads(self, obj):
		""" argl """
		data = self.decrypt(obj)
		if data == -1:
			return -1

		return self.decrypt(obj)
