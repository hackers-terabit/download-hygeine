#!/usr/bin/python2.7

'''
	Crypto - handle public key verification and signature of download catalogs
	
	The __init__() expects a dictionary containing relevant configuration paramters.
	
	sign_and_export() should sign data with the configured public key and export the signature as well
	as the public-key,name,url,description and the hash algorithm used
	
	verify_and_load() should parse what sign_and_export() exported,see if the public key is trusted,
	prompt the user if they want to trust the key and fail validation if the public key has already been trusted under a different name
	or if the signature is invalid.  Finally it should return the authenticated data or None if authentication has failed.
'''

color={"green":"\33[92m","blue":"\33[96m","red":"\33[31m","yellow":"\33[93m","white":"\33[98m"}

import os
import getpass 
import json 
import traceback 
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


    
class Crypto:
	curvemap={				"secp192r1": ec.SECP192R1(),
							"secp224r1": ec.SECP224R1(),
							"secp256r1": ec.SECP256R1(),
							"secp384r1": ec.SECP384R1(),
							"secp521r1": ec.SECP521R1(),
							"secp256k1": ec.SECP256K1(),
						
							"sect163k1": ec.SECT163K1(),
							"sect233k1": ec.SECT233K1(),
							"sect283k1": ec.SECT283K1(),
							"sect409k1": ec.SECT409K1(),
							"sect571k1": ec.SECT571K1(),
						
							"sect163r2": ec.SECT163R2(),
							"sect233r1": ec.SECT233R1(),
							"sect283r1": ec.SECT283R1(),
							"sect409r1": ec.SECT409R1(),
							"sect571r1": ec.SECT571R1()
					}
						
	hash_algorithms={"SHA256":hashes.SHA256(),"SHA512":hashes.SHA512()}
	
	def __init__(self,crypto_config):
		try:
			self.config=crypto_config
			self.ready=False
	
			self.trusted_keys_path=os.path.abspath(crypto_config["trusted_keys_path"])
			if not os.path.exists(self.trusted_keys_path):
				with open(self.trusted_keys_path,"w+") as tf:
					tf.write("")
					
			self.trusted_keys=set()
			
			
			self.backend=default_backend()
			self.ec_curve=self.curvemap[crypto_config["ECDSA-CURVE"]]
			self.hash_algorithm=crypto_config["hash"]
			
			if not "name" in crypto_config:
				name=""
				while True:
					name=raw_input(color["yellow"]+"Enter a name. This name will be associated with your public key and anyone you share downloads with will try to associate this name with your public key\n:")
					if len(name.strip())<1:
						print(color["red"]+"You didn't enter any name. it needs to have at least one character.")
					else:
						break
				self.config["name"]=name
						
			if not "url" in crypto_config:
				url=""
				while True:
					url=raw_input(color["yellow"]+"Enter a URL. This URL will be associated with your public key and anyone you share downloads with will attempt to visit this URL to validate whether or not your public key and name have a legitimate association with the site at that URL.\n:")
					if len(url.strip())<5:
						print(color["red"]+"You didn't enter any URL. it needs to have at least 5 characters.")
					else:
						break				
				self.config["url"]=url
				
			if not "description" in crypto_config:
				description=""
				while True:
					print(color["yellow"]+'''
Enter a	description of you and your public key. This is an informal field. It needs to have at least 5 characters.
Feel free to add as little or as much information as you want that will help others validate the association of your public key with your identity.
While not required, it certainly does help if you can include signatures (PGP,s/mime signed email,etc...) and other steps users should take to validate your public key and it's association with your identity.
	
When finished enter 'EOF' without quotes on it's own line:
					''')
					lines=[]
					while True:
						line=raw_input()
						if 'eof' in line.strip().lower():
							break
						else:
							lines.append(line)
					description='\n'.join(lines)	
					self.config["description"]=description	
					if len(description.strip())<5:
						print(color["red"]+"You description isn't long enough. it needs to have at least 5 characters.")
					else:
						break
					
									
			self.name=self.config["name"]
			self.url=self.config["url"]
			self.description=self.config["description"]
			
			if not "private-key" in crypto_config:
				if not self.ecdsa_keygen():
					print(color["red"]+"Error,failed to generate ecdsa key.")
					sys.exit(1)
				else:
					passwd=None
					confirm=None
					while True:
						passwd=getpass.getpass("Enter a password that will be used to encrypt your private signing key. You will need this password to sign any downloads.\n:")
						if len(passwd)>9:
							confirm=getpass.getpass("Confirm this password by entering it again:\n")
							if confirm==passwd:
								break
							else:
								print(color["red"]+"Your confirmation password is different than your initial password. Let's try this again.")	
						else:
							print(color["yellow"]+"Please enter a password longer than 8 characters.")
							
					self.config["private-key"]=self.private_ecdsa_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,
								encryption_algorithm=serialization.BestAvailableEncryption(passwd))
					passwd=None 
					confirm=None
			else:
				
				
				while True:
					try:
						passwd=getpass.getpass("Enter your private key password:")
						pkey=serialization.load_pem_private_key(str(crypto_config["private-key"]),passwd,self.backend)
						break
					except (ValueError,TypeError) as e:
						print(color["red"]+"Unable to decrypt your private key with the supplied password.")
						continue
						
				passwd=None
				
				if not None is pkey:
					self.private_ecdsa_key=pkey
					self.public_ecdsa_key=pkey.public_key()
				else:
					print(color["red"]+"Not good! Unable to load your private key")
					sys.exit(1)	
					
			self.load_keys()
		
			if not None is self.private_ecdsa_key and not None is self.public_ecdsa_key:
					self.ready=True
		except Exception as e:
			print(color["red"]+"Exception encountered while initializing Crypto")
			print(traceback.print_exc())
													
	def dump_keys(self): #dispalys trusted public key info
		print(color["yellow"]+"The following public keys have been trusted by you. Downloads signed by the holders of the corresponding private keys will be accepted and trusted:")
		for keystring in self.trusted_keys:
			self.showkey(json.loads(keystring))
			
	'''
		new line separated json encoded public key info				
		any key found in the trusted_keys file is valid for signing download catalogs
	'''
	def load_keys(self,showkeys=False):
		os.chown(self.trusted_keys_path,os.getuid(),os.getgid()) #make sure the current user owns this file. 
		os.chmod(self.trusted_keys_path,0o0600) #owner read/write,nobody else can rwx it.
		with open(self.trusted_keys_path,"r") as tf:
			for line in tf.read().splitlines():
				if len(line.strip())>0 and line.strip()[0] != "#":
					try:
						self.trusted_keys.add(line.strip())
					except Exception as e:
						print(color["red"]+"Error loading:"+line)
						print(traceback.print_exc())
						continue	
		if showkeys==True:				
			self.dump_keys()
			
	def showkey(self,keydict,showsig=False):
		info=''
		info+='----------------- IDENTITY -----------------\n'
		
		if 'name' in keydict:
			info+=color["yellow"]+"Associated Name: "+keydict['name']+"\n"
		if 'url' in keydict:
			info+=color["yellow"]+"Associated URL: "+keydict['url']+"\n\n"
		if 'description' in keydict:
			info+=color["blue"]+"Description:\n"+keydict['description']+"\n"
		if showsig==True and 'signature' in keydict:
			info+=color["red"]+"Download-specific Signature:\n'"+keydict['signature']+"'\n"	
		if 'public-key' in keydict:
			info+=color["red"]+"Public key:\n"+keydict['public-key']
		info+='----------------- IDENTITY -----------------\n'
		
		print(info)
		
		''' istrustedkey:
			For a key to be trusted a public key and associated information with the follwing properties need to be true:
				1) The public key itself
				2) The name associated with the public key (case insensitive)
				3) The URL associated with the public key (also case insensitve)
			When the user trusts a public key,they are verifying primarily the association of #1 with #2 and #3. 
			This also prevents trusted key holders from signing as other trusted key holders.
			
			If all paramters match True is returned.
			If the public key is found but corresponding paramters don't match - False is returned
			If the public key is not found None is returned
		'''				
	def istrustedkey(self,key_info):
		self.load_keys()
		for keystring in self.trusted_keys:
			trusted_key_info=json.loads(keystring)
			if (trusted_key_info["public-key"].strip() == key_info["public-key"].strip() and 
				trusted_key_info["name"].strip().lower() == key_info["name"].strip().lower() and
				 trusted_key_info["url"].strip().lower() == key_info["url"].strip().lower()):
				return True
			elif trusted_key_info["public-key"].strip() == key_info["public-key"].strip():
				return False	
		return None
		
	def confirmandtrust(self,keyinfo):
		print(color["red"]+'''
An unknown and untrusted key was found. The details of the key are below. *CAREFULLY* inspect the name,description and the contents of the associated URL.")
When you have verified and trusted this public key, type 'TRUSTED-KEY' as printed without quotes and it will be added to your trusted key list at '''+self.trusted_keys_path+'''
Enter blank or any other value if you do not trust this key:

''')
		self.showkey(keyinfo)
		
		choice=raw_input(color["red"]+"Do you trust this public key?\n")

		if choice.strip() == "TRUSTED-KEY":
			os.chown(self.trusted_keys_path,os.getuid(),os.getgid()) #make sure the current user owns this file. 
			os.chmod(self.trusted_keys_path,0o0600) #owner read/write,nobody else can rwx it.
			self.trusted_keys.add(json.dumps(keyinfo))
			with open(self.trusted_keys_path,"war+") as tf:
				tf.write("\n"+json.dumps(keyinfo,sort_keys=True))
				
			print(color["green"]+"Great! It has been added to your list of trusted keys")
			return True

		else:
			print(color["blue"]+"Good job verfying this public key. It will not be trusted or added to your trusted key list")
			return False
	
	def ecdsa_sign(self,hash_algorithm,data):
		try:
			if not None is self.private_ecdsa_key and not None is data and len(data)>0:
				signature=self.private_ecdsa_key.sign(data,ec.ECDSA(hash_algorithm))
				if None is signature or len(signature)<1:
					print(color["red"]+"ecdsa_sign error bad signature value")
					raise ValueError("ecdsa_sign error bad signature value")
					return None
				else:
					return signature
			else:
				print(color["red"]+"ecdsa_sign error private_key or data value error")
				raise ValueError("ecdsa_sign error private_key or data value error")
				return None	
		except Exception as e:
			print(color["red"]+"ecdsa_sign error")
			print(traceback.print_exc())
			return None		
		
	def ecdsa_verify(self,serialized_public_key,signature,hash_algorithm,data):
		
		try:
			public_ecdsa_key=serialization.load_pem_public_key(str(serialized_public_key),backend=self.backend)
			v=None
			if not None is public_ecdsa_key:
				v=public_ecdsa_key.verifier(signature, ec.ECDSA(hash_algorithm))
				if None is v:
					raise ValueError("ecdsa_verify_error bad verifier")
					return False
				v.update(data)
				v.verify()
				return True
			else:
				print(color["red"]+"ecdsa_verify error - no public key set")
				raise ValueError("ecdsa_verify error - no public key set")
				print(traceback.print_exc())
				return False
			
			
			return False
				
		except InvalidSignature as e:
			print(color["red"]+"ecdsa_verify error")
			return False
			
				
	def ecdsa_keygen(self):
		try:
			pkey=ec.generate_private_key(self.ec_curve,self.backend)
			if not None is pkey:
				self.private_ecdsa_key=pkey
				self.public_ecdsa_key=pkey.public_key()
				return True
			else:
				print(color["red"]+"ecdsa_keygen error")
				return False
			return False	
		except Exception as e:
			print(color["red"]+"ecdsa_keygen error")
			print(traceback.print_exc())
			return False
		return False				
				
	def verify_and_load(self,content):
		content_d=json.loads(content.strip())
		siginfo=content_d["siginfo"]
		data=content_d["data"]
		verify=False
		
		trusted=self.istrustedkey(siginfo)
		
		if trusted==True:
			verify=True
		elif trusted==False:
			print(color["red"]+'''
Unable to verify the authenticity of the public key that signed this download
The public key used to sign this download was found,however the name or URL associated with this same public key you trusted are not matching up.
This might be a malicious party attempting to sign packages by pretending to be someone you trust. Please investigate this (or seek help in doing so).
			''')
			verify=False
			
		else:
			print(color["red"]+"Unable to verify the authenticity of the public key that signed this download")
			if self.confirmandtrust(siginfo)==True:
				verify=True
			else:
				verify=False
		if verify==True:
			if not siginfo["hash-algorithm"] in self.hash_algorithms:
				print(color["red"]+"Unsupported hash algorithm used in signature.")
				return None
			
			if self.ecdsa_verify(siginfo["public-key"],base64.b64decode(siginfo["signature"]),self.hash_algorithms[siginfo["hash-algorithm"]],str(data))==True:
				return data,siginfo
		else:
			return None,None	
					
		return None,None
		
	def sign_and_export(self,content):
		if not type(content) is str or len(content.strip())<1:
			return None
			
		hash_algorithm=self.hash_algorithms[self.hash_algorithm]
		signature=self.ecdsa_sign(hash_algorithm,content)
		pubkey=self.private_ecdsa_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
		
		if None is signature or None is pubkey or len(signature.strip())<32 or len(pubkey)<32:
			return None
			
		export={"data":str(content),
				"siginfo":{
					"public-key":pubkey,
					"signature":base64.b64encode(signature),
					"hash-algorithm":self.hash_algorithm,
					"name":self.name,
					"url":self.url,
					"description":self.description
					}
				}
		
		return export
			
					
