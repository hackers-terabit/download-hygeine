#!/usr/bin/python2.7
'''
DownloadHygeine - Fetch software and other media safely and easily. 

TODO:
	multiple git repos
	mostly non-interactive command line operations
	gpg - ugh, no one uses consistent means of signing stuff. back-burner! :'(
	once gpg is supported,allow per-source authenticators
	test mirrors
	least latency mirror pick
'''
import subprocess
import os
import time
import re
import json
import sys
import traceback
import hashlib
import random
from subprocess import Popen

import crypto

color={"green":"\33[92m","blue":"\33[96m","red":"\33[31m","yellow":"\33[93m","white":"\33[98m"}
		
class Util:

	def pickpath(self,pathlist):
		if not type(pathlist) is list:
			raise ValueError("Util.pickpath was passed a non-list argument")
			return None
		for p in pathlist:
			path=os.path.abspath(p)
			if os.path.exists(path):
				return path
		return None
		
	def numeric_choice(self,prompt,options):
		oldprompt=prompt
		while True:
			prompt=color["white"]+prompt
			i=0
			for o in options:
				i=i+1
				prompt+="\n\t"+color["green"]+"["+color["yellow"]+str(i)+color["green"]+"]  "+color["white"]+o
			prompt+="\n"
			choice=raw_input(color["white"]+prompt)	
			try:
				if len(choice)>0 and int(choice) > 0 and int(choice) < len(options)+1:
					return options[int(choice)-1]
				raise ValueError("Invalid option")
			except ValueError:
				print(color["red"]+"Not a valid number,try again.")
				prompt=oldprompt
				continue
				
	def numeric_choice_flexible(self,prompt,options):
		oldprompt=prompt
		while True:
			prompt=color["white"]+prompt
			i=0
			for o in options:
				i=i+1
				prompt+="\n\t"+color["green"]+"["+color["yellow"]+str(i)+color["green"]+"]  "+color["white"]+o
			prompt+="\nPick one of these selections or specify a different configuration:"
			choice=raw_input(color["white"]+prompt)	
			try:
				if len(choice)>0 and choice.strip().isdigit() and int(choice) > 0 and int(choice) < len(options)+1:
					return options[int(choice)-1]
				elif len(choice.strip())>0:
					return choice
					
				raise ValueError("Invalid option")
			except ValueError:
				print(color["red"]+"Not a valid number,try again.")
				prompt=oldprompt
				continue
				
	def yesno_choice(self,prompt):
		yes=["y","yes","catsareweird","yeah","yup"]
		no=["no","nope","n","getoffmylawn"]
		while True:
			choice=raw_input(color["yellow"]+prompt+"["+color["green"]+"Y"+color["yellow"]+"/"+color["red"]+"N"+color["yellow"]+"]:")
			if choice.lower() in yes:
				return True
			elif choice.lower() in no:
				return False
			else:
				print(color["red"]+"Invalid option, please pick yes or no.\n"+color["white"]+">")
				
	def clear(self):
		print("\033[H\033[J")
					
	def mkdirs(self,path):
		try:
			print(color["white"]+"Creating directory tree '"+path+"'")
			#os.makedirs(path)  
			self.call(["mkdir","-vp",path])
			if os.path.exists(path):
				return True
			else:
				print(color["red"]+"Executed os.makedirs however the path still does not exist.")
				return False
		except Exception as e:
			print(color["red"]+"Error creating directory tree:"+path)
			return False 
			
	def which(self,program):
		try:
			p=subprocess.Popen(['which',program],shell=False,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
			stdo,stde=p.communicate()
			if p.returncode==0:
				return stdo.splitlines()[0] 
			else:
				return None	
		except Exception as e:
			print(traceback.print_exc())
			return False	
			
	def call(self,cmdlist):
		try:
	
			ret=subprocess.call(cmdlist,shell=False)
			return ret
			
		except Exception as e:
			print(color["yellow"]+"Exception while executing '"+str(cmdlist)+"'")
			return -1
						
class DownloadHygeine:
	def __init__(self):
		self.config_paths=[os.getenv('HOME')+"/.config/downloadhygeine",os.getenv('HOME')+"/.downloadhygeine","/etc/downloadhygeine.config","./downloadhygeine.config"]
		self.conf={}
		self.catalog=[]
		self.util=Util()
		self.suppressed_entries=set()
		
	def loadconfig(self,config):
		if not type(config) in [str,unicode]:
			return False
		try:
			cnf={}
			os.chown(config,os.getuid(),os.getgid()) #make sure the current user owns this file. 
			os.chmod(config,0o0600) #owner can read/write(-exec),nobody else can rwx it.
			with open(config,"r") as cf:
				cnf=json.loads(cf.read().strip())
			self.conf=cnf	
			if not os.path.exists(self.conf["downloads"]) and not self.util.mkdirs(self.conf["downloads"]):
				print(color["yellow"]+"Warning,unable to find your 'downloads' directory,attempting to recreate it has also failed.")
			if not os.path.exists(self.conf["localclone"]) and not self.util.mkdirs(self.conf["localclone"]):
				print(color["yellow"]+"Warning,unable to find your 'clone' directory,attempting to recreate it has also failed.")
				#self.gitsync()
				
			print(color["green"]+"Succesfully loaded configuration from: "+config)
			return True	
		except Exception as e:
			print(color["red"]+"Error loading the json configuration file at: "+config)
			print(traceback.print_exc())
			return False
		return False
			
	def init_config(self,config):
		if not 	type(config) is str:
			config=self.util.numeric_choice("Where should the configuration file be saved:",self.config_paths)
		self.conf={}
		'''
		Downloading with system tools is an intentional decision. This is one wheel that will not be re-invented here.
		aria2c and other downloaders will be added here in the future.
		'''
		self.conf["fetchtool"]=self.util.numeric_choice("Which tool should be used to download files:",["curl","wget"])
		self.conf["downloads"]=self.util.numeric_choice_flexible("Where should downloaded files be saved:",[os.getenv('HOME')+"/Downloads/",os.getenv('HOME')+"/",os.getenv('HOME')+"/DownloadHygeine/"])
		self.util.mkdirs(self.conf["downloads"])
		mirrors=self.util.yesno_choice("Do you want downloads to use mirrors? ")
		if mirrors==True:
			self.conf["mirrors"]=1
			self.conf["mirrorselect"]=self.util.numeric_choice("How should download mirrors be chosen?",["Round-Robin","Random"]) #TODO: least latency mirror selection
		else:
			self.conf["mirrors"]=0
			
		if self.util.yesno_choice("Do you want to use a git repository different than https://github.com/hackers-terabit/downloadhygeine-catalog for the download catalog management?"):
			self.conf["gitrepo"]=raw_input("Please enter the URL of a valid git repository: ")
			print(color["green"]+"Got it! Will use "+self.conf["gitrepo"]+" As the download catalog repository."+color["white"]+"\n>")
		else:
			self.conf["gitrepo"]="https://github.com/hackers-terabit/downloadhygeine-catalog"
			print(color["green"]+"Great, will use the default git repository "+self.conf["gitrepo"]+" to manage the download catalog")
			
		while True:
			self.conf["localclone"]=self.util.numeric_choice_flexible("Where should the download catalogue be stored?",[os.getenv('HOME')+"/Downloads/downloadhygeine-catalog",os.getenv('HOME')+"/downloadhygeine-catalog"])		
			if os.path.exists(self.conf["localclone"]):
				break
			elif os.path.exists(os.path.abspath(self.conf["localclone"])):
				self.conf["localclone"]=os.path.abspath(self.conf["localclone"])
				break
			elif self.util.mkdirs(os.path.abspath(self.conf["localclone"])):
				self.conf["localclone"]=os.path.abspath(self.conf["localclone"])
				break
				 	
			else:
				print(color["red"]+"The file system path:"+self.conf["localclone"]+" Does not exist, please enter a different valid path"+color["white"]+"\n>")

		torrents=self.util.yesno_choice("Should torrent downloads be enabled?")
		if torrents:
			self.conf["torrents"]=1
			while True:
				self.conf["torrentapp"]=self.util.numeric_choice_flexible("Where in your filesystem is your torrent application located?",["/usr/bin/rtorrent","/usr/bin/ktorrent","/usr/bin/transmission"])
				if os.path.exists(os.path.abspath(self.conf["torrentapp"])):
					break
				else:
					print("Error, the specified path '"+self.conf["torrentapp"]+"' Does not exist.")
			self.conf["torrentoptions"]=raw_input("What command-line options should be passed to the torrent application? (Leave blank and hit enter if none)\n:")		
			
		else:
			self.conf["torrents"]=0
		
		crypto_config={}
		crypto_config["trusted_keys_path"]=self.util.numeric_choice_flexible(color["green"]+"Where should trusted public keys be stored:",[os.getenv('HOME')+"/.download-hygeine.trusted_keys"])
		with open(crypto_config["trusted_keys_path"],"war+") as f: #check if we can write to this file.
			f.write("")
			
		crypto_config["ECDSA-CURVE"]="secp521r1"
		crypto_config["hash"]="SHA512"
		print(color["blue"]+"This is the current(default) configuration for digital signatures. This configuration will be used to sign and verify download catalogs:\n------------")
		print(color["blue"]+json.dumps(crypto_config,indent=4,sort_keys=True))
		print(color["blue"]+"------------")
		
		if self.util.yesno_choice("Would you like to change any of these paramters? (Pick 'N' unless you know what you are doing here)"):
			choice=self.util.numeric_choice("Select one of the following paramters to change: ",["Signature Hash","ECDSA-CURVE"])
			if choice=="ECDSA-CURVE":
				crypto_config["ECDSA-CURVE"]=self.util.numeric_choice("Pick from one the following availble curves:",list(crypto.Crypto.curvemap))
			elif choice=="Signature Hash":
				crypto_config["hash"]=self.util.numeric_choice("Pick from one the following availble hash algorithms:",list(crypto.Crypto.hash_algorithms))	
				
		self.crypto=crypto.Crypto(crypto_config)
		crypto_config=self.crypto.config
		self.conf["crypto-config"]=self.crypto.config	
		
		try:
			with open(config,"w+") as cf:
				cf.write(json.dumps(self.conf,indent=4,sort_keys=True))
			os.chown(config,os.getuid(),os.getgid()) #make sure the current user owns this file. 
			os.chmod(config,0o0600) #owner read/write,nobody else can rwx it.		
		except Exception as e:
			print(color["red"]+"Error saving the configuration file at: "+config)
			print(traceback.print_exc())
			print(color["white"]+">")
			return
			
		print(color["blue"]+"Finished saving your new configuration. ")
		return
		
	def check_tools(self):
		git=self.util.which("git")
		fetchtool=self.util.which(self.conf["fetchtool"])
		torrentapp=self.util.which(self.conf["torrentapp"])
		
		if None is git:
			raise ValueError("The git executable cannot be found or called. Please install git")
			return False
		else:
			self.conf["git"]=git
				
		if None is fetchtool:
			raise ValueError("The configured tool to fetch remote files cannot be found or executed"+self.conf["fetchtool"])
			return False
		else:
			self.conf["fetchtool"]=fetchtool	
		if self.conf["torrents"] == 1 and None is torrentapp:
			raise ValueError("Torrent downloads configured,however the configured bittorrent client cannot be executed:"+self.conf["torrentapp"])
			return False
		elif self.conf["torrents"] == 1:
			self.conf["torrentapp"]=torrentapp
				
		return True	
		
	def init_env(self):
		defconf=self.util.pickpath(self.config_paths)
		
		if not self.loadconfig(defconf):
			print(color["green"]+"Existing configuration not found. Let's setup one!")
			self.init_config(defconf)
			time.sleep(3)
			self.util.clear()
			
		self.crypto=crypto.Crypto(self.conf["crypto-config"])
		if self.crypto.ready != True:
			print(color["red"]+"Problem while setting up crypto configuration. exiting now!")
			sys.exit(1)
				
		return self.check_tools()	
		
	def curl_fetch(self,url):
		fname=self.conf["downloads"]+"/"+os.path.basename(url)
		p=subprocess.Popen(["curl","-L","--progress-bar",url],shell=False,stdout=subprocess.PIPE)
		
		print(color["blue"]+"Downloading and saving at "+fname+" with curl from "+url+" ....")
		with open(fname,"wb+") as df:
			for b in p.communicate():
				if None is b or len(b)<1:
					break
				df.write(b)
		print(color["white"]+"Finished downloading of "+fname)
		return fname 
			
	def wget_fetch(self,url):
		fname=self.conf["downloads"]+"/"+os.path.basename(url)
		print(color["blue"]+"Downloading and saving at "+fname+" with wget from "+url+" ....")
		self.util.call(["wget","-nv", "--show-progress", "-O",fname,url])
		print(color["white"]+"Finished downloading of "+fname)
		return fname 
		
	def fetch(self,url):
		try:
			if "curl" == os.path.basename(self.conf["fetchtool"]):
				fname=self.curl_fetch(url)			
				return fname,True
			elif "wget" == os.path.basename(self.conf["fetchtool"]):
				fname=self.wget_fetch(url)
				return fname,True
			else:
				print(color["red"]+"Unsupported download program:"+str(self.conf["fetchtool"]))
				return None,None	
		except Exception as e:
			print(color["red"]+"Error downloading "+url)
			print(traceback.print_exc())
			return None,False
			
	def verify_integrity(self,download,fname):
		try:
			hl=set()
			supportedhash=False
			for algo in ["sha512","sha256","whirlpool","ripemd160"]:
				if algo in download:
					supportedhash=True
			if not supportedhash:
				print(color["red"]+"Download catalog for "+download["name"]+" does not have hash algorithm supported on this system")
				return False
				
			for algo in hashlib.algorithms_available:
				if algo in ["sha512","sha256","whirlpool","ripemd160"] and algo in download:
					hl.add(hashlib.new(algo))
			with open(fname,"rb") as f:
				sofar=0
				total=os.path.getsize(fname)
				print("Verifying integrity of downloaded file "+fname)
				while True:
					block=f.read(65536)
					if len(block)<1:
						break
					else:
						sofar+=len(block)
						sys.stdout.write("\rRead so far:\t"+str(sofar/(total/100.00))[:5].ljust(5," ")+"\%")	
					for h in hl:
						h.update(block)
			print("\n")		
			integrity_good=False	
			for h in hl:
				digest=h.hexdigest()
				if digest != download[h.name]:
					print(color["red"]+"Integrity verification failed for "+download["name"]+"\n\tFile: "+fname+"\n\tFound "+h.name+" hash:"+digest+"\n\tExpected hash:"+download[h.name])
					integrity_good=False
				elif digest == download[h.name]:
					print(color["green"]+"Integrity verification ["+h.name+"] is good for "+download["name"]+" ["+fname+"]")
					integrity_good=True
			return integrity_good
					
		except Exception as e:
			print(color["red"]+"Exception while verifying download file integrity")
			print(traceback.print_exc())
			return False
					
	def load_catalog(self):
		flist=set()
		if not os.path.exists(self.conf["localclone"]):
			return False
		fl=os.listdir(self.conf["localclone"])
		if not type(fl) is list or len(fl)<1:
			return False
	
		for f in fl:
			if f.lower()[len(f)-5:] == ".json":
				flist.add(self.conf["localclone"]+"/"+f)
		self.catalog=[]
		for jf in flist:
			with open(jf,"r") as f:
				catalog_dict=None
				content=f.read()
				
				if content in list(self.suppressed_entries):
					break
						
				data,siginfo=self.crypto.verify_and_load(content)
				if type(data) in  [dict,unicode]:
					catalog_dict=json.loads(data)
				if (type(catalog_dict) is dict and type(siginfo) is dict and
					len(catalog_dict)>0 and len(catalog_dict["name"].strip()) > 0 and len(catalog_dict["url"].strip())>0):
					catalog_dict["siginfo"]=siginfo	
					self.catalog.append(catalog_dict)
				else:
					self.suppressed_entries.add(content)
					print(color["red"]+"Error,problem with loading catalog entry:\nData:"+"Content:\n"+str(content))
					self.suppressed_entries.add(content)
					#print(traceback.print_exc())
					return False	
		if len(self.catalog)>0:
			return True
		else:
			return False
						
	def dump_catalog(self):
		for e in self.catalog:
			print(color["green"]+"************************ "+e["uuid"]+" ************************")
			print("Name:"+e["name"])
			print("Category:"+e["category"])
			print("Type:"+e["type"])
			print("URL:"+e["url"])	 
			self.crypto.showkey(e["siginfo"],showsig=True)
			print("\n-----------")
			for h in hashlib.algorithms_available:
				if h in e:
					print("Integrity hash "+h+":"+e[h])
			print(color["green"]+"************************ "+e["uuid"]+" ************************")		
					
	def pick(self,uuid=None):
		categories=set()
		download_choice=None
		if not None is uuid:
			for e in self.catalog:
				if e["uuid"].strip() == uuid.strip():
					return e["uuid"]
			return None		
			
		for e in self.catalog:
			if "category" in e and len(e["category"])>0:
				categories.add(e["category"])
				
		if len(categories)<1:
			print(color["yellow"]+"No categories found. Please make sure your selected catalog has download entries with categories.")
			return None		
		catchoice=self.util.numeric_choice(color["blue"]+"Please select a category: ",list(categories))
		names=[]
		for e in self.catalog:
			
			if "category" in e and catchoice == e["category"]:
				names.append(e["name"]+" - Unique ID: "+e["uuid"])
		if len(names)>0:		
			choice=self.util.numeric_choice(color["yellow"]+"Please select one of these entries under the '"+catchoice+"' category:",names)
			uuid=choice.split(" - Unique ID: ")[1].strip()
			return uuid
		
		
		return uuid
						
	def pick_and_download(self):
		download_choice=self.pick()
		for e in self.catalog:
			if not type(e) is dict:
				continue
			if "uuid" in e and e["uuid"]==download_choice:
				'''
					Something to note here - It is assumed all content that has succesfully been loaded has been authenticated.
					load_catalog() will never load anything that hasn't been authenticated by crypto.verify_and_load()
					All loaded downloads are trusted downloads.
				'''
				self.util.clear()
				print(color["green"]+"This download information (including integrity hashes) was signed by the following identity you have already trusted:\n")
				self.crypto.showkey(e["siginfo"],showsig=True)
				print(color["green"]+"Download name: "+e["name"])
				print(color["green"]+"Category: "+e["category"])
				print(color["yellow"]+"File type: "+e["type"])
				print(color["yellow"]+"Unique ID(UUID): "+e["uuid"])
				print(color["blue"]+"Download URL: "+e["url"])				
				fname=''
				success=False
				lasturl=''
				if self.util.yesno_choice(color["yellow"]+"Download this file in "+self.conf["downloads"]+"? "):
					if "mirrors" in e and len(e["mirrors"])>0:
						if self.conf["mirrorselect"]=="Round-Robin":
							for m in e["mirrors"]:
								print(color["green"]+"Fetching "+e["name"]+" From mirror "+m["mirrorname"]+": '"+m["url"]+"' (round-robin selection)")
								fname,success=self.fetch(m["url"])
								lasturl=m["url"]
								if success:
									break
								else:
									print(color["yellow"]+"Round-Robin mirror download failed for "+e["name"]+" URL: "+lasturl)
						elif self.conf["mirrorselect"]=="Random":
							while True:
								m=random.choice(e["mirrors"])
								print(color["green"]+"Fetching "+e["name"]+" From mirror "+m["mirrorname"]+": '"+m["url"]+"' (round-robin selection)")
								fname,success=self.fetch(m["url"])
								lasturl=m["url"]
								if success:
									break
								else:
									print(color["yellow"]+"Round-Robin mirror download failed for "+e["name"]+" URL: "+lasturl)				
					else:
						fname,success=self.fetch(e["url"])
						if None is fname or None is success:
							print(color["red"]+"Fetching the download failed.")
							continue
						lasturl=e["url"]
										
					if success and not None is fname and len(fname)>0 and self.verify_integrity(e,fname):
						print(color["green"]+"Download of "+e["name"]+" is finished.\nThe downloaded file is saved at '"+fname+"', It was downloaded from the URL '"+lasturl+"' and integrity verification on the downloaded file has passed.")
						if e["torrent"] == 1:
							subprocess.Popen([self.conf["torrentapp"],self.conf["torrentoptions"],os.path.abspath(fname)],shell=False).communicate()
					else:
						os.remove(fname)
						print(color["red"]+"Download of "+e["name"]+" has failed.\nThe URL used in this download attempt is:"+e["url"])
						
				print(color["white"]+"\n>")
				
				break
				
	def gitsync(self):
		print(color["yellow"]+"Synchronizing download catalog ("+self.conf["gitrepo"]+")...")
		if os.path.exists(self.conf["localclone"]) and os.path.exists(self.conf["localclone"]+"/.git"):
			os.chdir(self.conf["localclone"])
			
			if self.util.call(["git","pull"])!=0:
				print(color["red"]+"Error running 'git pull' to update the local clone '"+self.conf["localclone"]+"' of the chosen download catalog. Please fix this manually.")
				print(color["red"]+"Alternatively, please adjust your configuration to relfect any system or network changes.")
				
		elif os.path.exists(self.conf["localclone"]) and not  os.path.exists(self.conf["localclone"]+"/.git"):
			
			if self.util.call(["git","clone",self.conf["gitrepo"],self.conf["localclone"]])!=0:
				print(color["red"]+"Error cloning the chosen git repository of the download catalog. Please make sure the local clone directory '"+self.conf["localclone"]+"' can be created by git and whether your internet connection is allowing access to your chosen git repository.")
				print(color["red"]+"Alternatively, please adjust your configuration to relfect any system or network changes.")
				
		elif self.util.mkdirs(self.conf["localclone"])==True:
			
			if self.util.call(["git","clone ",self.conf["gitrepo"],self.conf["localclone"]])!=0:
				print(color["red"]+"Error cloning the chosen git repository of the download catalog. Please make sure the local clone directory '"+self.conf["localclone"]+"' can be created by git and whether your internet connection is allowing access to your chosen git repository.")
				print(color["red"]+"Alternatively, please adjust your configuration to relfect any system or network changes.")
		else:
			print(color["red"]+"Unable to create the local download catalog clone directory at:"+self.conf["localclone"])		
			
		print(color["white"]+"------------------------------------------")						
		
	def start(self):
		dh=self
		
		if not dh.init_env():
			print("Critical error initializing. Exiting immediately.")
			sys.exit(1)
		self.util.clear()	
		print(color["green"]+"\n\nThank you for using download-hygeine. If you like this project start creating your own catalog or contribute downloads to the default catalog.")
		while True:
			try:
				dh.gitsync()
				if dh.load_catalog()==True:
					choice=self.util.numeric_choice(color["white"]+"What would you like to do? ",["Browse and download something","List all downloads","List all trusted download signers(identities/public-key information)","Exit"])
					if choice=="Browse and download something":
						dh.pick_and_download()
					elif choice=="List all downloads":
						dh.dump_catalog()
					elif choice=="List all trusted download signers(identities/public-key information)":
						self.crypto.dump_keys()
					elif choice=="Exit":
						sys.exit(0)
						
					
				else:
					print(color["red"]+"Error,could not load any items from your download catalog at: "+dh.conf["localclone"])
					time.sleep(3)
					if self.util.yesno_choice(color["red"]+"Retry? ")==False:
						break
			except Exception as e:
				print(color["red"]+"General error")
				print(traceback.print_exc())
				print(color["white"]+">")
				continue
		

if __name__ == "__main__":
	DownloadHygeine().start()
