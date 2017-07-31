#!/usr/bin/python2.7
#manage-downloads - adds/removes downloads to the catalogue
#TODO:
#	test it all \0/

import os,json,sys
import hashlib,uuid

from downloadhygeine import DownloadHygeine,Util,crypto

color={"green":"\33[92m","blue":"\33[96m","red":"\33[31m","yellow":"\33[93m","white":"\33[98m"}

def add(dh):
	download={}
	fname=''
	
	download["uuid"]=str(uuid.uuid4())
	download["name"]=raw_input("Name for this download: ")
	download["category"]=raw_input("What category is this download under?: ")
	download["type"]=raw_input("What type of a download is this? (e.g.:torrent,iso,tar,img,avi,etc...): ")

	
	torrent=dh.util.yesno_choice("Is this a bittorrent download?: ")
	if torrent:
		download["torrent"]=1
	else:
		download["torrent"]=0
	while True:	
		download["url"]=""
		retry=False
		if retry==False:
			download["url"]=raw_input(color["white"]+"Enter the primary URL for this download (This will be used to download and calculate the hash of the downloaded file):")
		fname,success=dh.fetch(download["url"])
		if not os.path.exists(fname) or os.path.getsize(fname)<1:
			print(color["red"]+"It seems downloading this file to: "+fname+" Has failed\nLet's try this again.")
			if dh.util.yesno_choice(color["yellow"]+"Use the same url as before ("+download["url"]+")?")==True:
				retry=False
		else:
			break
	if len(download["url"])<0:
		print(color["red"]+"Unable to find a valid download URL,exiting...")
		return #whoa!?
	else:
		if dh.util.yesno_choice(color["white"]+"Are there other accompanying meta-files that should be downloaded? (example: .asc gpg detached signature,hash data,readme,etc...) : "):
			metafiles=[]
			download["getmeta"]=0
			print(color["yellow"]+"Enter the URLs for these additonal meta-files,separated by a new line. enter 'eof' without quotes when done. Keep in mind the validity of these URLs will not be checked at this time.")
			while True:
				entry=raw_input().strip().split(" ")
				if entry[0].strip().lower() =='eof':
					break
				elif len(entry[0])>0:
					metafiles.append(entry[0])
			if len(metafiles)>0:
				download["getmeta"]=1		
				download["metafiles"]=metafiles
		else:
			download["getmeta"]=0
			
	print(color["blue"]+">")		
	hl=set()
	for algo in hashlib.algorithms_available:
		if algo in ["sha512","sha256","whirlpool","ripemd160"]:
			hl.add(hashlib.new(algo))
	with open(fname,"rb") as f:
		sofar=0
		total=os.path.getsize(fname)
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
	for h in hl:
		digest=h.hexdigest()
		print("\t Calculated "+h.name+" digest:\t "+digest)
		download[h.name]=digest
	
	mirrors=[]
	if dh.util.yesno_choice("Will this download use mirrors?"):
		suffix=raw_input(color["yellow"]+"What is the suffix to be used across all mirrors?\nExample: A suffix of '/mirrors/project/iso/someos.iso' for a mirror 'https://www.fancymirror.co.example/opensource/mirrors' will result in a download URL 'https://www.fancymirror.co.example/opensource/mirrors/mirrors/project/iso/someos.iso'\n:")
		print(color["yellow"]+"Enter a list of mirrors with the format 'Mirrorname <url>' (example:superfastmirror https://secureserver.com.example/)\nEnter just 'EOF' without quotes when done:")
		while True:
			entry=raw_input().strip().split(" ")
			if entry[0].strip().lower() =='eof':
				break
				
			if len(entry) <2 or len(entry[0])<1 or len(entry[len(entry)-1])<1:
				print(color["red"]+"Invalid entry, please be sure to specify the mirror name and the URL")
				continue
			else:
				mirrors.append({"mirrorname":entry[0].strip(),"url":entry[1].strip()+suffix.strip()})
	if len(mirrors)>0:
		download["mirrors"]=mirrors
	if (dh.util.yesno_choice("Have you verified the autenticity of the downloaded file '"+fname+"' ? (such as with GPG validation)?") and 
		dh.util.yesno_choice("Sign this download? ")):	
		content=json.dumps(download,sort_keys=True)
		exported=dh.crypto.sign_and_export(content)
		exportme=json.dumps(exported,indent=4,sort_keys=True)	
		with open(dh.conf["localclone"]+"/"+download["name"]+".json","w+") as df:
			df.write(exportme)
		
def remove(dh):
	dh.load_catalog()
	download_choice=dh.pick()
	for e in dh.catalog:
		if "uuid" in e and e["uuid"]==download_choice:
			print(color["green"]+"Download name: "+e["name"])
			print(color["green"]+"Category: "+e["category"])
			print(color["yellow"]+"File type: "+e["type"])
			print(color["blue"]+"Download URL: "+e["url"])				
			if dh.util.yesno_choice(color["yellow"]+"Remove this download catalog entry? "):
				os.remove(dh.conf["localclone"]+"/"+e["name"]+".json")
				
def gitupdate(dh):
	success=False
	print(color["yellow"]+"Synchronizing download catalog...")	
	if os.path.exists(dh.conf["localclone"]):
		os.chdir(dh.conf["localclone"])
		if dh.util.call(["git","add","*"])!=0:
			print(color["red"]+"Error running 'git add *' to update the local clone. Please fix this manually.")
			success=False
		else:
			if dh.util.call(["git","commit","-m","Sync catalog changes","*"])!=0:
				print(color["red"]+"Error running 'git commit -m 'Sync catalog changes' . Please fix this manually.")	
				success=False
			else:
				if dh.util.call(["git","push","-u","origin","master"])!=0:
					print(color["red"]+"Error running 'git push -u origin master' . Please fix this manually.")	
					success=False
				else:
					success=True
	if success==True:
		print(color["blue"]+"Updated your catalog changes to the preset git repository")
		
	return success
						
def update(dh,uuid=None):
	dh.load_catalog()
	download_choice=dh.pick(uuid=uuid)
			
	for e in dh.catalog:
		if "uuid" in e and e["uuid"]==download_choice:
			dh.crypto.showkey(e["siginfo"])
			print(color["green"]+"Download name: "+e["name"])
			print(color["green"]+"Category: "+e["category"])
			print(color["yellow"]+"File type: "+e["type"])
			print(color["blue"]+"Download URL: "+e["url"])		
			
			params=[]
			for p in e:
				if not str(p).strip() in ["siginfo"]:
					params.append(p)
			params.append("Done")
			while True:		
				choice=dh.util.numeric_choice(color["yellow"]+"Please select a paramter to update for "+e["name"]+".Select 'Done' when finished: ",params)
				if choice=="Done":
					break
				else:
					print(color["yellow"]+"Current value for "+choice+":\n"+str(e[choice]))
					e[choice]=raw_input("["+e["name"]+"] Please enter a new value for '"+choice+"' : ")
			if dh.util.yesno_choice("Now that you've updated '"+e["name"]+"', Would you like to re-download the file and update it's hash values? ")==True:
				while True:	
					fname=dh.fetch(e["url"])
					if not os.path.exists(fname) or os.path.getsize(fname)<1:
						print("It seems downloading this file to: "+fname+" Has failed\nLet's try this again.")
					else:
						break
						
				hl=set()
				for algo in hashlib.algorithms_available:
					if algo in ["sha512","sha256","whirlpool","ripemd160"]:
						hl.add(hashlib.new(algo))
				with open(fname,"rb") as f:
					sofar=0
					total=os.path.getsize(fname)
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
				for h in hl:
					digest=h.hexdigest()
					print("\t Calculated "+h.name+" digest:\t "+digest)
					e[h.name]=digest
					
					
			if (dh.util.yesno_choice("Have you verified the autenticity of the hashes for the download '"+e["name"]+"' ? (such as with GPG validation)?") and 		
				dh.util.yesno_choice("Sign this download? ")):	
				
				exportme=json.dumps(dh.crypto.sign_and_export(json.dumps(e,sort_keys=True)),indent=4,sort_keys=True)	
				with open(dh.conf["localclone"]+"/"+e["name"]+".json","w+") as df:
					df.write(exportme)
			break							
	
def fork(dh):
	dh.load_catalog()
	download_choice=dh.pick()
	if None is download_choice or len(dh.catalog)<0 or len(download_choice)<0:
		print(color["yellow"]+"Current download catalog is empty,nothing to fork.")
		return
			
	for e in dh.catalog:
		if "uuid" in e and e["uuid"]==download_choice:
			dh.crypto.showkey(e["siginfo"])
			print(color["green"]+"Download name: "+e["name"])
			print(color["green"]+"Category: "+e["category"])
			print(color["yellow"]+"File type: "+e["type"])
			print(color["blue"]+"Download URL: "+e["url"])
			e["name"]=raw_input("Forking '"+e["name"]+"' Please enter a new name: ")
			e["uuid"]=str(uuid.uuid4())

			exportme=json.dumps(dh.crypto.sign_and_export(json.dumps(e,sort_keys=True)),indent=4,sort_keys=True)	
			with open(dh.conf["localclone"]+"/"+e["name"]+".json","w+") as df:
				df.write(exportme)
					
			dh.load_catalog()		
			update(dh,e["uuid"])
			
def main():
	dh=DownloadHygeine()
	if not dh.init_env():
			print("Critical error initializing. Exiting immediately.")
			sys.exit(1)
	if not dh.util.yesno_choice("Do you have commit priviledge for the currently configured git repository? "+dh.conf["localclone"]+"\n Remote repository:'"+dh.conf["gitrepo"]+"' ?"):
		if dh.util.yesno_choice("Things will break if we continue to change the currently configured repository.\nIn order to avoid that, should we configure a new repository? (This new repository will be managed by you!) "):
			dh.conf["gitrepo"]=raw_input("Enter the remote URL that will be used to synchronize this new repository: ")
			if dh.util.yesno_choice("Use a different local directory for this new catalog? (Warning: if you pick no,the current contents of "+dh.conf["localclone"]+" Will be deleted.): "):
				dh.conf["localclone"]=dh.util.numeric_choice_flexible("Where should the download catalogue be stored?",[os.getenv('HOME')+"/Downloads/downloadhygeine-catalog",os.getenv('HOME')+"/downloadhygeine-catalog"])
			dh.util.call(["rm","-rfv",dh.conf["localclone"]]) #wipe out the current catalog.
			if dh.util.call(["git","init",dh.conf["localclone"]])!=0:
				print(color["red"]+"Error initializing the chosen git repository of the download catalog. Please make sure the local clone directory '"+dh.conf["localclone"]+"' can be created by git and whether your internet connection is allowing access to your chosen git repository.")
				print(color["red"]+"Alternatively, please adjust your configuration to relfect any system or network changes.")
				sys.exit(1)
			else:
				os.chdir(dh.conf["localclone"])
				if dh.util.call(["git","remote","add","origin",dh.conf["gitrepo"]])!=0:
					print(color["red"]+"Failed to run 'git remote add origin "+dh.conf["gitrepo"]+"' . Please fix this manually.")
					sys.exit(1)
				else:
					if dh.util.call(["git","fetch"])!=0:
						print(color["red"]+"Failed to run 'git fetch' . Please fix this manually.")
						sys.exit(1)
					else:
						if dh.util.call(["git","checkout","master"])!=0:
							print(color["red"]+"Failed to run 'git checkout master' . Please fix this manually.")
							sys.exit(1)
						
								
		else:
			print(color["red"]+"Sorry, you cannot manage a catalog(git repository) without being able to commit to it")
			sys.exit(1)
			
			with open(dh.util.pickpath(dh.config_paths),"w+") as cf:
				cf.write(json.dumps(dh.conf,indent=4,sort_keys=True))
	while True:		
		dh.gitsync()		
		choice=dh.util.numeric_choice("What would you like to do?",["Add","Remove","Update","Fork","List","Exit"])
		if choice=="Add":
			add(dh)
		elif choice=="Remove":
			remove(dh)
		elif choice=="Update":
			update(dh)
		elif choice=="Fork":
			fork(dh)
		elif choice=="List":
			dh.load_catalog()
			dh.dump_catalog()	
		elif choice=="Exit":
			break	
		gitupdate(dh)	
		
if __name__ == "__main__":
	main()
