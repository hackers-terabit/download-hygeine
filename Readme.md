# Download-Hygeine - a clean and safe way to download

### *Warning - This project has not undergone peer-review and the current version is'alpha'  (development) release*

## Demo

[![asciicast](https://asciinema.org/a/87TnA5y3WLA574CcvD3OkytcB.png)](https://asciinema.org/a/87TnA5y3WLA574CcvD3OkytcB)


## About

Download Hygeine tries to solve the problem of securely downloading anything.
Be it a software installation cd file,an archive or movies. 

Currently when downloading something like an installation CD (linux distros for example), user's have to find download-specific instructions on how to validate the download's authenticity (if they're lucky and find one). Users are also expected to know how to properly validate the authenticity of downloads with GPG , matter of fact most average users (linux or windows) don't even consider this step worthy of an effort. 

Download Hygeine allows one trusted user(could be the publisher of the content) to make the effort of properly authenticating the package and maintain a catalog of downloads in a git synchronized repsitory. 

Users only have to trust the maintainer of this repository once. All downloads (json formatted meta-data) are authenticated using ```ECDSA``` signatures which are unique per-download. The integrity of the download is also validated using all available hash algorithms. Change tracking using git allows some transparency as well.

Security aside, it is a nifty way to keep track of your downloads and share them with the world. 

## Requirments 

Currently you need to have git, wget(or curl - more download tools to be supported in the future), python2.7 and python package [cryptography](https://cryptography.io/) are required for Download Hygeine to work. 

To install cryptography use your system's package manager or run:

```
pip install cryptography
```

## Usage

Command-line options are currently unsupported (will be by 0.1 release).
Interactive prompts will give you instructions as you operate the program. 

The following command will run the main application - run this first to setup your configuration.

```
python2.7 downloadhygeine.py
```

The following command will bring up the download manager, it will allow you to add downloads,update existing downloads,fork existing downloads or remove them. 
This also uses an interactive prompt:

```
python2.7 manage-downloads.py
```

Since it is currently under development, no setup or system installation exists.

## TODO

* multiple git repos
* mostly non-interactive command line operations
* gpg auto-validation - ugh, no one uses consistent means of signing stuff. back-burner! :'(
* once gpg is supported,allow per-source authenticators
* test mirrors - untested feature currently
* least latency mirror pick

