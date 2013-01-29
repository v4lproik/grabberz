# GrabberZ

GrabberZ is a small python script which is capable of extracting metadata from files, downloaded from search engines.
Only google hack has been implemented, atm.

The purpose of coding this little script was to be able to gather as much information as possible
from a domain name during the reco/enu pentest step.

The file types supported for metadata (version 1.0) are the ones supported from :
* hachoir core (https://bitbucket.org/haypo/hachoir/wiki/hachoir-parser)
* pdf
* ole2
...

It supports :
* pdf decryption
* A fairly good list of file types
* Open files trying to extract emails, mac addresses, ip addresses...

Feel free to fork it...


## Pre-Installation Libraries
```
python-beautifulsoup
python-hachoir-core
python-hachoir-parser
python-hachoir-metadata
```

## Installation

No installation required

## Execution
```
	|----------------------------------------------------------|
	|                        GrabberZ  1.0                     |
	|                           v4lproik                       |
	|----------------------------------------------------------|

usage: extractor.py [-h] -d DOMAIN -t TYPE -p PATH [-l LIMIT] [-s SOCKS]
                    [-o OUTPUT]

optional arguments:
  -h, --help            show this help message and exit

Main arguments:
  -d DOMAIN, --domain DOMAIN
                        Domain to check
  -t TYPE, --type TYPE  File types' pdf, ppt, pptx...
  -p PATH, --path PATH  Directory where found files are stored (Need
                        Read/Written permissions)

Other arguments:
  -l LIMIT, --limit LIMIT
                        limit results
  -s SOCKS, --socks SOCKS
                        use a proxy type sock (ex: 127.0.0.1:5678)
  -o OUTPUT, --output OUTPUT
                        output in file .html
```

```
./grabberz.py -d <domain> -t ppt,pptx,odp,odt,pdf,doc,docx -p output/domain/ -l 10
```

## Todo List

* Expanding type files support
* Generic regex to extract author/creator of a script (corp. dev info)
* Bing search engine implementation
* Html output
