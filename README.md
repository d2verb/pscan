# pscan - a simple port scanner
pscan is a simple port scanner. not working. Tested on Linux (container on macOS). Doesn't work on macOS.

## Installation
```
$ poetry build
$ pip install ./dist/pscan-0.1.0-py3-none-any.whl
```

## Usage
```
$ pscan -t 172.217.175.67 -p 0-1023
Scanning 172.217.175.67...
110/pop3 : open
143/imap2 : open
80/http : open
443/https : open
110/pop3 : open
```

## LICENSE
MIT