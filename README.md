# lfs (local_file_send)

`lfs` is a small proof of concept to make file exchange on a local network as simple as possible.
The only thing necessary is to pass on a few keywords and the transfer will happen automatically, in a somewhat secure way, between two device on the same network.

## How it works

Discovery of the host, serving the file, is done via zeroconf.
The service type is `_lfs._tcp.local.`.
To identify the correct serving host, the first keyword is used, resulting in a service name of `<first-keyword>._lfs._tcp.local.`.

The data exchange is done in an encrypted fashion.
The remaining keywords are fed into `scrypt` and the result, in combination with a random 32 byte salt and 16 byte nonce, generates a `AES-256` key, which will be used in `GCM` for communication between the peers.

## Usage

Send a file:
```shell
$ python lfs.py <file-to-send>
[*] Share keywords: watermark-rattles-troll-inch
[...]
```

Receive the file:
```shell
$ python lfs.py
Please enter the magic keywords: watermark-rattles-troll-inch
[*] Starting file transfer
[*] File successfully received
[❤] Thanks for using LFS
```

Customization options:
```
usage: lfs.py [-h] [-a] [-i INTERFACE] [-k KEYWORDS] [-o OUTFILE] [-p PORT] [file]

positional arguments:
  file                  File to be transferred. Receiving mode if omitted.

optional arguments:
  -h, --help            show this help message and exit
  -a, --ask             Ask before accepting file transfer.
    -c KEYWORD_COUNT, --keyword-count KEYWORD_COUNT
                        Number of keywords to use, if automatically generated (default: 4).
  -i INTERFACE, --interface INTERFACE
                        Interface to use for file transfer (only used for file serving and IPv6).
  -k KEYWORDS, --keywords KEYWORDS
                        Keywords to use for exchange, delimited with '-'. At least two keywords are required.
  -o OUTFILE, --outfile OUTFILE
                        File received data should be stored in (default: served file name).
  -p PORT, --port PORT  Port to listen on (only used for file serving) (default: 12345).
```

# Installation

The script is written in python and the requirements can be installed via:
```shell
pip install -r requirements.txt
```
