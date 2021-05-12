# lfs (local_file_send)

`lfs` is a small proof of concept to make file exchange on a local network as simple as possible.
The only thing necessary is to pass on a few keywords and the transfer will happen automatically, in a somewhat secure way, between two device on the same network.

## How it works

Discovery of the host, serving the file, is done via zeroconf.
The service type is `_lfs._tcp.local.`.
To identify the correct serving host, a SHA224 hash, based on the provided keywords, is used as part of the service name: `<hash>._lfs._tcp.local.`.

The data exchange is done in an encrypted fashion.
The keywords are based on BIP-0039 (https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki).
The underlying entropy is then used as password with PBKDF2, plus a randomly generated salt, which will be passed on before transmission.
The encryption is based on the `Fernet` (https://github.com/fernet/spec/blob/master/Spec.md) implementation from the `cryptography` python library (https://github.com/pyca/cryptography).
`Fernet` is based on AES in CBC mode with a 128-bit key for encryption, using PKCS7 padding and 
HMAC using SHA256 for authentication.

The exchange format is:
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             salt              |    length     |               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               |
|                                                               |
|                         encrypted data                        |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
**salt**: Byte sequence used for PBKDF2 key derivation.\
**length**: Payload length of encrypted data.

## Usage

Send a file:
```shell
$ python lfs.py <file-to-send>
[*] Share keywords: leg stage viable
[...]
```

Receive the file:
```shell
$ python lfs.py
Please enter the magic keywords: leg stage viable
[*] Starting file transfer
[*] File successfully received
[❤] Thanks for using LFS
```

Customization options:
```
usage: lfs.py [-h] [-a] [-s STRENGTH] [-i INTERFACE] [-k KEYWORDS] [-o OUTFILE] [-p PORT] [file]

positional arguments:
  file                  File to be transferred. Receiving mode if omitted.

optional arguments:
  -h, --help            show this help message and exit
  -a, --ask             Ask before accepting file transfer.
  -s STRENGTH, --strength STRENGTH
                        Amount of entropy to use for key derivation. Results in strength×3 key
                        words (default: 1).
  -i INTERFACE, --interface INTERFACE
                        Interface to use for file transfer (only used for file serving and IPv6).
  -k KEYWORDS, --keywords KEYWORDS
                        Keywords to use for exchange, delimited with '-' or space. (Multiples of 3
                        and need to conform to BIP039.)
  -o OUTFILE, --outfile OUTFILE
                        File received data should be stored in (default: served file name).
  -p PORT, --port PORT  Port to listen on (only used for file serving) (default: 12345).
```

# Installation

The script is written in python and the requirements can be installed via:
```shell
pip install -r requirements.txt
```

# Note:

For a client to use the IPv6 link-local address of the server, it needs to specify the interface explicitly, otherwise announced link-local addresses will be skipped.
