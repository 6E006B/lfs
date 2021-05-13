#!/usr/bin/env python3

import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
import itertools
from mnemonic.mnemonic import binary_search, Mnemonic
import netifaces
import os
import re
# import readline
import socket
import struct
import sys
from typing import List
from zeroconf import IPVersion, ServiceInfo, Zeroconf


#
# def complete_keyword(self, text, state):
#     print(f"complete({text}, {state})")
#     hits = [w for w in WORD_LIST if w.startswith(text)] + [None]
#     return hits[state]
#
# from os import environ
# def display_keyword_matches(self, substitution, matches, longest_match_length):
#     print(f"display({substitution}, {matches}, {longest_match_length})")
#     line_buffer = readline.get_line_buffer()
#     columns = environ.get("COLUMNS", 80)
#     print()
#     tpl = "{:<" + str(int(max(map(len, matches)) * 1.2)) + "}"
#     buffer = ""
#     for match in matches:
#         match = tpl.format(match[len(substitution):])
#         if len(buffer + match) > columns:
#             print(buffer)
#             buffer = ""
#         buffer += match
#     if buffer:
#         print(buffer)
#     print("> ", end="")
#     print(line_buffer, end="")
#     sys.stdout.flush()


class LFS:

    BUFFER_SIZE = 2**22
    DEFAULT_PORT = 12345
    SALT_SIZE = 16
    SIZE_SIZE = 8
    TYPE_POSTFIX = "_lfs._tcp.local."
    VERSION = "0.1"

    def __init__(self, port: int, iface: str = None, keywords: str = None, strength: int = 4):
        self.zconf: Zeroconf = Zeroconf(ip_version=IPVersion.All)
        self.service_info: ServiceInfo = None
        self.iface: str = iface
        self.port: int = port
        self.transferred: bool = False
        self.keywords = Mnemonic.normalize_string(keywords if keywords is not None else self._generate_keywords(strength))
        self.cipher = None

    def get_cipher(self, salt: bytes = None):
        entropy = self._get_entropy_for_keywords(self.keywords)
        salt = salt if salt else os.urandom(self.SALT_SIZE)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        key = base64.urlsafe_b64encode(kdf.derive(entropy))
        cipher = Fernet(key)
        return salt, cipher

    @staticmethod
    def _generate_keywords(strength: int) -> str:
        assert strength > 0
        mnemo = Mnemonic(language="english")
        entropy = os.urandom(strength*4)
        h = hashlib.sha256(entropy).hexdigest()
        b = (
            bin(int.from_bytes(entropy, byteorder="big"))[2:].zfill(len(entropy) * 8)
            + bin(int(h, 16))[2:].zfill(256)[: len(entropy) * 8 // 32]
        )
        result = []
        for i in range(len(b) // 11):
            idx = int(b[i * 11: (i + 1) * 11], 2)
            result.append(mnemo.wordlist[idx])
        if (
            mnemo.detect_language(" ".join(result)) == "japanese"
        ):  # Japanese must be joined by ideographic space.
            result_phrase = u"\u3000".join(result)
        else:
            result_phrase = " ".join(result)
        return result_phrase

    @staticmethod
    def _get_entropy_for_keywords(keywords: str) -> bytearray:
        language = Mnemonic.detect_language(keywords)
        words = keywords.split()
        mnemo = Mnemonic(language=language)
        concatLenBits = len(words) * 11
        concatBits = [False] * concatLenBits
        wordindex = 0
        if mnemo.detect_language(" ".join(words)) == "english":
            use_binary_search = True
        else:
            use_binary_search = False
        for word in words:
            # Find the words index in the wordlist
            ndx = (
                binary_search(mnemo.wordlist, word)
                if use_binary_search
                else mnemo.wordlist.index(word)
            )
            if ndx < 0:
                raise LookupError('Unable to find "%s" in word list.' % word)
            # Set the next 11 bits to the value of the index.
            for ii in range(11):
                concatBits[(wordindex * 11) + ii] = (ndx & (1 << (10 - ii))) != 0
            wordindex += 1
        checksumLengthBits = concatLenBits // 33
        entropyLengthBits = concatLenBits - checksumLengthBits
        # Extract original entropy as bytes.
        entropy = bytearray(entropyLengthBits // 8)
        for ii in range(len(entropy)):
            for jj in range(8):
                if concatBits[(ii * 8) + jj]:
                    entropy[ii] |= 1 << (7 - jj)
        # Take the digest of the entropy.
        hashBytes = hashlib.sha256(entropy).digest()
        hashBits = list(
            itertools.chain.from_iterable(
                [c & (1 << (7 - i)) != 0 for i in range(8)] for c in hashBytes
            )
        )
        # Check all the checksum bits.
        for i in range(checksumLengthBits):
            if concatBits[entropyLengthBits + i] != hashBits[i]:
                raise ValueError("Failed checksum.")
        return entropy

    @staticmethod
    def get_addresses(iface: str = None) -> List[bytes]:
        addresses = set()
        ifaces = [iface]
        if iface is None:
            ifaces = netifaces.interfaces()
        for iface in ifaces:
            address_families = netifaces.ifaddresses(iface)
            for family, addresses_lists in address_families.items():
                for address_struct in addresses_lists:
                    address = address_struct['addr'].split('%')[0]
                    if family == netifaces.AF_INET:
                        addresses.add(socket.inet_aton(address))
                    elif family == netifaces.AF_INET6:
                        addresses.add(socket.inet_pton(socket.AF_INET6, address))
        return list(addresses)

    def announce(self):
        desc = {'version': self.VERSION}
        addresses = self.get_addresses(self.iface)
        # sha224 is chosen here, because 256 bit is too long for a type name
        announce_prefix = hashlib.sha224(self._get_entropy_for_keywords(self.keywords)).hexdigest()
        self.service_info = ServiceInfo(
            self.TYPE_POSTFIX,
            f"{announce_prefix}.{self.TYPE_POSTFIX}",
            addresses=addresses,
            port=self.port,
            properties=desc)
        self.zconf.register_service(self.service_info)
        # print("[*] Announcing", self.service_info)

    def discover(self):
        prefix = hashlib.sha224(self._get_entropy_for_keywords(self.keywords)).hexdigest()
        type_string = f"{prefix}.{self.TYPE_POSTFIX}"
        info = self.zconf.get_service_info(self.TYPE_POSTFIX, type_string)
        if info is None:
            return None, None
        else:
            return info.parsed_addresses(), info.port

    def renounce(self):
        if self.service_info is not None:
            self.zconf.unregister_service(self.service_info)
            self.service_info = None
            # print("[*] Unregistered announcement")

    def send_data(self, conn: socket.socket, data: bytes):
        assert self.cipher is not None
        encrypted_data = self.cipher.encrypt(data)
        conn.sendall(struct.pack("Q", len(encrypted_data)))
        conn.sendall(encrypted_data)

    def recv_data(self, conn: socket.socket):
        assert self.cipher is not None
        size = struct.unpack("Q", conn.recv(self.SIZE_SIZE))[0]
        encrypted_data = b""
        while len(encrypted_data) < size:
            encrypted_data += conn.recv(min(self.BUFFER_SIZE, size - len(encrypted_data)))
        if len(encrypted_data) != size:
            raise ConnectionError(f"Error: Received incomplete data ({len(encrypted_data)}, but expected {size})")
        return self.cipher.decrypt(encrypted_data)

    def send_init_crypto(self, conn: socket.socket):
        salt, self.cipher = self.get_cipher()
        conn.sendall(salt)

    def recv_init_crypto(self, conn: socket.socket):
        salt = conn.recv(self.SALT_SIZE)
        _, self.cipher = self.get_cipher(salt=salt)

    def send_filename(self, conn: socket.socket, file: str):
        filename = os.path.basename(file)
        data = bytes(filename, "ascii")
        self.send_data(conn, data)

    def recv_filename(self, sock: socket.socket):
        return self.recv_data(sock)

    @staticmethod
    def ask_decision(name: bytes) -> bool:
        print(f"[*] File offered: '{name.decode('ascii')}'")
        print("Continue? (Y/n): ", end="", flush=True)
        response = sys.stdin.read(1)
        return  response in ("y", "Y", "\n")

    def recv_decision(self, conn: socket.socket) -> bool:
        decision = self.recv_data(conn)
        return decision == b"y"

    def send_success(self, conn: socket.socket, success: bool):
        self.send_data(conn, b"y" if success else b"n")

    def recv_success(self, conn: socket.socket) -> bool:
        return self.recv_data(conn) == b"y"

    def send_file(self, conn: socket.socket, file: str) -> bool:
        with open(file, "rb") as fh:
            self.send_data(conn, fh.read())
        return self.recv_success(conn)

    def recv_file(self, sock: socket.socket, filename: str):
        success = True
        try:
            with open(filename, "wb") as fh:
                fh.write(self.recv_data(sock))
        except Exception as e:
            print("[ ] Error: Failure on file transmission")
            os.remove(filename)
            success = False
            raise e
        finally:
            try:
                self.send_success(sock, success)
            except Exception as e:
                print("[ ] Error: Failed to send transmissions success state:", e)
            finally:
                sock.close()

    def handle_client(self, conn: socket.socket, file: str):
        self.send_init_crypto(conn)
        self.send_filename(conn, file)
        decision = self.recv_decision(conn)
        if decision:
            print("[*] Transmitting file")
            if self.send_file(conn, file):
                print("[*] File successfully sent")
            else:
                print("[ ] Error in transferred file, please try again.")
        else:
            print("[ ] Transfer aborted by recipient")

    def serve_file(self, file: str):
        # TODO: support explicit IPv6
        listen_address = ("", self.port)
        if getattr(socket, 'has_dualstack_ipv6', None) is not None and socket.has_dualstack_ipv6():
            sock = socket.create_server(listen_address, family=socket.AF_INET6, reuse_port=True, dualstack_ipv6=True)
        elif getattr(socket, 'create_server', None) is not None:
            sock = socket.create_server(listen_address, reuse_port=True)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(listen_address)
            sock.listen()
        try:
            conn, addr = sock.accept()
            print("[*] Connection from", addr)
            # try:
            self.handle_client(conn, file)
            # finally:
                # conn.close()
        finally:
            # sock.shutdown(socket.SHUT_RDWR)
            sock.close()

    def get_file(self, filename: str = None, ask: bool = False):
        ips, port = self.discover()
        if ips is None:
            print("[ ] Unable to discover sender")
        else:
            # TODO: improve ip selection mechanism
            for ip in ips:
                try:
                    if ip.startswith("fe80"):
                        if self.iface:
                            ip += f"%{self.iface}"
                        else:
                            raise ConnectionRefusedError(f"Cannot connect to link-local IPv6 ({ip}) without explicit --interface.")
                    # print("connecting to", (ip, port))
                    with socket.create_connection((ip, port)) as sock:
                        decision = True
                        self.recv_init_crypto(sock)
                        name = self.recv_filename(sock)
                        if filename is None:
                            # TODO: check for unwanted chars in name
                            filename = os.path.basename(name)
                            if os.path.exists(filename):
                                print(f"[*] File '{filename.decode('ascii')}' already exists.")
                                print("Overwrite? (Y/n): ", end="", flush=True)
                                decision = sys.stdin.read(1) in ("y", "Y", "\n")
                        decision = decision if not decision or not ask else self.ask_decision(name)
                        if decision:
                            self.send_data(sock, b"y")
                            print("[*] Starting file transfer")
                            self.recv_file(sock, filename)
                            print("[*] File successfully received")
                        else:
                            self.send_data(sock, b"n")
                            print("[ ] Aborting")
                        break
                except ConnectionRefusedError as e:
                    print(f"[ ] Error reaching '{ip}:{port}':", e)
                except OSError as e:
                    if e.errno == 101:
                        print(f"[ ] Error reaching '{ip}:{port}':", e)
                    else:
                        raise e

    def __del__(self):
        self.renounce()
        self.zconf.close()
        print("[❤] Thanks for using LFS")


if __name__ == '__main__':
    import argparse

    def keywords_argument(arg: str):
        words = re.split("[ -]", arg.strip())
        if len(words) % 3 != 0:
            raise ValueError
        return " ".join(words)

    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--ask', action="store_true", help="Ask before accepting file transfer.")
    parser.add_argument('-s', '--strength', default=1, type=int,
                        help="Amount of entropy to use for key derivation. Results in strength×3 key words (default: 1).")
    parser.add_argument('-i', '--interface', default=None,
                        help="Interface to use for file transfer (only used for file serving and IPv6).")
    parser.add_argument('-k', '--keywords', default=None, type=keywords_argument,
                        help="Keywords to use for exchange, delimited with '-' or space. (Multiples of 3 and need to conform to BIP039.)")
    parser.add_argument('-o', '--outfile', default=None,
                        help="File received data should be stored in (default: served file name).")
    parser.add_argument('-p', '--port', default=LFS.DEFAULT_PORT,
                        help=f"Port to listen on (only used for file serving) (default: {LFS.DEFAULT_PORT}).")
    parser.add_argument('file', nargs="?", help="File to be transferred. Receiving mode if omitted.")
    args = parser.parse_args()

    # TODO: Print firewall hint text on what rules to add to make it work
    if args.file is not None:
        lfs = LFS(port=args.port, iface=args.interface, keywords=args.keywords, strength=args.strength)
        lfs.announce()
        print("[*] Share keywords:", lfs.keywords)
        try:
            lfs.serve_file(args.file)
        except KeyboardInterrupt:
            print("[X] Stopped serving")
    else:
        keywords = args.keywords
        if keywords is None:
            # readline.set_completer(complete_keyword)
            # readline.parse_and_bind("tab: complete")
            # readline.set_completion_display_matches_hook(display_keyword_matches)
            keywords_input = input("Please enter the magic keywords: ")
            keywords = keywords_input.replace('-', ' ').strip()
            assert len(keywords.split()) % 3 == 0, "Error: Number of keywords must be a multiple of 3"
        lfs = LFS(port=args.port, iface=args.interface, keywords=keywords)
        lfs.get_file(args.outfile, args.ask)
