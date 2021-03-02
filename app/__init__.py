# Needed for proper tying annotations
# Must always be first to be imported until Python 3.10 is used
from __future__ import annotations
from typing import List, Mapping, Optional, Union
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from enum import IntEnum
from pathlib import Path
import zstandard
import random
import zlib
import json


class CompressionFlag(IntEnum):
    NO_COMPRESS = 0x00
    ZLIB = 0x0E
    ZSTD = 0x0D


class EncryptionFlag(IntEnum):
    ENCRYPTED = 0xF0
    UNENCRTYPTED = 0x00


class TinfoilIndex:
    __tinfoil_pub_key: Optional[RsaKey] = None
    __files: Optional[List[Union[str, Mapping[str, Union[int, str]]]]] = None
    __success: Optional[str] = None

    @staticmethod
    def set_tinfoil_public_key(pub_key: RsaKey):
        TinfoilIndex.__tinfoil_pub_key = pub_key

    @classmethod
    def from_existing_index(
        cls,
        existing_index_path: Path,
        tinfoil_priv_key: Optional[RsaKey] = None,
        vm_export_path: Optional[Path] = None,
    ) -> TinfoilIndex:
        tinfoil_index = cls()
        with existing_index_path.open(mode="rb") as index_stream:
            tinfoil_header_sz = 0x110
            index_stream_header = index_stream.read(tinfoil_header_sz)
            index_stream_magic = index_stream_header[0:7]
            if index_stream_magic != "TINFOIL":
                raise IOError("Invalid stream magic!\nExpected: TINFOIL\n" +
                              f"Stream Magic: {index_stream_magic}")

            index_flags = index_stream_header[7]
            encryption = index_flags & 0xF0

            compression = index_flags & 0x0F
            data_sz = int.from_bytes(
                index_stream_header[:8],
                byteorder="little",
            )
            data_buffer = index_stream.read(data_sz)

            if encryption == EncryptionFlag.ENCRYPTED:
                if not tinfoil_priv_key:
                    raise IOError(
                        "Unable to read encrypted index without private key"
                    )

                session_key = index_stream_header[0x8:-0x8]
                rsa_cipher = PKCS1_OAEP.new(
                    tinfoil_priv_key,
                    hashAlgo=SHA256,
                    label=b"",
                )
                aes_key = rsa_cipher.decrypt(session_key)
                aes_cipher = AES.new(aes_key, AES.MODE_ECB)
                data_buffer = aes_cipher.decrypt(data_buffer)

            if compression == CompressionFlag.ZSTD:
                data_buffer = zstandard.ZstdDecompressor().compress(
                    data_buffer,
                )

            elif compression == CompressionFlag.ZLIB:
                data_buffer = zlib.decompress(data_buffer)

            elif compression == CompressionFlag.NO_COMPRESS:
                pass

            else:
                raise NotImplementedError(
                    "Compression flag from index not implemented"
                )

            if data_buffer[0x4:] == b"\x13\x37\xB0\x0B":
                vm_data_sz = int.from_bytes(
                    data_buffer[0x4:0x8],
                    byteorder="little",
                )

                if vm_export_path:
                    with vm_export_path.open(mode="wb") as vm_stream:
                        vm_stream.write(data_buffer[0xC:0xC+vm_data_sz])

                data_buffer = data_buffer[0xC+vm_data_sz:]

            parsed_index = json.loads(data_buffer)

            if parsed_index.get("files"):
                tinfoil_index.__files = parsed_index["files"]

            if parsed_index.get("success"):
                tinfoil_index.__success = parsed_index["success"]

        return tinfoil_index

    def add_success_message(self, success: str):
        if self.__success is None:
            self.__success = success
        else:
            self.__success += success

    def generate(
        self,
        encryption: EncryptionFlag = EncryptionFlag.ENCRYPTED,
        compression: CompressionFlag = CompressionFlag.ZSTD,
        vm_file_path: Optional[Path] = None,
    ) -> bytes:
        if encryption == EncryptionFlag.ENCRYPTED and not \
                TinfoilIndex.__tinfoil_pub_key:
            raise ValueError(
                "Unable to encrypt index as encryption key was not provided"
            )

        compression_buffer = b""

        if vm_file_path and vm_file_path.exists():
            with vm_file_path.open(mode="rb") as vm_file_stream:
                vm_data = vm_file_stream.read()
                compression_buffer += b'\x13\x37\xB0\x0B'
                compression_buffer += len(vm_data).to_bytes(4, "little")
                compression_buffer += vm_data

        index = {}

        if self.__files:
            index.update({"files": self.__files})

        if self.__success:
            index.update({"success": self.__success})

        compression_buffer += bytes(json.dumps(index).encode())

        compressed_buffer = b""

        if compression == CompressionFlag.ZSTD:
            compressed_buffer += zstandard.ZstdCompressor(level=22).compress(
                compression_buffer,
            )

        elif compression == CompressionFlag.ZLIB:
            compressed_buffer += zlib.compress(compression_buffer, level=9)

        elif compression == CompressionFlag.NO_COMPRESS:
            compressed_buffer += compression_buffer

        else:
            raise NotImplementedError(
                "Compression method not implemented yet"
            )

        compression_buffer = None
        session_key: Optional[bytes] = None
        data_sz = len(compressed_buffer)
        index_flags = compression & encryption
        compressed_buffer += (b"\x00" * (0x10 - (data_sz % 0x10)))

        if encryption == EncryptionFlag.ENCRYPTED:
            random_aes_key = random.randint(
                0,
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
            ).to_bytes(
                0x10,
                'big',
            )
            rsa_cipher = PKCS1_OAEP.new(
                TinfoilIndex.__tinfoil_pub_key,
                hashAlgo=SHA256,
                label=b"",
            )
            session_key = rsa_cipher.encrypt(random_aes_key)
            aes_cipher = AES.new(
                random_aes_key,
                TinfoilIndex.__tinfoil_pub_key,
            )
            compressed_buffer = aes_cipher.encrypt(compressed_buffer)

        out_buffer = b"TINFOIL"
        out_buffer += index_flags.to_bytes(1, byteorder="little")

        if session_key and len(out_buffer) == 0x100:
            out_buffer += session_key
        else:
            out_buffer += b"\x00" * 0x100

        out_buffer += data_sz.to_bytes(8, byteorder="little")
        out_buffer += compressed_buffer

        compressed_buffer = None
        return out_buffer
