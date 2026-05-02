
# Requirements:
# * python-pcapng
# * ldn==0.0.15

from Crypto.Cipher import AES
from dataclasses import dataclass
from pcapng import FileScanner
from pcapng.blocks import EnhancedPacket
from ldn import wlan, streams
import binascii
import copy
import ldn
import socket
import struct
import zlib


ETH_P_IPV4 = 0x800


class Random:
    state: list[int]

    def __init__(self, seed: int):
        multiplier = 0x6C078965
        
        temp = seed
        self.state = []
        for i in range(1, 5):
            temp ^= temp >> 30
            temp = (temp * multiplier + i) & 0xFFFFFFFF
            self.state.append(temp)
    
    def u32(self) -> int:
        temp = self.state[0]
        temp = (temp ^ (temp << 11)) & 0xFFFFFFFF
        temp ^= temp >> 8
        temp ^= self.state[3]
        temp ^= self.state[3] >> 19
        self.state[0] = self.state[1]
        self.state[1] = self.state[2]
        self.state[2] = self.state[3]
        self.state[3] = temp
        return temp


@dataclass
class ApplicationData:
    session_id: int = 0
    user_password_hash: int = 0
    system_communication_version: int = 0
    session_param: int = 0
    application_data: bytes = b""

    def decode(self, data: bytes) -> None:
        stream = streams.StreamIn(data, "<")
        self.session_id = stream.u32()
        self.user_password_hash = stream.u32()
        self.system_communication_version = stream.u8()
        if stream.u8() != 24:
            raise ValueError("Application data has unexpected header size")
        stream.pad(2)
        self.session_param = stream.u32()
        stream.pad(8)
        self.application_data = stream.readall()


@dataclass
class LLCFrame:
    dsap: int = 0
    ssap: int = 0
    control: int = 0
    data: bytes = b""

    def decode(self, data: bytes) -> None:
        stream = streams.StreamIn(data, "<")
        self.dsap = stream.u8()
        self.ssap = stream.u8()
        self.control = stream.u8()
        if self.control & 3 != 3:
            self.control |= stream.u8() << 8
        self.data = stream.readall()


@dataclass
class SNAPFrame:
    oui: bytes = bytes(3)
    type: int = 0
    data: bytes = b""
    
    def decode(self, data: bytes) -> None:
        stream = streams.StreamIn(data, ">")
        self.oui = stream.read(3)
        self.type = stream.u16()
        self.data = stream.readall()


@dataclass
class IPV4Packet:
    protocol: int = 0
    source_address: str = "0.0.0.0"
    target_address: str = "0.0.0.0"
    data: bytes = b""
    
    def decode(self, data: bytes) -> None:
        stream = streams.StreamIn(data, ">")

        value = stream.u8()
        if value >> 4 != 4:
            raise ValueError("IPv4 packet has unexpected version number")
        if value & 0xF != 5:
            raise ValueError("IPv4 options are not supported")

        stream.skip(1) # Skip DSCP and ECN

        total_length = stream.u16()
        assert len(data) == total_length

        stream.skip(5) # Skip identification, flags and fragment offset

        self.protocol = stream.u8()

        stream.skip(2) # Skip header checksum

        self.source_address = socket.inet_ntoa(stream.read(4))
        self.target_address = socket.inet_ntoa(stream.read(4))
        
        self.data = stream.readall()


@dataclass
class UDPPacket:
    source_port: int = 0
    target_port: int = 0
    data: bytes = b""
    
    def decode(self, data: bytes) -> None:
        stream = streams.StreamIn(data, ">")
        self.source_port = stream.u16()
        self.target_port = stream.u16()

        length = stream.u16()
        stream.skip(2) # Skip checksum

        self.data = stream.read(length - 8)

        if not stream.eof():
            raise ValueError("UDP packet has incorrect length")


@dataclass
class PiaPacket:
    encrypted: bool = False
    connection_id: int = 0
    sequence_id: int = 0
    nonce: int = 0
    signature: bytes = bytes(16)
    payload: bytes = b""
    
    def decode(self, data: bytes) -> None:
        stream = streams.StreamIn(data, ">")
        if stream.u32() != 0x32AB9864:
            raise ValueError("Pia packet has wrong magic number")
        
        encryption = stream.u8()
        if encryption & 0x7F != 4:
            raise ValueError("Pia packet has unexpected version number")
        
        self.encrypted = bool(encryption >> 7)
        self.connection_id = stream.u8()
        self.sequence_id = stream.u16()
        self.nonce = stream.u64()
        self.signature = stream.read(16)
        self.payload = stream.readall()
    
    def decrypt(self, session_key: bytes, nonce: bytes) -> None:
        if not self.encrypted: return
        
        aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        self.payload = aes.decrypt_and_verify(self.payload, self.signature)
        self.encrypted = False


@dataclass
class PiaMessage:
    flags: int = 0
    protocol_id: int = 0
    protocol_port: int = 0
    destination: int = 0
    source_constant_id: int = 0
    payload: bytes = b""

    def decompress(self) -> None:
        if not self.flags & 16:
            return
        
        self.payload = zlib.decompress(self.payload)
        self.flags &= ~16


def decode_pia_messages(data: bytes) -> list[PiaMessage]:
    stream = streams.StreamIn(data, ">")
    
    messages = []
    message = PiaMessage()
    while not stream.eof():
        flags = stream.u8()
        if flags == 0xFF:
            break
        
        message = copy.copy(message)
        payload_size = len(message.payload)
        
        if flags & 1: message.flags = stream.u8()
        if flags & 2: payload_size = stream.u16()
        if flags & 4:
            message.protocol_id = stream.u8()
            message.protocol_port = stream.u24()
        if flags & 8: message.destination = stream.u64()
        if flags & 16: message.source_constant_id = stream.u64()
        
        message.payload = stream.read(payload_size)
        stream.align(4)
        
        messages.append(message)
    return messages


def load_pcapng(filename: str) -> list[bytes]:
    packets = []
    with open(filename, "rb") as f:
        scanner = FileScanner(f)
        for block in scanner:
            if isinstance(block, EnhancedPacket):
                packets.append(block.packet_data)
    return packets


def remove_radiotap_headers(packets: list[bytes]) -> list[bytes]:
    decoded = []
    for packet in packets:
        frame = wlan.RadiotapFrame()
        frame.decode(packet)
        decoded.append(frame.data)
    return decoded


def find_action_frame(packets: list[bytes]) -> wlan.ActionFrame:
    for packet in packets:
        try:
            frame = wlan.ActionFrame()
            frame.decode(packet)
            return frame
        except Exception:
            pass
    raise ValueError("Couldn't find any action frames")


def derive_pia_key(session_param: int, game_key: bytes) -> bytes:
    random = Random(session_param)

    values = [random.u32() for i in range(4)]
    data = struct.pack("<4I", *values)

    aes = AES.new(game_key, AES.MODE_ECB)
    return aes.encrypt(data)


def derive_pia_nonce(frame: wlan.DataFrame, packet: PiaPacket, session_id: int) -> bytes:
    data = struct.pack("<I", session_id) + frame.source.encode()
    hash = binascii.crc32(data)

    nonce = struct.pack(">I", hash)[:3]
    nonce += struct.pack(">BQ", packet.connection_id, packet.nonce)
    return nonce


def parse_data_frames(packets: list[bytes], data_key: bytes, pia_key: bytes, session_id: int) -> list[bytes]:
    decoded = []
    for packet in packets:
        try:
            frame = wlan.DataFrame()
            frame.decode(packet)
            frame.decrypt(data_key)
        except Exception as e:
            continue

        llc = LLCFrame()
        llc.decode(frame.payload)

        if llc.dsap != 0xAA or llc.ssap != 0xAA or llc.control != 3:
            continue

        snap = SNAPFrame()
        snap.decode(llc.data)

        if snap.oui != bytes(3) or snap.type != ETH_P_IPV4:
            continue

        ipv4 = IPV4Packet()
        ipv4.decode(snap.data)

        if ipv4.protocol != 17:
            # We are only interested in UDP
            continue

        if not ipv4.source_address.endswith(".1"):
            # The level data is transmitted by the host, we are only interested
            # in packets that are transmitted by the host
            continue

        udp = UDPPacket()
        udp.decode(ipv4.data)
        
        pia = PiaPacket()
        pia.decode(udp.data)

        nonce = derive_pia_nonce(frame, pia, session_id)
        pia.decrypt(pia_key, nonce)

        messages = decode_pia_messages(pia.payload)
        for message in messages:
            if message.protocol_id != 0x81:
                continue

            message.decompress()

            decoded.append(message.payload)
    return decoded



def solve(filename: str) -> None:
    password = b"LunchPack2DefaultPhrase"
    game_key = bytes.fromhex("667c18475889faab61f93ef1da180971")

    keys = {
        "aes_kek_generation_source": bytes.fromhex("4d870986c45d20722fba1053da92e8a9"),
        "aes_key_generation_source": bytes.fromhex("89615ee05c31b6805fe58f3da24f7aa8"),
        "master_key_00": bytes.fromhex("c2caaff089b9aed55694876055271c7d")
    }
    key_derivation = ldn.KeyDerivation(keys, 1)

    packets = load_pcapng(filename)
    packets = remove_radiotap_headers(packets)

    action = find_action_frame(packets)
    advertisement = ldn.AdvertisementFrame(key_derivation, 1)
    advertisement.decode(action.action)

    advertisement_info = advertisement.payload

    application_data = ApplicationData()
    application_data.decode(advertisement_info.application_data)

    pia_key = derive_pia_key(application_data.session_param, game_key)

    data_key = key_derivation.derive_data_key(advertisement_info.server_random, password)

    messages = parse_data_frames(packets, data_key, pia_key, application_data.session_id)

    # The fact that the level file is transmitted unencrypted makes it a bit
    # easier for the player, as we can simply search for the flag after
    # decrypting the Pia packets.
    # 
    # If the level file was encrypted, it would have been necessary to
    # reassemble the fragments of the reliable sliding window, parse the
    # messages of the stream broadcast reliable protocol and then decrypt the
    # level file. Much harder!

    search = "dach2026{".encode("utf-16-le")
    for message in messages:
        start = message.find(search)
        if start != -1:
            end = message.index(b"}", start) + 2
            flag = message[start:end].decode("utf-16-le")
            print(flag)
            return


if __name__ == "__main__":
    solve("capture.pcapng")
