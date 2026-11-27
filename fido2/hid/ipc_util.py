import struct
import json
import os
from enum import Enum
from dataclasses import dataclass, asdict, field
from fido2.hid.base import FIDO_USAGE, FIDO_USAGE_PAGE, CtapHidConnection, HidDescriptor

HANDLE_SIZE = 16
PIPE_NAME = r"\\.\pipe\CTAPPipe"

class Commands(int, Enum):
    LIST_DESCRIPTORS = 0x00
    GET_DESCRIPTOR = 0x01
    OPEN_CONNECTION = 0x02
    READ_PACKET = 0x03
    WRITE_PACKET = 0x04
    CLOSE = 0x05
    ERROR = 0x06
    ECHO = 0x07

@dataclass
class InputOutput:
    command: Commands
    handle: bytes = b""
    data: bytes = b""

    @staticmethod
    def from_binary(bindata: bytes):
        command = Commands(bindata[0])
        remaining = bindata[1:]
        handle = b''
        if command in (Commands.READ_PACKET, Commands.WRITE_PACKET, Commands.CLOSE):
            handle = remaining[:HANDLE_SIZE]
            remaining = remaining[HANDLE_SIZE:]
        data = remaining
        return InputOutput(
            command = command,
            handle = handle,
            data = data
        )

    def to_binary(self):
        if self.command in (Commands.READ_PACKET, Commands.WRITE_PACKET, Commands.CLOSE):
            return struct.pack(
                f"B{HANDLE_SIZE}s{len(self.data)}s",
                self.command,
                self.handle,
                self.data,
            )
        else:
            return struct.pack(
                f"B{len(self.data)}s",
                self.command,
                self.data,
            )

@dataclass
class Connections():
    connections: dict[bytes, CtapHidConnection] = field(default_factory=dict)

    def add_connection(self, connection: CtapHidConnection) -> bytes:
        handle = os.urandom(HANDLE_SIZE)
        self.connections[handle] = connection
        return handle

    def remove_connection(self, handle: bytes) -> CtapHidConnection:
        return self.connections.pop(handle)

    def get_connection(self, handle: bytes) -> CtapHidConnection:
        return self.connections.get(handle)

class DescriptorConvertor:
    
    @staticmethod
    def descriptor_to_str(descriptor: HidDescriptor) -> str:
        descriptor_dict = asdict(descriptor)
        if isinstance(descriptor_dict.get("path", None), bytes):
            descriptor_dict["path"] = descriptor_dict["path"].decode()
        return json.dumps(descriptor_dict)

    @staticmethod
    def str_to_descriptor(descriptor_str: str) -> HidDescriptor:
        descriptor_dict = json.loads(descriptor_str)
        descriptor_dict["path"] = descriptor_dict["path"].encode()
        return HidDescriptor(**descriptor_dict)
