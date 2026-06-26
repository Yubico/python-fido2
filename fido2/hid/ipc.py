import win32file
import win32pipe
import pywintypes
import random
import string
import json
import os
from fido2.hid.base import CtapHidConnection, HidDescriptor
from fido2.hid.ipc_util import Commands, InputOutput, Connections, DescriptorConvertor, PIPE_NAME
import time
import win32security
import ntsecuritycon as ntsec
import win32pipe
import win32con

class IPC_Pipe:
    def __init__(self, retry_time_ms=2000, retry_count=3):
        for _ in range(retry_count):
            try:
                self.handle = win32file.CreateFile(
                    PIPE_NAME,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0,
                    None,
                    win32file.OPEN_EXISTING,
                    0,
                    None
                )
                break
            except pywintypes.error as e:
                if e.winerror == 231: #Busy handles
                    time.sleep(retry_time_ms/1000)


    @staticmethod
    def is_pipe_available(timeout_ms=2000) -> bool:
        try:
            win32pipe.WaitNamedPipe(PIPE_NAME, timeout_ms)
            handle = win32file.CreateFile(
                PIPE_NAME,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0,
                None,
                win32file.OPEN_EXISTING,
                0,
                None
            )
            random_data= os.urandom(16)
            command = InputOutput(
                command = Commands.ECHO,
                data = random_data
            )
            win32file.WriteFile(handle, command.to_binary())
            hr, response = win32file.ReadFile(handle, 65536)
            response_data = InputOutput.from_binary(response).data
            win32file.CloseHandle(handle)
            assert response_data == b"echo"+random_data
            return True
        except (pywintypes.error, AssertionError):
            return False

    def call_pipe(self, command: InputOutput, has_response: bool = True) -> InputOutput | None:
        data = command.to_binary()
        win32file.WriteFile(self.handle, data)
        if has_response:
            hr, response = win32file.ReadFile(self.handle, 65536)
            return InputOutput.from_binary(response)

    def close_pipe(self):
        win32file.CloseHandle(self.handle)
        

class IPC_Client:
    def __init__(self):
        self.pipe = IPC_Pipe()

    def list_descriptors(self):
        command = InputOutput(
            command = Commands.LIST_DESCRIPTORS
        )
        resp = self.pipe.call_pipe(command)
        data = resp.data
        assert resp.command == Commands.LIST_DESCRIPTORS
        descriptors_list = json.loads(data.decode())
        descriptors_list_hid = [DescriptorConvertor.str_to_descriptor(descriptor) for descriptor in descriptors_list]
        return descriptors_list_hid

    def get_descriptor(self, path: bytes):
        command = InputOutput(
            command = Commands.GET_DESCRIPTOR,
            data = path
        )
        resp = self.pipe.call_pipe(command)
        assert resp.command == Commands.GET_DESCRIPTOR
        descriptor = DescriptorConvertor.str_to_descriptor(resp.data.decode())
        return descriptor

    def open_connection(self, descriptor: HidDescriptor):
        command = InputOutput(
            command = Commands.OPEN_CONNECTION,
            data = DescriptorConvertor.descriptor_to_str(descriptor).encode()
        )
        resp = self.pipe.call_pipe(command)
        assert resp.command == Commands.OPEN_CONNECTION
        handle = resp.data
        return handle

    def read_packet(self, handle: bytes):
        command = InputOutput(
            command = Commands.READ_PACKET,
            handle = handle
        )
        resp = self.pipe.call_pipe(command)
        assert resp.command == Commands.READ_PACKET
        data = resp.data
        return data

    def write_packet(self, handle: bytes, data: bytes):
        command = InputOutput(
            command = Commands.WRITE_PACKET,
            handle = handle,
            data = data
        )

        self.pipe.call_pipe(command, has_response = False)

    def close(self, handle: bytes):
        command = InputOutput(
            command = Commands.CLOSE,
            handle = handle
        )
        self.pipe.call_pipe(command, has_response = False)

class ClientHandler:
    def __init__(self):
        self.ipc_client = None

    def open_client(self):
        if self.ipc_client:
            return
        assert IPC_Pipe.is_pipe_available()
        self.ipc_client = IPC_Client()

    def get_client(self):
        self.open_client()
        return self.ipc_client

    def close_client(self):
        assert self.ipc_client
        self.ipc_client.pipe.close_pipe()

client_handler = ClientHandler()

def list_descriptors():
    client = client_handler.get_client()
    return client.list_descriptors()

def get_descriptor(path):
    client = client_handler.get_client()
    return client.get_descriptor(path)

class IPC_Connection(CtapHidConnection):
    def __init__(self, client: IPC_Client, descriptor: HidDescriptor):
        self.client = client
        self.handle = self.client.open_connection(descriptor)

    def read_packet(self):
        return self.client.read_packet(self.handle)

    def write_packet(self, data):
        self.client.write_packet(self.handle, data)

    def close(self):
        self.client.close(self.handle)

def open_connection(descriptor):
    client = client_handler.get_client()
    return IPC_Connection(client, descriptor)
