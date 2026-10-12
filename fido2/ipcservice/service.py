import win32serviceutil
import win32service
import win32event
import win32pipe
import win32file
import win32security
import win32con
import pywintypes
import winerror

import servicemanager
import logging
import json
import threading
from dataclasses import asdict
from fido2.hid import windows
from fido2.hid.base import CtapHidConnection, HidDescriptor
from fido2.hid.ipc_util import Commands, InputOutput, Connections, DescriptorConvertor, PIPE_NAME

log = logging.getLogger(__name__)

class CTAP_Broker:
    def __init__(self):
        self.connections = Connections()

    def list_descriptors(self) -> bytes:
        descriptors_list = windows.list_descriptors()
        descriptors_list_str = [DescriptorConvertor.descriptor_to_str(descriptor) for descriptor in descriptors_list]
        return json.dumps(descriptors_list_str).encode()

    def get_descriptor(self, path: bytes) -> bytes:
        descriptor = windows.get_descriptor(path)
        return DescriptorConvertor.descriptor_to_str(descriptor).encode()

    def open_connection(self, descriptor: bytes) -> bytes:
        descriptor_hid = DescriptorConvertor.str_to_descriptor(descriptor.decode())
        connection = windows.open_connection(descriptor_hid)
        handle = self.connections.add_connection(connection)
        return handle

    def read_packet(self, handle: bytes) -> bytes:
        connection = self.connections.get_connection(handle)
        return connection.read_packet()

    def write_packet(self, handle: bytes, data: bytes) -> None:
        connection = self.connections.get_connection(handle)
        connection.write_packet(data)

    def close(self, handle: bytes) -> None:
        connection = self.connections.remove_connection(handle)
        connection.close()   

    def echo(self, data: bytes) -> bytes:
        return b"echo"+data



    def process(self, data: bytes) -> bytes:
        try:
            io_command = InputOutput.from_binary(data)
            if io_command.command == Commands.LIST_DESCRIPTORS:
                resp = InputOutput(
                    command = io_command.command,
                    data = self.list_descriptors()
                )
                return resp.to_binary()

            if io_command.command == Commands.GET_DESCRIPTOR:
                resp = InputOutput(
                    command = io_command.command,
                    data = self.get_descriptor(io_command.data)
                )
                return resp.to_binary()

            if io_command.command == Commands.OPEN_CONNECTION:
                resp = InputOutput(
                    command = io_command.command,
                    data = self.open_connection(io_command.data)
                )
                return resp.to_binary()

            if io_command.command == Commands.READ_PACKET:
                resp = InputOutput(
                    command = io_command.command,
                    data = self.read_packet(io_command.handle)
                )
                return resp.to_binary()

            if io_command.command == Commands.WRITE_PACKET:
                self.write_packet(io_command.handle, io_command.data)
                return b""

            if io_command.command == Commands.CLOSE:
                self.close(io_command.handle)
                return b""

            if io_command.command == Commands.ECHO:
                resp = InputOutput(
                    command = io_command.command,
                    data = self.echo(io_command.data)
                )
                return resp.to_binary()

        except Exception as e:
            log.exception(f"Exception in processing command {e}")
            resp = InputOutput(
                command = Commands.ERROR
            )
            return resp.to_binary()



class CTAPIPCService(win32serviceutil.ServiceFramework):
    _svc_name_ = "CTAPIPCService"
    _svc_display_name_ = "CTAP IPC Service"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.running = True
        self.ctap_broker = CTAP_Broker()
        self.current_pipe = None

    @classmethod
    def SvcInstall(cls):
        win32serviceutil.ServiceFramework.SvcInstall(cls)
        cls._set_recovery()

    @classmethod
    def _set_recovery(cls, restart_delay_ms=3000, reset_period_sec=86400):
        hscm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
        try:
            hs = win32service.OpenService(hscm, cls._svc_name_, win32service.SERVICE_ALL_ACCESS)
            try:
                actions = [(win32service.SERVICE_RESTART, restart_delay_ms)]
                failure_actions = {
                    'ResetPeriod': reset_period_sec,
                    'RebootMsg': '',
                    'Command': '',
                    'Actions': actions
                }
                win32service.ChangeServiceConfig2(
                    hs, win32service.SERVICE_CONFIG_FAILURE_ACTIONS, failure_actions
                )
                win32service.ChangeServiceConfig2(
                    hs, win32service.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, True
                )
                log.info("Recovery actions configured")
            finally:
                win32service.CloseServiceHandle(hs)
        finally:
            win32service.CloseServiceHandle(hscm)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.running = False
        win32event.SetEvent(self.stop_event)
        if self.current_pipe is not None:
            try:
                win32file.CancelIoEx(self.current_pipe)
            except Exception:
                pass

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        try:
            self.main()
        except Exception:
            log.exception("Fatal error — service exiting")
            # Raise will make it exit with non zero exit code and will restart
            raise

    def make_pipe_security_attributes(self):
        sd = win32security.SECURITY_DESCRIPTOR()
        dacl = win32security.ACL()
        authenticated_users_sid = win32security.ConvertStringSidToSid("S-1-5-11")
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            win32con.GENERIC_READ | win32con.GENERIC_WRITE,
            authenticated_users_sid
        )
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        sa = win32security.SECURITY_ATTRIBUTES()
        sa.SECURITY_DESCRIPTOR = sd
        return sa

    def main(self):
        pipe = win32pipe.CreateNamedPipe(
            PIPE_NAME,
            win32pipe.PIPE_ACCESS_DUPLEX | win32file.FILE_FLAG_OVERLAPPED,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
            win32pipe.PIPE_UNLIMITED_INSTANCES,
            65536, 65536,
            0,
            self.make_pipe_security_attributes()
        )
        self.current_pipe = pipe

        try:
            while self.running:
                overlapped = pywintypes.OVERLAPPED()
                overlapped.hEvent = win32event.CreateEvent(None, 0, 0, None)

                log.info("Waiting for client connection...")
                try:
                    win32pipe.ConnectNamedPipe(pipe, overlapped)
                except pywintypes.error as e:
                    if e.winerror == winerror.ERROR_PIPE_CONNECTED:
                        win32event.SetEvent(overlapped.hEvent)
                    if e.winerror != winerror.ERROR_IO_PENDING:
                        raise  

                wait_result = win32event.WaitForMultipleObjects(
                    [self.stop_event, overlapped.hEvent], False, win32event.INFINITE
                )

                if wait_result == win32event.WAIT_OBJECT_0:
                    log.info("Stop requested, exiting")
                    return  

                log.info("Client connected")
                self.handle_client(pipe)

                win32pipe.DisconnectNamedPipe(pipe)
        finally:
            try:
                win32file.CloseHandle(pipe)
            except Exception:
                pass
            self.current_pipe = None
            
    def handle_client(self, pipe):
        try:
            while self.running:
                hr, data = win32file.ReadFile(pipe, 65536)
                if not data:
                    break
                result = self.ctap_broker.process(data)
                if result:
                    win32file.WriteFile(pipe, result)
        except pywintypes.error as e:
            if e.winerror == 109:  
                log.info("Client disconnected")
            else:
                log.exception("Unexpected pipe error")
        except Exception:
            log.exception("Error handling client")
        


if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(CTAPIPCService)