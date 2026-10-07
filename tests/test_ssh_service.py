import io
import socket
import unittest
from pathlib import PurePosixPath

import paramiko

from app.services.ssh_service import (
    SSHClientFactory,
    SSHCommandError,
    SSHService,
)


class FakeSSHClient:
    def __init__(self):
        self.connected = False
        self.command_calls = []
        self.sftp_calls = []
        self.sftp = FakeSFTP()

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def load_system_host_keys(self, path=None):
        self.system_host_keys_path = path

    def connect(self, **kwargs):
        self.connected = True
        self.connect_kwargs = kwargs

    def exec_command(self, command, timeout=None, get_pty=False):
        self.command_calls.append({
            "command": command,
            "timeout": timeout,
            "get_pty": get_pty,
        })
        stdin = type("Stdin", (), {})()
        stdout = type("Stdout", (), {"read": lambda self: b"stdout\n"})()
        stderr = type("Stderr", (), {"read": lambda self: b"stderr\n"})()
        channel = type("Channel", (), {"recv_exit_status": lambda self: 0})()
        stdout.channel = channel
        return stdin, stdout, stderr

    def open_sftp(self):
        self.sftp_calls.append("open_sftp")
        return self.sftp

    def close(self):
        self.connected = False


class FakeSFTP:
    def __init__(self):
        self.operations = []

    def listdir(self, path):
        self.operations.append(("listdir", path))
        return ["file.txt", "dir"]

    def stat(self, path):
        self.operations.append(("stat", path))
        return type("Stat", (), {"st_mode": 0o100644, "st_size": 12})()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def mkdir(self, path, mode=0o777):
        self.operations.append(("mkdir", path, mode))

    def rmdir(self, path):
        self.operations.append(("rmdir", path))

    def remove(self, path):
        self.operations.append(("remove", path))

    def rename(self, old_path, new_path):
        self.operations.append(("rename", old_path, new_path))

    def chmod(self, path, mode):
        self.operations.append(("chmod", path, mode))

    def getfo(self, remote_path, file_obj, callback=None):
        self.operations.append(("getfo", remote_path))
        file_obj.write(b"remote-data")

    def putfo(self, file_obj, remote_path, callback=None, confirm=True):
        self.operations.append(("putfo", remote_path, len(file_obj.read())))

    def close(self):
        self.operations.append(("close",))


class SSHServiceTest(unittest.TestCase):
    def test_execute_command_returns_standardized_result(self):
        client = FakeSSHClient()
        service = SSHService(client_factory=lambda *args, **kwargs: client)

        result = service.execute_command(
            host="192.168.1.10",
            username="alice",
            password="secret",
            command="uname -a",
            timeout=10,
        )

        self.assertEqual(client.connect_kwargs["hostname"], "192.168.1.10")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["stdout"], "stdout\n")
        self.assertEqual(result["stderr"], "stderr\n")
        self.assertEqual(result["command"], "uname -a")

    def test_sftp_list_and_stat_are_available(self):
        client = FakeSSHClient()
        service = SSHService(client_factory=lambda *args, **kwargs: client)

        listing = service.list_directory(
            host="192.168.1.10",
            username="alice",
            password="secret",
            path="/tmp",
        )
        info = service.get_file_info(
            host="192.168.1.10",
            username="alice",
            password="secret",
            path="/tmp/file.txt",
        )

        self.assertEqual([entry["name"] for entry in listing["files"]], ["file.txt", "dir"])
        self.assertEqual(info["mode"], "100644")
        self.assertEqual(info["size"], 12)

    def test_private_key_content_is_accepted(self):
        key = paramiko.RSAKey.generate(2048)
        private_key = io.StringIO()
        key.write_private_key(private_key)

        client = FakeSSHClient()
        service = SSHService(client_factory=lambda *args, **kwargs: client)

        result = service.execute_command(
            host="192.168.1.10",
            username="alice",
            private_key=private_key.getvalue(),
            command="uname -a",
        )

        self.assertEqual(result["exit_code"], 0)
        self.assertIsNotNone(client.connect_kwargs["pkey"])

    def test_execute_command_reports_socket_timeout(self):
        class TimeoutClient:
            def connect(self, **kwargs):
                pass

            def exec_command(self, command, timeout=None, get_pty=False):
                raise socket.timeout("SSH output read timed out")

            def close(self):
                pass

        service = SSHService(client_factory=lambda *args, **kwargs: TimeoutClient())

        with self.assertRaisesRegex(SSHCommandError, "SSH output read timed out"):
            service.execute_command(
                host="192.168.1.10",
                username="alice",
                password="secret",
                command="ipsec statusall",
                command_timeout=30,
            )

    def test_factory_uses_key_authentication_when_requested(self):
        factory = SSHClientFactory(allow_unknown_hosts=True)
        fake_client = factory._create_client()

        self.assertTrue(hasattr(fake_client, "load_system_host_keys"))
        self.assertEqual(factory.allow_unknown_hosts, True)


class SSHApiContractTest(unittest.TestCase):
    def test_only_connect_endpoint_exists(self):
        from app.main import app

        paths = sorted(app.openapi()["paths"])
        ssh_paths = [path for path in paths if path.startswith("/api/ssh/")]

        self.assertEqual(ssh_paths, ["/api/ssh/connect"])


if __name__ == "__main__":
    unittest.main()
