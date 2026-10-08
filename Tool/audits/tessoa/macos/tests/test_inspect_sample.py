import pathlib
import plistlib
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from inspect_sample import inspect


def sample(cpu=0x0100000c, commands=b'', count=0, payload=b''):
    return struct.pack('<8I', 0xfeedfacf, cpu, 0, 2, count, len(commands), 0, 0) + commands + payload


class InspectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = pathlib.Path(self.temp.name) / 'Fixture.app'
        (self.app / 'Contents/MacOS').mkdir(parents=True)
        self.info = self.app / 'Contents/Info.plist'
        self.info.write_bytes(plistlib.dumps({'CFBundleExecutable': 'fixture'}))
        self.binary = self.app / 'Contents/MacOS/fixture'

    def check_rejected(self, data, message):
        self.binary.write_bytes(data)
        with patch('inspect_sample.subprocess.run') as run:
            with self.assertRaisesRegex(ValueError, message):
                inspect(self.app)
            run.assert_not_called()

    def test_valid_fixture(self):
        self.binary.write_bytes(sample(commands=struct.pack('<4I', 0x1d, 16, 48, 4), count=1, payload=b'test'))
        with patch('inspect_sample.subprocess.run', return_value=subprocess.CompletedProcess([], 0, '', '')):
            report = inspect(self.app)
        self.assertEqual(report['codesign_exit'], 0)
        self.assertEqual(report['code_signatures'], [{'offset': 48, 'size': 4}])

    def test_signature_failure_preserved(self):
        self.binary.write_bytes(sample())
        with patch('inspect_sample.subprocess.run', return_value=subprocess.CompletedProcess([], 1, '', 'invalid signature')):
            report = inspect(self.app)
        self.assertEqual(report['codesign_exit'], 1)
        self.assertEqual(report['codesign_diagnostic'], 'invalid signature')

    def test_wrong_architecture(self):
        self.check_rejected(sample(cpu=0x01000007), 'Expected arm64')

    def test_truncated_header(self):
        self.check_rejected(b'\xcf\xfa\xed\xfe', 'Expected thin')

    def test_bad_command_size(self):
        self.check_rejected(sample(commands=struct.pack('<2I', 1, 4), count=1), 'Invalid load command size')

    def test_signature_outside_file(self):
        self.check_rejected(sample(commands=struct.pack('<4I', 0x1d, 16, 4096, 4), count=1), 'Signature exceeds file')

    def test_missing_command(self):
        self.check_rejected(sample(count=1), 'Truncated load command')

    def test_path_traversal(self):
        self.info.write_bytes(plistlib.dumps({'CFBundleExecutable': '../fixture'}))
        with self.assertRaisesRegex(ValueError, 'Unexpected executable path'):
            inspect(self.app)


if __name__ == '__main__':
    unittest.main()
