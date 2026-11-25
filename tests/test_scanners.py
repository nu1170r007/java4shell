import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("scanner", ROOT / "scanner/java4shell_scan.py")
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class NetworkTests(unittest.TestCase):
    def test_patch_boundaries(self):
        for old, fixed in [("17.0.21", "17.0.21.1"), ("21.0.13", "21.0.13.1"),
                           ("25.0.5", "25.0.5.1"), ("27.0.1", "27.0.1.1")]:
            with self.subTest(old=old):
                self.assertTrue(scanner.is_vulnerable(*scanner.parse_version(old)))
                self.assertFalse(scanner.is_vulnerable(*scanner.parse_version(fixed)))
        self.assertIsNone(scanner.is_vulnerable(8, 0, 511))
        self.assertIsNone(scanner.parse_version("21"))
        self.assertIsNone(scanner.parse_version("garbage"))
        self.assertFalse(scanner.is_vulnerable(17, 0, 5))

    def test_application_version_is_not_java_version(self):
        match = scanner.JAVA_SIGNATURES[-1].search("Server: Jetty/21.0.1")
        self.assertIsNotNone(match)
        self.assertIsNone(match.lastindex)

    def test_network_results_never_clear_host(self):
        for version, assessment in [(None, "INCONCLUSIVE"), ("21.0.13.1", "INCONCLUSIVE"),
                                    ("21.0.13", "CANDIDATE"), ("8.0.511", "INCONCLUSIVE")]:
            with self.subTest(version=version), \
                 patch.object(scanner, "probe_http", return_value=[{"version": version}]), \
                 patch.object(scanner, "probe_tls", return_value=[]):
                result = scanner.scan_host("unused.invalid", [80])
                self.assertEqual(result["assessment"], assessment)
                self.assertIsNone(result["vulnerable"])


class HostTests(unittest.TestCase):
    def run_shell(self, body):
        return subprocess.run(["bash", "-c", f'source "{ROOT}/scanner/java4shell_scan.sh"\n{body}'],
                              capture_output=True, text=True)

    def test_versions(self):
        for version, expected in [("21.0.13.1", "OUTSIDE_KNOWN_RANGE"),
                                  ("21.0.13", "CANDIDATE"), ("22.0.1", "UNKNOWN")]:
            result = self.run_shell(f'''fake_java() {{ echo 'openjdk version "{version}"'; }}
timeout() {{ shift; "$@"; }}
check_java fake_java''')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(expected, result.stdout)

    def test_failed_version_is_unknown(self):
        result = self.run_shell('timeout() { return 124; }; check_java /fake/java')
        self.assertIn("UNKNOWN", result.stdout)
        self.assertNotIn("SAFE", result.stdout)

    def test_effective_flags_not_command_line(self):
        with tempfile.TemporaryDirectory() as d:
            jcmd = Path(d) / "jcmd"
            jcmd.touch()
            jcmd.chmod(0o700)
            for flag, expected in [("false", "MITIGATED"), ("true", "INTRINSIC_ENABLED")]:
                result = self.run_shell(f'''readlink() {{ echo "{d}/java"; }}
timeout() {{ echo "bool UseBASE64Intrinsics = {flag} {{product}}"; }}
ps() {{ echo "java -XX:+UseBASE64Intrinsics secret-do-not-print"; }}
check_jvm_flags 123''')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(expected, result.stdout)
                self.assertNotIn("secret-do-not-print", result.stdout)
                if flag == "true":
                    self.assertNotIn("MITIGATED", result.stdout)
            result = self.run_shell(f'''readlink() {{ echo "{d}/java"; }}
timeout() {{ return 1; }}
check_jvm_flags 123''')
            self.assertIn("UNKNOWN", result.stdout)


class VerifierTests(unittest.TestCase):
    def test_outcomes(self):
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            helpers = {
                "uname": '#!/bin/sh\necho x86_64\n',
                "grep": '#!/bin/sh\ncase "$*" in *"/proc/cpuinfo"*) echo "flags : avx512f avx512bw avx512vbmi bmi2";; *) exec /usr/bin/grep "$@";; esac\n',
                "javac": '#!/bin/sh\nexit 0\n',
                "java": '''#!/bin/sh
case "$*" in
  *UseBASE64Intrinsics*)
    if [ "$MODE" = bad_control ]; then echo REPRODUCED; exit 0; fi
    echo 'rejected=true changed=0 first=-1 last=-1'
    echo 'NOT REPRODUCED'; exit 1;;
esac
case "$MODE" in
  crash) echo "private-options"; exit 139;;
  timeout) exit 124;;
  negative) echo 'rejected=true changed=0 first=-1 last=-1'; echo 'NOT REPRODUCED'; exit 1;;
  *) echo REPRODUCED; exit 0;;
esac
''',
            }
            for name, content in helpers.items():
                p = directory / name
                p.write_text(content)
                p.chmod(0o700)
            for mode in ["crash", "timeout", "negative", "bad_control", "positive"]:
                with self.subTest(mode=mode):
                    env = dict(os.environ, PATH=f"{d}:{os.environ['PATH']}", MODE=mode)
                    result = subprocess.run(["bash", str(ROOT / "poc/verify_corruption.sh"), str(directory / "java")],
                                            env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 1 if mode == "positive" else 2, result.stdout + result.stderr)
                    self.assertNotIn("NOT VULNERABLE", result.stdout)
                    self.assertNotIn("private-options", result.stdout)
                    if mode == "positive":
                        self.assertIn("CONFIRMED:", result.stdout)


if __name__ == "__main__":
    unittest.main()
