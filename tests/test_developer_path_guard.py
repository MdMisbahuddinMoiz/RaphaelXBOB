"""Guard: no test file may hardcode a developer checkout path.

Fifteen test modules carried `sys.path.insert(0, '/home/yaser/...')` for months
without failing anything, because `pyproject.toml` already sets
`pythonpath = ["src"]` — so the bogus entry was a silent no-op. A green suite
therefore proved nothing about this class of defect, and only
`3150a3060`'s fix and this guard catch it.

The rule is deliberately narrow: an absolute path into a *developer's home
directory checkout of this project* is forbidden. It must not fire on `/tmp/...`,
nor on a security fixture that legitimately mentions a home directory.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TESTS = REPO / "tests"

#: /home/<user>/<something that is this project>
_CHECKOUT = re.compile(r"/home/[A-Za-z0-9._-]+/raphael[-A-Za-z0-9._]*")

#: Paths that are legitimate even though they are absolute.
_ALLOWED_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/", "/proc/", "/sys/")


def _offending_lines(path: Path) -> list:
    out = []
    for number, line in enumerate(path.read_text(encoding="utf-8")
                                  .splitlines(), 1):
        if any(line.lstrip().startswith(p) for p in _ALLOWED_PREFIXES):
            continue
        if _CHECKOUT.search(line):
            out.append((number, line.strip()))
    return out


class DeveloperPathGuard(unittest.TestCase):
    def test_no_test_file_hardcodes_a_developer_checkout(self):
        offenders = {}
        for path in sorted(TESTS.glob("test_*.py")):
            hits = _offending_lines(path)
            if hits:
                offenders[path.name] = hits
        self.assertEqual(
            offenders, {},
            "test files must resolve paths from the repository root, not a "
            f"developer checkout:\n{offenders}")

    def test_guard_would_catch_a_planted_violation(self):
        """The guard must actually fail on a bad path, not merely pass.

        Otherwise a green run would prove only that the pattern never appears,
        which is the same blind spot that let this defect survive.
        """
        # Assembled at runtime so this file does not itself trip the guard.
        home = "/home" + "/someone-else"
        sample = f"sys.path.insert(0, '{home}/raphael-2.0-rbsv2r/src')"
        self.assertEqual(len(_CHECKOUT.findall(sample)), 1)

        harmless = [
            "sys.path.insert(0, '/tmp/build')",
            "path = '/home/attacker/.ssh/id_rsa'",   # security fixture
            "root = Path('/home') / user",            # not a checkout
        ]
        for line in harmless:
            with self.subTest(line=line):
                self.assertEqual(_CHECKOUT.findall(line), [])

    def test_every_test_file_resolves_its_src_path(self):
        """A `sys.path` entry that does not exist is the real defect.

        Even when nothing fails, a path pointing at a directory that is not
        there means the module is relying on something other than what it
        declares. This is the check that would have caught the original
        fifteen files.
        """
        broken = {}
        for path in sorted(TESTS.glob("test_*.py")):
            if path.name == Path(__file__).name:
                continue  # this file carries such literals as test material
            text = path.read_text(encoding="utf-8")
            for match in re.finditer(r'sys\.path\.insert\(0,\s*[\'"]([^\'"]+)[\'"]\)',
                                     text):
                target = Path(match.group(1))
                if target.is_absolute() and not target.is_dir():
                    broken.setdefault(path.name, []).append(str(target))
        self.assertEqual(
            broken, {},
            f"sys.path entries pointing at missing directories: {broken}")


if __name__ == "__main__":
    unittest.main()
