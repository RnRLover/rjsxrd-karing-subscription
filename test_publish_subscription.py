import json
import io
from contextlib import redirect_stdout
from pathlib import Path
import subprocess
import tempfile
import unittest
from publish_subscription import publish


def git(root, *args):
    return subprocess.run(['git', *args], cwd=root, check=True, capture_output=True, text=True).stdout.strip()


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.remote, self.work = root / 'origin.git', root / 'work'
        git(root, 'init', '--bare', '--initial-branch=main', str(self.remote))
        git(root, 'clone', str(self.remote), str(self.work))
        git(self.work, 'config', 'user.email', 'test@example.com')
        git(self.work, 'config', 'user.name', 'Test')
        for name in ('subscription.json', 'report.json'):
            (self.work / name).write_text('{}\n')
        (self.work / 'ru.json').write_text('{"obsolete": true}\n')
        git(self.work, 'add', '.')
        git(self.work, 'commit', '-m', 'base')
        git(self.work, 'push', 'origin', 'main')

    def publish_quietly(self):
        # Expected fixture notices must not become real Actions annotations.
        with redirect_stdout(io.StringIO()):
            return publish(self.work)

    def test_validated_outputs_are_published(self):
        (self.work / 'subscription.json').write_text('[{"remarks":"new"}]\n')
        self.assertTrue(self.publish_quietly())
        remote = git(self.remote, 'show', 'main:subscription.json')
        self.assertEqual(json.loads(remote), [{'remarks': 'new'}])
        self.assertEqual(git(self.remote, 'ls-tree', '--name-only', 'main', '--', 'ru.json'), '')
        self.assertFalse(self.publish_quietly())

    def test_newer_source_is_preserved_without_merge_or_force_push(self):
        other = Path(self.temp.name) / 'other'
        git(Path(self.temp.name), 'clone', str(self.remote), str(other))
        git(other, 'config', 'user.email', 'test@example.com')
        git(other, 'config', 'user.name', 'Test')
        (other / 'source.py').write_text('new_source = True\n')
        git(other, 'add', '.')
        git(other, 'commit', '-m', 'new source')
        git(other, 'push', 'origin', 'main')
        latest = git(other, 'rev-parse', 'HEAD')
        (self.work / 'subscription.json').write_text('[{"remarks":"stale build"}]\n')
        self.assertFalse(self.publish_quietly())
        self.assertEqual(git(self.remote, 'rev-parse', 'main'), latest)
        self.assertEqual(json.loads(git(self.remote, 'show', 'main:subscription.json')), {})
