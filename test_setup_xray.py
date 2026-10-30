"""The updater must resolve one official stable version or fail closed."""
import unittest
from unittest.mock import patch, MagicMock
from setup_xray import latest_version


class XrayReleaseTests(unittest.TestCase):
    def resolve(self, url):
        response = MagicMock()
        response.__enter__.return_value.geturl.return_value = url
        with patch('setup_xray.urllib.request.urlopen', return_value=response):
            return latest_version()

    def test_official_stable_release(self):
        self.assertEqual(self.resolve('https://github.com/XTLS/Xray-core/releases/tag/v26.10.29'), 'v26.10.29')

    def test_unexpected_redirect_or_prerelease_is_rejected(self):
        for url in ['https://example.com/releases/tag/v26.10.29',
                    'https://github.com/other/Xray-core/releases/tag/v26.10.29',
                    'https://github.com/XTLS/Xray-core/releases/tag/v26.10.29-beta',
                    'https://github.com/XTLS/Xray-core/releases/latest']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.resolve(url)

    def test_release_lookup_failure_is_not_silenced(self):
        with patch('setup_xray.urllib.request.urlopen', side_effect=OSError('offline')):
            with self.assertRaises(OSError):
                latest_version()
