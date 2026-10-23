"""Endpoint tests: python -m unittest discover -s tests -v.

Only Flask is needed. ML imports are stubbed and no model artifact is opened.
"""
import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch


class ModelEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            'url_model_under_test', Path(__file__).resolve().parents[1] / 'model.py')
        cls.model = importlib.util.module_from_spec(spec)
        cls.joblib = Mock()
        cls.joblib.load.side_effect = AssertionError('Model loading forbidden in endpoint tests')
        with patch.dict(sys.modules, {
            'pandas': Mock(), 'numpy': Mock(), 'tld': Mock(), 'joblib': cls.joblib,
        }):
            spec.loader.exec_module(cls.model)
        cls.model.app.config['TESTING'] = True

    def setUp(self):
        self.client = self.model.app.test_client()
        self.predictor_patch = patch.object(self.model, 'predict_model', return_value=2)
        self.predictor = self.predictor_patch.start()
        self.addCleanup(self.predictor_patch.stop)

    def assert_invalid(self, data):
        response = self.client.post('/model', data=data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json(), {
            'error': 'Enter a valid HTTP or HTTPS URL with a hostname.'})
        self.predictor.assert_not_called()
        self.joblib.load.assert_not_called()

    def test_missing_url(self):
        self.assert_invalid({})

    def test_empty_url(self):
        for url in ('', ' ', '\t\n'):
            with self.subTest(url=url):
                self.assert_invalid({'url': url})

    def test_malformed_urls(self):
        for url in ('not a url', 'example.com', 'https://', '/relative',
                    'ftp://example.com', 'javascript:alert(1)',
                    'https://[broken', 'https://example.com:bad',
                    'https://example.com:65536', 'https://example.com:0',
                    'https://exa mple.com', 'https://example.com/\nsecret',
                    'https://example.com/\x00secret', 'https://exa\\mple.com',
                    'https://%20/', 'https://)/', 'https://-example.com',
                    'https://example..com'):
            with self.subTest(url=url):
                self.assert_invalid({'url': url})

    def test_valid_urls_preserve_prediction_contract(self):
        for url in ('https://example.com', 'http://127.0.0.1/path',
                    'https://[::1]:8443/path',
                    'https://user:pass@example.com/login?token=private#fragment'):
            with self.subTest(url=url):
                self.predictor.reset_mock()
                with contextlib.redirect_stdout(io.StringIO()) as stdout:
                    response = self.client.post('/model', data={'url': url})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json(), {'result': {'output': 2}})
                self.predictor.assert_called_once_with(url)
                self.assertEqual(stdout.getvalue(), '')
                self.joblib.load.assert_not_called()

    def test_get_without_form_is_json_error(self):
        response = self.client.get('/model')
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', response.get_json())
        self.predictor.assert_not_called()


if __name__ == '__main__':
    unittest.main()
