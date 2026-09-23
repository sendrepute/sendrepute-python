import json
import ssl
import unittest

from sendrepute import (
    AuthenticationError,
    BalanceError,
    ConsentRequiredError,
    InvalidResponseError,
    RateLimitError,
    SendReputeClient,
    TransportError,
)


def valid_response(probability=0.2):
    return {
        "requestId": "req-safe",
        "model": "thor",
        "result": {
            "label": "inbox",
            "spamProbability": probability,
            "confidence": "high",
            "reasons": [],
            "flaggedTerms": [],
            "analyzedFields": ["subject", "body"],
            "modelVersion": "1",
            "analyzedAt": "2025-01-01T00:00:00Z",
        },
        "billing": {"chargedMillicents": 1, "replayed": False},
    }


class Response:
    def __init__(self, status=200, payload=None, headers=None, raw=None):
        self.status = status
        self._raw = raw if raw is not None else json.dumps(payload if payload is not None else valid_response()).encode()
        self._headers = headers or {}
        self.read_called = False

    def getheader(self, key):
        return self._headers.get(key)

    def read(self, amount):
        self.read_called = True
        return self._raw[:amount]


class Connection:
    def __init__(self, response, capture, host, port, **kwargs):
        capture["host"] = host
        capture["port"] = port
        capture.update(kwargs)
        self.response = response
        self.capture = capture

    def request(self, method, path, body, headers):
        self.capture.update(method=method, path=path, body=body, headers=headers)

    def getresponse(self):
        return self.response

    def close(self):
        self.capture["closed"] = True


def client(response=None, **kwargs):
    capture = {}

    def factory(host, port, **options):
        return Connection(response or Response(), capture, host, port, **options)

    instance = SendReputeClient("top-secret", paid_analysis_consent=True, _connection_factory=factory, **kwargs)
    return instance, capture


class ClientTests(unittest.TestCase):
    def test_consent_defaults_off_and_makes_no_connection(self):
        calls = []
        value = SendReputeClient("secret", _connection_factory=lambda *a, **k: calls.append(a))
        with self.assertRaises(ConsentRequiredError):
            value.classify(sender="Sender", subject="Subject", body="Body")
        self.assertEqual(calls, [])

    def test_fixed_path_tls_and_only_three_content_fields(self):
        value, capture = client()
        result = value.classify(sender="Sender", subject="Subject", body="Body")
        self.assertEqual(result["requestId"], "req-safe")
        self.assertEqual(capture["host"], "www.sendrepute.com")
        self.assertEqual(capture["path"], "/api/v1/classify")
        self.assertEqual(json.loads(capture["body"]), {"sender": "Sender", "subject": "Subject", "body": "Body"})
        self.assertEqual(capture["context"].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(capture["context"].check_hostname)

    def test_endpoint_requires_https_allowlist_and_no_url_metadata(self):
        for endpoint in (
            "http://www.sendrepute.com/api",
            "https://user@www.sendrepute.com/api",
            "https://www.sendrepute.com/api?q=1",
            "https://evil.example/api",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                SendReputeClient("secret", endpoint=endpoint)

    def test_redirect_is_not_followed(self):
        value, capture = client(Response(302, {}, {"Location": "https://evil.example"}))
        with self.assertRaises(TransportError) as raised:
            value.classify(sender="Sender", subject="Subject", body="Body")
        self.assertEqual(raised.exception.code, "REDIRECT_REFUSED")
        self.assertEqual(capture["path"], "/api/v1/classify")

    def test_invalid_and_nonfinite_probability_rejected(self):
        for probability in (float("nan"), float("inf"), -0.1, 1.1):
            value, _ = client(Response(payload=valid_response(probability)))
            with self.subTest(probability=probability), self.assertRaises(InvalidResponseError):
                value.classify(sender="Sender", subject="Subject", body="Body")

    def test_error_categories_are_redacted(self):
        secret_body = "private body"
        payload = {"error": {"code": "BAD_SECRET", "message": secret_body}, "requestId": "req-1"}
        for status, kind in ((401, AuthenticationError), (402, BalanceError), (429, RateLimitError)):
            value, _ = client(Response(status, payload))
            with self.subTest(status=status), self.assertRaises(kind) as raised:
                value.classify(sender="Sender", subject="Subject", body=secret_body)
            self.assertNotIn(secret_body, str(raised.exception))
            self.assertNotIn("top-secret", str(raised.exception))
            self.assertEqual(raised.exception.request_id, None if status == 401 else "req-1")

    def test_auth_status_wins_over_html_invalid_and_oversized_bodies(self):
        for status in (401, 403):
            for raw, headers in (
                (b"<html>proxy login</html>", {}),
                (b"x" * 1_048_577, {"Content-Length": "1048577"}),
            ):
                response = Response(status, raw=raw, headers=headers)
                value, _ = client(response)
                with self.subTest(status=status, size=len(raw)), self.assertRaises(AuthenticationError) as raised:
                    value.classify(sender="Sender", subject="Subject", body="Body")
                self.assertFalse(response.read_called)
                self.assertIsNone(raised.exception.__cause__)
                self.assertIsNone(raised.exception.__context__)

    def test_response_size_and_shape_are_bounded(self):
        value, _ = client(Response(headers={"Content-Length": "1048577"}))
        with self.assertRaises(InvalidResponseError):
            value.classify(sender="Sender", subject="Subject", body="Body")
        malformed = valid_response()
        malformed["unexpected"] = True
        value, _ = client(Response(payload=malformed))
        with self.assertRaises(InvalidResponseError):
            value.classify(sender="Sender", subject="Subject", body="Body")

    def test_no_hidden_retry_on_transport_failure(self):
        calls = []

        class Broken:
            def __init__(self, *args, **kwargs):
                calls.append(1)

            def request(self, *args, **kwargs):
                raise OSError("contains private network detail")

            def close(self):
                pass

        value = SendReputeClient("secret", paid_analysis_consent=True, _connection_factory=Broken)
        with self.assertRaises(TransportError) as raised:
            value.classify(sender="Sender", subject="Subject", body="Body")
        self.assertEqual(len(calls), 1)
        self.assertNotIn("private", str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)


if __name__ == "__main__":
    unittest.main()