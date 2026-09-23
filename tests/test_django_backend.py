"""Offline integration tests against the installed real Django package."""

import unittest

from django.conf import settings

if not settings.configured:
    settings.configure(
        DEFAULT_CHARSET="utf-8",
        SENDREPUTE_ORIGINAL_EMAIL_BACKEND="test_django_backend.RecordingBackend",
        SENDREPUTE_API_KEY="secret",
        SENDREPUTE_PAID_ANALYSIS_CONSENT=True,
        SENDREPUTE_SENDER_NAME="Fallback Sender",
    )

import django
django.setup()

from django.core.mail import EmailMultiAlternatives
from django.core.mail.backends.base import BaseEmailBackend

from sendrepute import AuthenticationError
from sendrepute.django import SendReputeEmailBackend, UnsupportedMessageError


class RecordingBackend(BaseEmailBackend):
    def __init__(self, **kwargs):
        fail_silently = kwargs.pop("fail_silently", False)
        super().__init__(**kwargs)
        self.fail_silently = fail_silently
        self.received = None

    def open(self):
        return True

    def close(self):
        pass

    def send_messages(self, messages):
        self.received = messages
        return len(messages)


class RecordingClient:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = []

    def classify(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return self.result


class DjangoBackendTests(unittest.TestCase):
    def setUp(self):
        settings.SENDREPUTE_POLICY_MODE = "advisory"
        settings.SENDREPUTE_FAILURE_POLICY = "allow"
        settings.SENDREPUTE_ALLOW_AUTH_FAILURE = False
        settings.SENDREPUTE_SPAM_THRESHOLD = 0.9
        self.backend = SendReputeEmailBackend()

    @staticmethod
    def message():
        message = EmailMultiAlternatives(
            subject="Subject",
            body="Plain body",
            from_email="Example Team <sender@example.test>",
            to=["private-recipient@example.test"],
        )
        message.attach_alternative("<p>MALICIOUS HTML</p>", "text/html")
        message.attach("private.txt", b"private", "text/plain")
        return message

    def test_real_django_combines_all_displayed_alternatives_and_preserves_message(self):
        recording = RecordingClient({"result": {"spamProbability": 0.1}})
        self.backend._client = recording
        message = self.message()
        self.assertEqual(self.backend.send_messages([message]), 1)
        self.assertEqual(
            recording.calls,
            [{
                "sender": "Example Team",
                "subject": "Subject",
                "body": "Plain body\n\n<p>MALICIOUS HTML</p>",
                "model": None,
            }],
        )
        self.assertIs(self.backend._backend.received[0], message)
        self.assertEqual(len(message.attachments), 1)
        self.assertEqual(len(message.alternatives), 1)

    def test_malicious_html_alternative_can_trigger_block(self):
        self.backend._mode = "blocking"
        self.backend._client = RecordingClient({"result": {"spamProbability": 0.95}})
        self.assertEqual(self.backend.send_messages([self.message()]), 0)
        self.assertIn("MALICIOUS HTML", self.backend._client.calls[0]["body"])
        self.assertIsNone(self.backend._backend.received)

    def test_unsupported_alternative_is_rejected_in_blocking_even_failure_allow(self):
        self.backend._mode = "blocking"
        message = self.message()
        message.attach_alternative(b"binary", "application/octet-stream")
        with self.assertRaises(UnsupportedMessageError):
            self.backend.send_messages([message])
        self.assertIsNone(self.backend._backend.received)

    def test_advisory_does_not_silently_block(self):
        self.backend._client = RecordingClient({"result": {"spamProbability": 1.0}})
        self.assertEqual(self.backend.send_messages([self.message()]), 1)

    def test_auth_failure_requires_separate_explicit_allow_setting(self):
        error = AuthenticationError("redacted", code="AUTH", status=401)
        self.backend._client = RecordingClient(error=error)
        with self.assertRaises(AuthenticationError):
            self.backend.send_messages([self.message()])
        self.assertIsNone(self.backend._backend.received)
        self.backend._allow_auth_failure = True
        self.assertEqual(self.backend.send_messages([self.message()]), 1)


if __name__ == "__main__":
    unittest.main()