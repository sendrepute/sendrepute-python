"""Explicit opt-in Django email backend wrapper."""

from __future__ import annotations

from email.utils import parseaddr
from typing import Any

from .client import MAX_BODY, AuthenticationError, SendReputeClient, SendReputeError

try:
    from django.conf import settings
    from django.core.mail.backends.base import BaseEmailBackend
    from django.utils.module_loading import import_string
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError("Install sendrepute with the 'django' extra to use this backend") from exc


class SendReputeEmailBackend(BaseEmailBackend):
    """Classify messages, then delegate unchanged messages to another backend."""

    def __init__(self, fail_silently: bool = False, **kwargs: Any) -> None:
        # Set this explicitly for Django 6.1+/7 while remaining compatible
        # with older supported releases where BaseEmailBackend accepted it.
        super().__init__()
        self.fail_silently = fail_silently
        backend_path = getattr(settings, "SENDREPUTE_ORIGINAL_EMAIL_BACKEND", "")
        if not backend_path or backend_path == "%s.%s" % (self.__class__.__module__, self.__class__.__name__):
            raise ValueError("SENDREPUTE_ORIGINAL_EMAIL_BACKEND must name a different Django backend")
        backend_class = import_string(backend_path)
        self._backend = backend_class(fail_silently=fail_silently, **kwargs)
        self._mode = getattr(settings, "SENDREPUTE_POLICY_MODE", "advisory")
        self._failure = getattr(settings, "SENDREPUTE_FAILURE_POLICY", "allow")
        self._threshold = getattr(settings, "SENDREPUTE_SPAM_THRESHOLD", 0.9)
        if self._mode not in ("advisory", "blocking") or self._failure not in ("allow", "block"):
            raise ValueError("SendRepute policy settings are invalid")
        if isinstance(self._threshold, bool) or not isinstance(self._threshold, (int, float)) or not 0 <= self._threshold <= 1:
            raise ValueError("SENDREPUTE_SPAM_THRESHOLD must be between 0 and 1")
        self._allow_auth_failure = getattr(settings, "SENDREPUTE_ALLOW_AUTH_FAILURE", False) is True
        self._client = SendReputeClient(
            getattr(settings, "SENDREPUTE_API_KEY", ""),
            endpoint=getattr(settings, "SENDREPUTE_API_ENDPOINT", "https://www.sendrepute.com/api"),
            allowed_origins=getattr(settings, "SENDREPUTE_ALLOWED_ORIGINS", ("https://www.sendrepute.com",)),
            timeout=getattr(settings, "SENDREPUTE_TIMEOUT", 10.0),
            paid_analysis_consent=getattr(settings, "SENDREPUTE_PAID_ANALYSIS_CONSENT", False),
        )

    def open(self) -> bool:
        return self._backend.open()

    def close(self) -> None:
        self._backend.close()

    def _classification_body(self, message: Any) -> str:
        body = message.body
        if not isinstance(body, str):
            raise UnsupportedMessageError("The primary email body must be an in-memory string.")
        displayed = [body]
        for alternative in getattr(message, "alternatives", ()) or ():
            content = getattr(alternative, "content", None)
            mimetype = getattr(alternative, "mimetype", None)
            # Django versions before named alternatives expose two-tuples.
            if content is None and isinstance(alternative, (tuple, list)) and len(alternative) == 2:
                content, mimetype = alternative
            if mimetype not in ("text/plain", "text/html") or not isinstance(content, str):
                raise UnsupportedMessageError(
                    "Only in-memory text/plain and text/html alternatives can be classified."
                )
            displayed.append(content)
        combined = "\n\n".join(displayed)
        if not combined or len(combined) > MAX_BODY:
            raise UnsupportedMessageError("Combined displayed email content is empty or too large.")
        return combined

    def send_messages(self, email_messages: Any) -> int:
        if not email_messages:
            return 0
        allowed = []
        for message in email_messages:
            try:
                display_name, _address = parseaddr(message.from_email or "")
                sender = display_name or getattr(settings, "SENDREPUTE_SENDER_NAME", "")
                result = self._client.classify(
                    sender=sender,
                    subject=message.subject,
                    body=self._classification_body(message),
                    model=getattr(settings, "SENDREPUTE_MODEL", None),
                )
                blocked = self._mode == "blocking" and result["result"]["spamProbability"] >= self._threshold
                if not blocked:
                    allowed.append(message)
            except SendReputeError as exc:
                auth_must_block = isinstance(exc, AuthenticationError) and not self._allow_auth_failure
                if auth_must_block or self._failure == "block":
                    if self.fail_silently:
                        continue
                    raise
                allowed.append(message)
            except (TypeError, ValueError) as exc:
                unsupported_must_block = isinstance(exc, UnsupportedMessageError) and self._mode == "blocking"
                if unsupported_must_block or self._failure == "block":
                    if self.fail_silently:
                        continue
                    raise
                allowed.append(message)
        # Original objects are passed through; recipients, alternatives and
        # attachments are neither inspected nor copied by this wrapper.
        return self._backend.send_messages(allowed) if allowed else 0


class UnsupportedMessageError(ValueError):
    """Displayed content cannot be safely represented in one bounded request."""
