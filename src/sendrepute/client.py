"""Dependency-free, server-only SendRepute classification client."""

from __future__ import annotations

import http.client
import json
import math
import ssl
from typing import Any, Callable, Mapping, Optional, Sequence
from urllib.parse import urlsplit

DEFAULT_ENDPOINT = "https://www.sendrepute.com/api"
MODELS = frozenset(("thor", "theos", "athena", "odin", "freya", "hermes", "ares", "apollo"))
MAX_SENDER = 320
MAX_SUBJECT = 998
MAX_BODY = 524_288
MAX_PAYLOAD_BYTES = 540_000
MAX_RESPONSE_BYTES = 1_048_576
MAX_TIMEOUT_SECONDS = 30.0


class SendReputeError(Exception):
    """A redacted error safe to report without message content or credentials."""

    def __init__(
        self,
        message: str,
        *,
        code: str,
        status: Optional[int] = None,
        request_id: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.request_id = request_id


class ConsentRequiredError(SendReputeError):
    pass


class ClassificationError(SendReputeError):
    pass


class TransportError(SendReputeError):
    pass


class InvalidResponseError(SendReputeError):
    pass


class AuthenticationError(SendReputeError):
    pass


class BalanceError(SendReputeError):
    pass


class RateLimitError(SendReputeError):
    pass


def _origin(parts: Any) -> str:
    port = parts.port
    default_port = port is None or port == 443
    return "https://%s%s" % (parts.hostname, "" if default_port else ":%d" % port)


def _validated_endpoint(endpoint: str, allowed_origins: Sequence[str]) -> tuple[str, int, str]:
    invalid_url = False
    try:
        parts = urlsplit(endpoint)
        port = parts.port or 443
    except (TypeError, ValueError):
        invalid_url = True
    if invalid_url:
        # Raised outside the handler so even __context__ cannot retain a
        # malformed URL that may contain deployment credentials.
        raise ValueError("endpoint must be a valid absolute HTTPS URL")
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
    ):
        raise ValueError("endpoint must be HTTPS and contain no credentials, query, or fragment")
    normalized_allowed = set()
    for allowed in allowed_origins:
        candidate = urlsplit(allowed)
        if (
            candidate.scheme != "https"
            or not candidate.hostname
            or candidate.path not in ("", "/")
            or candidate.query
            or candidate.fragment
            or candidate.username is not None
            or candidate.password is not None
        ):
            raise ValueError("allowed origins must be HTTPS origins without paths or credentials")
        normalized_allowed.add(_origin(candidate))
    if _origin(parts) not in normalized_allowed:
        raise ValueError("endpoint origin is not explicitly trusted")
    path = parts.path.rstrip("/")
    if not path:
        raise ValueError("endpoint must include a fixed API path")
    return parts.hostname, port, path


def _string(value: Any, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError("%s must be a non-empty string of at most %d characters" % (name, maximum))
    return value


def _exact_keys(value: Any, required: set[str], optional: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("%s must be an object" % name)
    keys = set(value)
    if not required.issubset(keys) or not keys.issubset(required | optional):
        raise ValueError("%s has an invalid shape" % name)
    return value


def _validate_result(payload: Any) -> dict[str, Any]:
    top = _exact_keys(payload, {"requestId", "model", "result", "billing"}, set(), "response")
    _string(top["requestId"], "requestId", 128)
    if top["model"] not in MODELS:
        raise ValueError("model is invalid")
    billing = _exact_keys(top["billing"], {"chargedMillicents", "replayed"}, set(), "billing")
    charged = billing["chargedMillicents"]
    if isinstance(charged, bool) or not isinstance(charged, (int, float)) or not math.isfinite(charged) or charged < 0 or charged % 1:
        raise ValueError("chargedMillicents is invalid")
    if not isinstance(billing["replayed"], bool):
        raise ValueError("replayed is invalid")
    result = _exact_keys(
        top["result"],
        {"label", "spamProbability", "confidence", "reasons", "flaggedTerms", "analyzedFields", "modelVersion", "analyzedAt"},
        {"flaggedTermCount", "contentAudit"},
        "result",
    )
    if result["label"] not in ("inbox", "spam") or result["confidence"] not in ("low", "medium", "high"):
        raise ValueError("classification label or confidence is invalid")
    probability = result["spamProbability"]
    if isinstance(probability, bool) or not isinstance(probability, (int, float)) or not math.isfinite(probability) or not 0 <= probability <= 1:
        raise ValueError("spamProbability must be finite and between 0 and 1")
    for field in ("reasons", "flaggedTerms", "analyzedFields"):
        if not isinstance(result[field], list):
            raise ValueError("%s must be an array" % field)
    for reason in result["reasons"]:
        item = _exact_keys(reason, {"signal", "detail", "weight"}, set(), "reason")
        if not isinstance(item["signal"], str) or not isinstance(item["detail"], str):
            raise ValueError("reason strings are invalid")
        weight = item["weight"]
        if isinstance(weight, bool) or not isinstance(weight, (int, float)) or not math.isfinite(weight):
            raise ValueError("reason weight is invalid")
    if not all(isinstance(value, str) for value in result["flaggedTerms"] + result["analyzedFields"]):
        raise ValueError("classification term and field arrays must contain strings")
    for field in ("modelVersion", "analyzedAt"):
        if not isinstance(result[field], str):
            raise ValueError("%s must be a string" % field)
    if "flaggedTermCount" in result:
        count = result["flaggedTermCount"]
        if isinstance(count, bool) or not isinstance(count, (int, float)) or not math.isfinite(count) or count < 0 or count % 1:
            raise ValueError("flaggedTermCount is invalid")
    if "contentAudit" in result:
        _validate_content_audit(result["contentAudit"])
    return payload


def _whole_number(value: Any, name: str, maximum: Optional[int] = None) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
        or value % 1
        or (maximum is not None and value > maximum)
    ):
        raise ValueError("%s is invalid" % name)


def _validate_content_audit(value: Any) -> None:
    audit = _exact_keys(
        value,
        {
            "score", "grade", "summary", "counts", "totalIssues", "criticalCount",
            "warningCount", "suggestionCount", "issues", "goodPractices", "inputTruncated",
        },
        {"homoglyphTerms"},
        "contentAudit",
    )
    _whole_number(audit["score"], "contentAudit.score", 100)
    if audit["grade"] not in ("A", "B", "C", "D", "F"):
        raise ValueError("contentAudit.grade is invalid")
    if audit["summary"] not in ("fix_critical", "fix_warnings", "review_suggestions", "looks_good"):
        raise ValueError("contentAudit.summary is invalid")
    counts = _exact_keys(audit["counts"], {"words", "links", "images", "triggerPhrases"}, set(), "contentAudit.counts")
    for name, count in counts.items():
        _whole_number(count, "contentAudit.counts." + name)
    for name in ("totalIssues", "criticalCount", "warningCount", "suggestionCount"):
        _whole_number(audit[name], "contentAudit." + name)
    if not isinstance(audit["inputTruncated"], bool):
        raise ValueError("contentAudit.inputTruncated is invalid")
    if not isinstance(audit["issues"], list) or len(audit["issues"]) > 50:
        raise ValueError("contentAudit.issues is invalid")
    for value in audit["issues"]:
        issue = _exact_keys(value, {"code", "category", "severity", "deduction", "evidence"}, set(), "contentAudit.issue")
        if not isinstance(issue["code"], str) or not isinstance(issue["evidence"], str) or len(issue["evidence"]) > 200:
            raise ValueError("contentAudit issue strings are invalid")
        if issue["category"] not in ("subject", "content", "links", "structure", "compliance"):
            raise ValueError("contentAudit issue category is invalid")
        if issue["severity"] not in ("critical", "warning", "suggestion"):
            raise ValueError("contentAudit issue severity is invalid")
        _whole_number(issue["deduction"], "contentAudit.issue.deduction", 100)
    if not isinstance(audit["goodPractices"], list) or len(audit["goodPractices"]) > 20:
        raise ValueError("contentAudit.goodPractices is invalid")
    for value in audit["goodPractices"]:
        practice = _exact_keys(value, {"code", "category"}, set(), "contentAudit.goodPractice")
        if not isinstance(practice["code"], str) or practice["category"] not in ("subject", "content", "links", "structure", "compliance"):
            raise ValueError("contentAudit good practice is invalid")
    terms = audit.get("homoglyphTerms", [])
    if not isinstance(terms, list) or len(terms) > 20 or not all(isinstance(term, str) and len(term) <= 120 for term in terms):
        raise ValueError("contentAudit.homoglyphTerms is invalid")


class SendReputeClient:
    """Classify email content using one paid API call and no automatic retries."""

    def __init__(
        self,
        api_key: str,
        *,
        endpoint: str = DEFAULT_ENDPOINT,
        allowed_origins: Sequence[str] = ("https://www.sendrepute.com",),
        timeout: float = 10.0,
        paid_analysis_consent: bool = False,
        _connection_factory: Optional[Callable[..., Any]] = None,
    ) -> None:
        if not isinstance(api_key, str) or not api_key.strip() or "\r" in api_key or "\n" in api_key:
            raise ValueError("api_key is required and must be a valid header value")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= MAX_TIMEOUT_SECONDS:
            raise ValueError("timeout must be greater than zero and at most 30 seconds")
        if not isinstance(paid_analysis_consent, bool):
            raise ValueError("paid_analysis_consent must be a boolean")
        self._host, self._port, self._base_path = _validated_endpoint(endpoint, allowed_origins)
        self._api_key = api_key
        self._timeout = float(timeout)
        self._paid_analysis_consent = paid_analysis_consent
        self._connection_factory = _connection_factory or http.client.HTTPSConnection

    def classify(
        self,
        *,
        sender: str,
        subject: str,
        body: str,
        model: Optional[str] = None,
        paid_analysis_consent: Optional[bool] = None,
    ) -> dict[str, Any]:
        """Return the exact validated API response. This call may debit the account."""
        consent = self._paid_analysis_consent if paid_analysis_consent is None else paid_analysis_consent
        if consent is not True:
            raise ConsentRequiredError(
                "Paid classification requires explicit consent.",
                code="CONSENT_REQUIRED",
            )
        request: dict[str, Any] = {
            "sender": _string(sender, "sender", MAX_SENDER),
            "subject": _string(subject, "subject", MAX_SUBJECT),
            "body": _string(body, "body", MAX_BODY),
        }
        if model is not None:
            if model not in MODELS:
                raise ValueError("model is not supported")
            request["model"] = model
        encoded = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_PAYLOAD_BYTES:
            raise ValueError("encoded request is too large")

        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        connection = self._connection_factory(
            self._host,
            self._port,
            timeout=self._timeout,
            context=context,
        )
        transport_failed = False
        try:
            connection.request(
                "POST",
                self._base_path + "/v1/classify",
                body=encoded,
                headers={
                    "Accept": "application/json",
                    "Authorization": "Bearer " + self._api_key,
                    "Content-Type": "application/json",
                    "Content-Length": str(len(encoded)),
                },
            )
            response = connection.getresponse()
            # Authentication and authorization are classified from the status
            # alone. Never parse, log, or trust an HTML/oversized auth response.
            if response.status in (401, 403):
                raise AuthenticationError(
                    "SendRepute authentication or permission failed.",
                    code="AUTHENTICATION_ERROR",
                    status=response.status,
                )
            length = response.getheader("Content-Length")
            if length is not None:
                try:
                    if int(length) > MAX_RESPONSE_BYTES:
                        raise InvalidResponseError("SendRepute response was too large.", code="RESPONSE_TOO_LARGE", status=response.status)
                except ValueError:
                    raise InvalidResponseError("SendRepute response length was invalid.", code="INVALID_RESPONSE", status=response.status) from None
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise InvalidResponseError("SendRepute response was too large.", code="RESPONSE_TOO_LARGE", status=response.status)
        except SendReputeError:
            raise
        except (OSError, http.client.HTTPException, TimeoutError):
            transport_failed = True
        finally:
            try:
                connection.close()
            except Exception:
                # Closing must not replace a safely categorized result with a
                # transport implementation's potentially sensitive exception.
                pass
        if transport_failed:
            # Raised outside the handler: neither __cause__ nor __context__ can
            # retain credentials, DNS/proxy details, or request content.
            raise TransportError("SendRepute transport request failed.", code="TRANSPORT_ERROR")

        if 300 <= response.status < 400:
            raise TransportError("SendRepute redirects are refused.", code="REDIRECT_REFUSED", status=response.status)
        invalid_json = False
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            invalid_json = True
        if invalid_json:
            raise InvalidResponseError("SendRepute returned an invalid JSON response.", code="INVALID_RESPONSE", status=response.status)
        if not 200 <= response.status < 300:
            self._raise_api_error(response.status, decoded)
        invalid_contract = False
        try:
            validated = _validate_result(decoded)
        except ValueError:
            invalid_contract = True
        if invalid_contract:
            raise InvalidResponseError("SendRepute returned an invalid response.", code="INVALID_RESPONSE", status=response.status)
        return validated

    @staticmethod
    def _raise_api_error(status: int, payload: Any) -> None:
        code = "API_ERROR"
        request_id = None
        if isinstance(payload, dict):
            error = payload.get("error")
            raw_code = error.get("code") if isinstance(error, dict) else None
            raw_request_id = payload.get("requestId")
            if isinstance(raw_code, str) and 0 < len(raw_code) <= 128:
                code = raw_code
            if isinstance(raw_request_id, str) and 0 < len(raw_request_id) <= 128:
                request_id = raw_request_id
        options = {"code": code, "status": status, "request_id": request_id}
        if status in (401, 403):
            raise AuthenticationError("SendRepute authentication or permission failed.", **options)
        if status == 402:
            raise BalanceError("SendRepute account balance or spend limit is insufficient.", **options)
        if status == 429:
            raise RateLimitError("SendRepute rate limit was exceeded.", **options)
        raise ClassificationError("SendRepute classification request failed.", **options)
