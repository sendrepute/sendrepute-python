# SendRepute Python integration

An open-source, server-only Python client for the paid SendRepute customer
classification endpoint. This directory is installable locally as a wheel or
sdist; it is **not a claim that a package is published on PyPI**.

## Local install and tests

```sh
git clone https://github.com/sendrepute/sendrepute-python.git
cd sendrepute-python
python -m pip install '.[django]'
python -m unittest discover -s tests -v
python -m pip install build
python -m build
```

For a direct Git installation: `python -m pip install
"sendrepute @ git+https://github.com/sendrepute/sendrepute-python.git@main"`.
Use a reviewed commit hash instead of `main` for reproducible production installs.

The runtime client uses only the Python standard library. `build` is a local
packaging tool and Django is needed only for the optional backend. The package
allowlist includes only `sendrepute` and its subpackages.

The offline backend suite has been run against real Django 6.1.1 message and
backend classes. The declared optional dependency is Django 4.2 or newer, but
this repository does not claim a complete multi-version compatibility matrix.

## Generic use (Flask, FastAPI, or any server)

```python
from sendrepute import SendReputeClient

client = SendReputeClient(
    api_key=server_secret,
    paid_analysis_consent=True,  # explicit opt-in: each new input may be billed
    timeout=10,
)
result = client.classify(sender="Example Team", subject=subject, body=body)
```

Consent defaults to false. The default endpoint is fixed at
`https://www.sendrepute.com/api/v1/classify`. A deployment-specific endpoint
must use verified HTTPS, contain no credentials/query/fragment, and its origin
must also appear in the explicit `allowed_origins` constructor argument.
Message values never choose the destination. The client refuses redirects,
performs no retries, bounds inputs and responses, and returns only a fully
validated customer classification response. Errors expose safe status, code,
and request ID metadata, never credentials or request/response bodies.

Classification is a content safety signal, not a guarantee of inbox placement
or deliverability. Identical content may replay a server receipt; changed
sender, subject, body, or model is a new paid analysis.

## Explicit Django backend

Install Django separately or use the local optional extra:

```sh
python -m pip install '.[django]'
```

Then opt in explicitly:

```python
EMAIL_BACKEND = "sendrepute.django.SendReputeEmailBackend"
SENDREPUTE_ORIGINAL_EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
SENDREPUTE_API_KEY = env["SENDREPUTE_API_KEY"]
SENDREPUTE_PAID_ANALYSIS_CONSENT = True

# Defaults shown:
SENDREPUTE_POLICY_MODE = "advisory"       # or "blocking"
SENDREPUTE_SPAM_THRESHOLD = 0.90
SENDREPUTE_FAILURE_POLICY = "allow"       # or "block" (fail closed)
SENDREPUTE_ALLOW_AUTH_FAILURE = False     # auth errors block by default
SENDREPUTE_TIMEOUT = 10
SENDREPUTE_SENDER_NAME = "Example Team"   # used if From has no display name
```

Only the sender display name, subject, and combined displayed body are
transmitted for classification. The body is one bounded string containing the
primary body and every inline `text/plain`/`text/html` alternative. Recipients,
addresses, and attachments are not transmitted. The original message objects
are passed unchanged to the configured original backend, preserving its
transport, alternatives, and attachments. There is no automatic fallback to
another transport. Blocking mode rejects unsupported/non-string alternatives
and combined displayed content over the API body limit rather than analyzing
only a safer-looking subset.

Advisory mode allows messages after a successful classification. Blocking mode
rejects messages at or above the threshold. API failure handling is explicit;
authentication/permission errors block even under `allow` unless the separately
documented `SENDREPUTE_ALLOW_AUTH_FAILURE = True` is set. Do not enable global
blocking for password resets or other critical transactional mail without
deliberately choosing and testing the desired failure behavior.

The Django wrapper does not render templates, inspect attachments, expose
diagnostic callbacks, or make async calls. Callers must render bodies and
inline text/HTML alternatives before sending. Django's `fail_silently` behavior
is honored for blocked failures.

## Support and security

Use GitHub issues for reproducible, non-sensitive bugs. Account support and
private vulnerability reports: support@sendrepute.com. Never include API keys,
customer messages or unredacted logs. See [SECURITY.md](SECURITY.md).
MIT licensed; see LICENSE.
