# Password Security Analyzer

A polished, fully **local** web application that analyzes the strength of a password
and generates cryptographically secure passwords. No external APIs, no API keys,
no database, no internet connection required.

## Project overview

| Feature | Details |
|---|---|
| Password analysis | Length, uppercase/lowercase/digit/special counts, entropy estimate, 5-level strength verdict |
| Security checks | Too short, only letters, only numbers, repeated characters, sequential characters (`abcd`, `1234`, `qwer`...), common passwords (`password`, `qwerty`...), predictable patterns (`Password123`) |
| Password generator | User-chosen length (4–128) and character sets, powered by Python's `secrets` module |
| Session history | Non-sensitive analysis metadata (strength, score, length) shown for the current session only |
| Dashboard | Responsive dark UI: strength meter, statistics tiles, detected problems, generator, reset button |

## Architecture

```
├── backend/
│   ├── analyzer.py     Pure analysis engine (entropy, checks, penalties). No I/O.
│   ├── generator.py    CSPRNG password generation via `secrets`.
│   ├── schemas.py      Pydantic request/response models + validation rules.
│   └── main.py         FastAPI app: endpoints, error sanitization, CORS, static hosting.
├── frontend/
│   ├── index.html      Dashboard markup.
│   ├── styles.css      Responsive dark theme.
│   └── app.js          Fetch calls to the local API; in-memory history only.
├── tests/
│   ├── test_analyzer.py    Analysis engine unit tests.
│   ├── test_generator.py   Generator + schema validation tests.
│   ├── test_api.py         Endpoint, validation, and log-leak prevention tests.
│   └── test_frontend.py    Static guarantees (no localStorage/sessionStorage/cookies).
├── conftest.py             Makes `backend` importable when running pytest from the root.
├── requirements.txt
└── README.md
```

The FastAPI app serves both the JSON API under `/api/*` and the static frontend at `/`,
so everything runs in a single process on loopback. The frontend talks to the backend via
same-origin `fetch("/api/...")` calls — no cross-origin traffic is required in normal use.

## Installation

Requires Python 3.10+.

```bash
cd <project-directory>
python -m venv .venv                # optional but recommended
# Windows: .venv\Scripts\activate    |    Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

## How to run

```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Then open **http://127.0.0.1:8000** in your browser. Alternatively:
`python -m backend.main`.

Interactive API docs are available locally at `/api/docs`.

## Deploying to Vercel (optional)

The repo ships with `vercel.json` and an `api/index.py` ASGI entrypoint, so it can also run as a serverless app:

1. Push the repo to GitHub.
2. Go to [vercel.com/new](https://vercel.com/new) and import the repository.
3. Leave **Framework Preset** as "Other" and the root directory as-is; no environment variables are needed.
4. Click **Deploy**.

Vercel serves `/api/*` from the Python function and the frontend files from its CDN.
Note: this makes the app publicly reachable over HTTPS — analysis remains stateless
and nothing is persisted, but the "loopback-only" local guarantee no longer applies.

## API endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Liveness check |
| POST | `/api/analyze` | Analyze a password, return stats/checks/problems |
| POST | `/api/generate` | Generate a secure password with chosen options |

### Example requests

Analyze:

```bash
curl -X POST http://127.0.0.1:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d "{\"password\": \"Password123\"}"
```

Response (abbreviated):

```json
{
  "stats": {"length": 11, "uppercase": 1, "lowercase": 8, "digits": 2, "special": 0, "entropy_bits": 65.4},
  "strength": {"label": "Very Weak", "level": 0, "score": 7.8},
  "checks": {"too_short": false, "common_password": true, "common_pattern": true, "...": "..."},
  "problems": ["Matches or contains a well-known common password.", "..."]
}
```

Generate:

```bash
curl -X POST http://127.0.0.1:8000/api/generate \
  -H "Content-Type: application/json" \
  -d "{\"length\": 24, \"uppercase\": true, \"lowercase\": true, \"numbers\": true, \"special\": true}"
```

Response:

```json
{"password": "kR7#mQz2!vLp4@Wx9&Yt", "length": 24}
```

Validation failures return HTTP 422. Error bodies are sanitized so submitted values
(e.g. an over-long password) are never echoed back.

## How to run tests

```bash
python -m pytest -v
```

72 tests cover: very weak / strong / empty / very long inputs, character counting,
repeated & sequential characters, keyboard rows, common passwords and patterns,
Unicode/CJK input, generator options and bounds, API validation, frontend storage
guarantees, and assertion that passwords never appear in server logs.

## Security decisions

- **No persistence anywhere.** Passwords exist only as short-lived in-process strings.
  Nothing is written to files, databases, cookies, `localStorage`, `sessionStorage`,
  or `indexedDB` (enforced by tests). History shown in the UI lives only in a JS array.
- **No logging of secret material.** Log lines record only length and verdict
  (e.g. "Analyzed a password (length=17, verdict=Strong)"). A dedicated test suite
  submits probe passwords and asserts they never appear in captured logs.
- **Sanitized API errors.** A custom `RequestValidationError` handler strips `input`
  values from 422 responses; otherwise FastAPI/Pydantic would echo invalid payloads
  back to the client, leaking the very password being analyzed.
- **Secure randomness only.** The generator uses `secrets.choice` and a
  Fisher–Yates shuffle driven by `secrets.randbelow`. The `random` module is never
  imported (enforced by a meta-test), and every enabled charset is guaranteed to be
  represented at least once.
- **Input validation.** Analysis input capped at 1024 chars; generated length bounded
  to 4–128; at least one charset must be selected; types strictly enforced by Pydantic.
- **Loopback-only operation.** CORS allows localhost origins only; all traffic stays on
  `127.0.0.1`. The frontend sends `Referrer-Policy: no-referrer` and loads zero
  external resources (no CDNs, fonts, or trackers).
- **Entropy model.** Entropy = `length × log2(pool)` where the pool reflects which
  character classes are present (plus a rough bonus pool for non-ASCII characters).
  Effective entropy then subtracts penalties for detected weaknesses (common password
  −30 bits, sequences/repeats −12, etc.), and exact matches of well-known passwords are
  forced down to "Very Weak". This mirrors how real crackers treat patterns, rather
  than trusting raw math alone.

## Limitations

- The common-password list is embedded and small (~80 entries); it catches the classics,
  not dictionary attacks. For serious audits use a tool like `zxcvbn` or HaveIBeenPwned
  data (offline copies) — deliberately avoided here to keep the app dependency-free.
- Entropy estimation assumes uniform random characters; human-chosen passwords are
  weaker than the raw number suggests (penalties partially compensate).
- Special characters counted as anything non-alphanumeric (including spaces);
  non-ASCII letters get an approximate extra pool of 100 symbols.
- Keyboard-run detection covers QWERTY rows plus common fragments, not full keyboard-walk graphs.
- The app binds to `127.0.0.1`; it is designed for local single-user use, not deployment.
