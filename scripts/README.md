# scripts

Two read-only triage helpers used by the secure-code-auditor skill. Neither
imports or runs the target project, and neither makes network calls. They read
files and print indicators; confirm everything they surface by reading the code.

## settings_scan.py

Static (AST-based) posture check for a Django settings file. It reports on
`DEBUG`, `ALLOWED_HOSTS`, `SECRET_KEY`, the `SECURE_*` / `SESSION_*` / `CSRF_*`
flags, `X_FRAME_OPTIONS`, and CORS. Values computed at runtime (from env vars,
etc.) are reported as "dynamic - verify manually" instead of guessed.

```
python scripts/settings_scan.py path/to/settings.py
```

## dangerous_patterns.py

Regex scan across a directory of `.py` files for patterns that frequently
indicate an issue: string-built SQL, client-controlled ORM identifiers,
`shell=True`, `pickle`/`yaml.load`, `fields='__all__'`, open CORS, `DEBUG=True`,
`@csrf_exempt`, disabled TLS verification, and likely hardcoded secrets.

```
python scripts/dangerous_patterns.py path/to/project
python scripts/dangerous_patterns.py .
```

Both exit 0 always; they're aids, not gates. They require only the Python
standard library (Python 3.9+).
