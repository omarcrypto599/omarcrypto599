# Password Security Analyzer 🔐

A small, privacy-conscious Python command-line tool that evaluates password quality using transparent, local checks.

## Features

- Checks password length and character variety.
- Flags a small set of commonly used passwords.
- Detects repeated characters and simple sequential patterns.
- Produces actionable feedback and a score.
- Reads passwords with `getpass` so the input is not echoed in the terminal.
- Does not transmit, save, or log passwords.

## Requirements

- Python 3.10+
- No third-party dependencies

## Run

From this directory:

```bash
python password_analyzer.py
```

Run the tests:

```bash
python -m unittest -v
```

## How scoring works

The analyzer awards points for length and character variety, then applies penalties for common-password matches and predictable patterns. The score is a learning aid, not a guarantee that a password is secure.

## Limitations

- This tool does not check passwords against breached-password databases.
- It cannot determine whether a password has been reused elsewhere.
- It does not replace a password manager, multi-factor authentication, or a professional security review.
- Avoid entering a real password into tools you do not trust. For experimentation, use a unique test password.

## Security notes

Password evaluation happens locally in the process. The tool does not make network requests and does not write the entered password to disk.

## Learning outcomes

This project demonstrates Python functions, input handling, string analysis, defensive programming, unit testing, and basic security awareness.

## Disclaimer

Created for educational purposes. Use only with passwords you own or have permission to assess.
