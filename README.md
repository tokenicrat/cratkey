# CRATKEY

A local password manager. It's dangerous to upload your password to *any* service provider since it goes through the internet jungle, so let's just not upload it.

## Usage

This script is designed for Linux. Requirements:

- Valid Python installation (and PyPI access)
- Bash

Running either of `totp` and `password` for the first time will get you a virtual environment. You can also set it up manually by:

```bash
python3 -m venv .venv
```

Scripts are kept in `.tool`. You should use shown Bash scripts to ensure virtual environment is loaded automatically.

Command line usage are kept in `.tool/{totp, password}/README`. It's very simple.

## License

The Unlicense
