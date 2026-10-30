"""injection-guard: detect and strip hidden instructions in documents before an AI agent reads them."""
import glob as _glob, os as _os, sys as _sys

# optional extras (pypdf, fontTools) live in a private venv; appended so system packages win
import pwd as _pwd
_real_home = _pwd.getpwuid(_os.getuid()).pw_dir  # not $HOME: tests and sandboxes may override it
for _p in _glob.glob(_os.path.join(_real_home, ".local/opt/injection-guard-venv/lib/python3*/site-packages")):
    if _p not in _sys.path:
        _sys.path.append(_p)
