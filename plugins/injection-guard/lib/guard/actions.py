"""Judge an action by what it does and where it came from, not by how the text that asked for it sounds (round 7).

A masked injection reads like a normal setup guide: "add this MCP server", "run make to finish the install". Wording
cannot separate it from a real guide. Effects can: which program will run, which server is added, which permission is
granted, which package is fetched, and whether the code comes from something downloaded in this session. The hook
uses these helpers to show the user that effect, with the source, before it happens.

Everything here is pure (no hook I/O) so it can be tested directly.
"""
import json, os, re, shlex

# ---------------------------------------------------------------- code downloaded in this session
CLONE_OUT = re.compile(r"Cloning into (?:bare repository )?'([^'\n]+)'")


def _tokens(cmd):
    try:
        lex = shlex.shlex(cmd.replace("\\\n", " ").replace("\n", " ; "), posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        toks = list(lex)
    except ValueError:
        return [cmd.split()]
    segs, cur = [], []
    for t in toks:
        if t in (";", "&&", "||", "|", "&", "|&", "(", ")"):
            if cur:
                segs.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        segs.append(cur)
    return segs


def _abs(p, cwd):
    p = os.path.expanduser(p)
    return os.path.normpath(p if os.path.isabs(p) else os.path.join(cwd or ".", p))


def _args(seg, start, takes_value=()):
    """Positional arguments after index `start`, skipping options and the values of options in `takes_value`."""
    out, skip = [], False
    for t in seg[start:]:
        if skip:
            skip = False
            continue
        if t.startswith("-"):
            if t in takes_value:
                skip = True
            continue
        out.append(t)
    return out


def walk_segments(cmd, cwd):
    """(segment, effective cwd) for each simple command, following `cd DIR &&` within the command."""
    here = cwd or "."
    for seg in _tokens(cmd):
        while seg and re.match(r"^[A-Za-z_]\w*=", seg[0]):
            seg = seg[1:]
        if not seg:
            continue
        if seg[0] in ("cd", "pushd") and len(seg) > 1:
            here = _abs(seg[1], here)
            continue
        yield seg, here


def downloads(cmd, cwd, output=""):
    """Directories and files a command fetched from outside: git clone, gh repo clone, archive extraction, curl -o, wget."""
    found = []
    for seg, here in walk_segments(cmd, cwd):
        w = os.path.basename(seg[0])
        if w == "git" and "clone" in seg:
            pos = _args(seg, seg.index("clone") + 1, ("-b", "--branch", "--depth", "-o", "--origin", "-c", "--config", "--reference",
                                                      "--separate-git-dir", "-j", "--jobs", "--filter", "-u", "--upload-pack", "--template"))
            if pos:
                name = pos[1] if len(pos) > 1 else re.sub(r"\.git$", "", pos[0].rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1])
                found.append(_abs(name, here))
        elif w == "gh" and seg[1:3] == ["repo", "clone"]:
            pos = _args(seg, 3)
            if pos:
                found.append(_abs(pos[1] if len(pos) > 1 else pos[0].rstrip("/").rsplit("/", 1)[-1], here))
        elif w in ("unzip", "7z", "7za", "unrar", "bsdtar") or (w == "tar" and any(re.match(r"^-?[a-zA-Z]*x", t) for t in seg[1:2]) or "--extract" in seg):
            dest = None
            for i, t in enumerate(seg):
                if t in ("-d", "-C", "--directory") and i + 1 < len(seg):
                    dest = seg[i + 1]
                elif t.startswith("-o") and w.startswith("7z") and len(t) > 2:
                    dest = t[2:]
                elif t.startswith("--directory="):
                    dest = t.split("=", 1)[1]
            if dest:
                found.append(_abs(dest, here))
            else:  # into the current folder: the archive's top-level folder name is in the listing, not knowable here
                arch = next((a for a in _args(seg, 1, ("-f",)) if re.search(r"\.(zip|tar|tgz|gz|bz2|xz|zst|7z|rar)$", a)), None)
                if arch:
                    found.append(_abs(re.sub(r"(\.tar)?\.(zip|tar|tgz|gz|bz2|xz|zst|7z|rar)$", "", os.path.basename(arch)), here))
        elif w in ("curl", "wget"):
            for i, t in enumerate(seg):
                if t in ("-o", "--output", "-O", "--output-document", "-P", "--directory-prefix") and i + 1 < len(seg):
                    if not (w == "curl" and t == "-O"):
                        found.append(_abs(seg[i + 1], here))
    for m in CLONE_OUT.finditer(output or ""):
        found.append(_abs(m.group(1), cwd))
    return list(dict.fromkeys(found))


def inside(path, roots):
    """The first root that contains path, or None."""
    rp = os.path.realpath(path)
    for r in roots:
        rr = os.path.realpath(r)
        if rp == rr or rp.startswith(rr + os.sep):
            return r
    return None


# programs that run code from the folder they are run in (or from the path they are given)
_BUILD = re.compile(r"^(pytest|py\.test|make|gmake|cmake|ninja|meson|tox|nox|pre-commit|just|rake|gradle|gradlew|mvn|mvnw|ant|sbt|"
                    r"direnv|configure|autogen\.sh|bootstrap\.sh|install\.sh|setup\.sh|build\.sh|hatch|pdm|poetry|pipenv|bundle|composer|"
                    r"cargo|go|npm|yarn|pnpm|bun|deno|npx|bunx|uv|pip[\d.]*|python[\d.]*|node|docker|docker-compose|podman)$")
_SUB = {
    "npm": {"install", "i", "ci", "test", "t", "run", "run-script", "start", "exec", "x", "rebuild", "pack", "publish", "link"},
    "yarn": {"", "install", "add", "test", "run", "start", "build", "dlx"},
    "pnpm": {"install", "i", "add", "test", "run", "start", "exec", "dlx"},
    "bun": {"install", "i", "add", "test", "run", "x"},
    "cargo": {"build", "run", "test", "check", "bench", "install", "clippy"},
    "go": {"generate", "run", "test", "build", "install", "vet"},
    "uv": {"sync", "run", "pip", "build"},
    "poetry": {"install", "run", "build"}, "pipenv": {"install", "run", "sync"}, "pdm": {"install", "run", "sync", "build"},
    "hatch": {"run", "build", "env", "test"}, "bundle": {"install", "exec"}, "composer": {"install", "update", "run-script"},
    "direnv": {"allow"}, "docker": {"build", "compose"}, "podman": {"build"}, "deno": {"run", "task", "test"},
}


def build_runs(seg, here):
    """(what, folder) if this simple command runs build or test code from a folder, else None."""
    w = os.path.basename(seg[0])
    if not _BUILD.match(w):
        return None
    rest = seg[1:]
    sub = next((t for t in rest if not t.startswith("-")), "")
    paths = [t for t in _args(seg, 1, ("-C", "--prefix", "--cwd", "--dir", "-f", "--file", "--manifest-path", "-r", "--rootdir", "-c"))
             if ("/" in t or t == ".") and not t.startswith(("http:", "https:"))]
    folder = here
    for i, t in enumerate(seg):
        if t in ("-C", "--prefix", "--cwd", "--dir", "--directory", "--rootdir") and i + 1 < len(seg):
            folder = _abs(seg[i + 1], here)
        elif t.startswith(("--prefix=", "--cwd=", "--dir=", "--rootdir=", "--directory=")):
            folder = _abs(t.split("=", 1)[1], here)
        elif t == "--manifest-path" and i + 1 < len(seg):
            folder = os.path.dirname(_abs(seg[i + 1], here))
    if w.startswith("python"):
        if "-m" not in rest:
            if rest and re.search(r"(^|/)setup\.py$", rest[0]):
                return "setup.py", os.path.dirname(_abs(rest[0], here))
            return None
        mod = rest[rest.index("-m") + 1] if rest.index("-m") + 1 < len(rest) else ""
        if mod not in ("pytest", "tox", "nox", "pip", "build", "unittest"):
            return None
        if mod == "pip" and "install" not in rest:
            return None
        if mod == "pip":
            local = [p for p in _args(seg, rest.index("install") + 2, ("-r", "-c", "-i", "--index-url", "-t", "--target")) if p == "." or "/" in p]
            if not local:
                return None
            return "pip install (runs the package's build code)", _abs(local[0], here)
        w = mod
        paths = [p for p in paths if p != "-m"]
    elif w.startswith("pip"):
        if sub != "install":
            return None
        local = [p for p in _args(seg, 2, ("-r", "-c", "-i", "--index-url", "-t", "--target")) if p == "." or p.startswith(("./", "../", "/")) or "/" in p]
        if not local and "-e" not in rest:
            return None
        tgt = local[0] if local else rest[rest.index("-e") + 1] if rest.index("-e") + 1 < len(rest) else "."
        return "pip install (runs the package's build code)", _abs(tgt, here)
    elif w in _SUB and sub not in _SUB[w]:
        return None
    elif w in ("npx", "bunx"):
        return None   # runs a registry package, not folder code (package names are checked separately)
    if paths and folder == here:
        folder = _abs(paths[0], here)
        if os.path.isfile(folder):
            folder = os.path.dirname(folder)
    return (w + (" " + sub if sub else "")).strip(), folder


def what_runs(folder, what):
    """A short, factual list of the folder's code that this tool would run."""
    out = []
    def has(*rel):
        return [r for r in rel if os.path.exists(os.path.join(folder, r))]
    root = folder
    try:
        if what.startswith(("pytest", "tox", "nox", "unittest")):
            n = 0
            for dp, dns, fns in os.walk(root):
                dns[:] = [d for d in dns if d not in (".git", "node_modules", ".venv", "venv")][:50]
                if "conftest.py" in fns:
                    n += 1
                if n > 20:
                    break
            if n:
                out.append(f"{n} conftest.py file(s), which pytest imports before any test")
            out += [f"{f} (plugins/addopts)" for f in has("pytest.ini", "tox.ini", "setup.cfg", "pyproject.toml", "noxfile.py")]
        if what.startswith(("make", "gmake")):
            mf = has("Makefile", "makefile", "GNUmakefile")
            if mf:
                with open(os.path.join(root, mf[0]), errors="replace") as fh:
                    lines = [l.strip() for l in fh.read(20_000).splitlines() if l.startswith("\t")][:3]
                out.append(f"{mf[0]} recipes such as: " + " | ".join(lines)[:220])
        if what.split(" ")[0] in ("npm", "yarn", "pnpm", "bun"):
            if has("package.json"):
                with open(os.path.join(root, "package.json"), errors="replace") as fh:
                    pj = json.loads(fh.read(400_000) or "{}")
                sc = pj.get("scripts") or {}
                keys = [k for k in ("preinstall", "install", "postinstall", "prepare", "pretest", "test", "start", "build") if k in sc]
                out += [f"package.json {k}: {str(sc[k])[:120]}" for k in keys[:5]]
        if what.startswith(("pip", "setup.py", "poetry", "pdm", "hatch", "uv")):
            out += [f"{f} (build code)" for f in has("setup.py", "pyproject.toml", "build.py")]
        if what.startswith("cargo"):
            out += ["build.rs (runs at build time)" for _ in has("build.rs")]
        if what.startswith("direnv"):
            out += [".envrc (runs on every cd into the folder)" for _ in has(".envrc")]
    except Exception:
        pass
    return out


# ---------------------------------------------------------------- .git/config that makes git run a program
GIT_DANGER = re.compile(r"^\s*(fsmonitor|sshcommand|pager|editor|askpass|gitproxy|external|textconv|clean|smudge|process|helper|"
                        r"uploadpack|receivepack)\s*=\s*(.+)$|^\s*[\w.-]+\s*=\s*!", re.I | re.M)


def git_dir_of(folder):
    d = os.path.realpath(folder or ".")
    while True:
        if os.path.isdir(os.path.join(d, ".git")):
            return os.path.join(d, ".git")
        nd = os.path.dirname(d)
        if nd == d:
            return None
        d = nd


def git_config_risk(folder):
    """(line, why) when the repository's own .git/config makes git run a program, else None. Git never copies this
    file on clone, so it only arrives with an archive, a shared folder or a planted repository."""
    g = git_dir_of(folder)
    if not g:
        return None
    try:
        with open(os.path.join(g, "config"), errors="replace") as fh:
            text = fh.read(200_000)
    except OSError:
        return None
    for m in GIT_DANGER.finditer(text):
        key, val = (m.group(1) or "alias").lower(), (m.group(2) or "").strip().strip("\"'")
        if key == "fsmonitor" and val.lower() in ("true", "false", "0", "1", "yes", "no", ""):
            continue
        if key in ("pager", "editor") and not re.search(r"[|;&$`<>()]|\b(sh|bash|curl|wget|python\d?|perl|nc)\b", val):
            continue
        if key == "helper" and not (val.startswith("!") or "/" in val):
            continue
        return m.group(0).strip()[:200], f"{os.path.join(g, 'config')} sets {key}, so every git command in this repository runs that program"
    return None


def git_folders(cmd, cwd):
    """Folders in which a command runs git."""
    out = []
    for seg, here in walk_segments(cmd, cwd):
        if os.path.basename(seg[0]) != "git":
            continue
        folder = here
        for i, t in enumerate(seg):
            if t == "-C" and i + 1 < len(seg):
                folder = _abs(seg[i + 1], folder)
            elif t.startswith("--git-dir="):
                folder = os.path.dirname(_abs(t.split("=", 1)[1], folder))
        out.append(folder)
    return out


# ---------------------------------------------------------------- agent configuration that a downloaded repository brings
AGENT_FILES = ("CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules", ".clinerules",
               ".github/copilot-instructions.md", ".claude/settings.json", ".claude/settings.local.json", ".mcp.json", ".vscode/tasks.json",
               ".vscode/settings.json", ".vscode/mcp.json", ".cursor/mcp.json", ".devcontainer/devcontainer.json", ".envrc",
               ".pre-commit-config.yaml", ".claude/commands", ".claude/agents", ".claude/skills", ".cursor/rules")


def agent_files(root):
    return [r for r in AGENT_FILES if os.path.exists(os.path.join(root, r))]


def _walk_json(x, path=()):
    if isinstance(x, dict):
        for k, v in x.items():
            yield from _walk_json(v, path + (str(k),))
    elif isinstance(x, list):
        for v in x:
            yield from _walk_json(v, path)
    else:
        yield path, x


def config_effects(name, text):
    """What a configuration file makes happen: programs it runs, servers it adds, permissions it grants. Text in, list out."""
    base = os.path.basename(name)
    out = []
    try:
        data = json.loads(text)
    except Exception:
        data = None
    if data is not None:
        servers = (data.get("mcpServers") or data.get("servers") or {}) if isinstance(data, dict) else {}
        if isinstance(servers, dict):
            for k, v in list(servers.items())[:8]:
                if isinstance(v, dict):
                    run = v.get("url") or " ".join([str(v.get("command", ""))] + [str(a) for a in (v.get("args") or [])][:8])
                    out.append(f"adds MCP server '{k}': {run.strip()[:160]}" + (f" (env: {', '.join(list(v['env'])[:5])})" if isinstance(v.get("env"), dict) else ""))
        for path, val in _walk_json(data):
            if not isinstance(val, (str, bool)):
                continue
            key = path[-1] if path else ""
            if "hooks" in path and key == "command":
                ev = next((p for p in path if p[:1].isupper()), "?")
                out.append(f"hook on {ev} runs: {str(val)[:160]}")
            elif path[:2] == ("permissions", "allow"):
                out.append(f"allows without asking: {str(val)[:120]}")
            elif key in ("apiKeyHelper", "awsCredentialExport", "awsAuthRefresh", "otelHeadersHelper") or (path[:1] == ("statusLine",) and key == "command"):
                out.append(f"{'.'.join(path)} runs: {str(val)[:160]}")
            elif key in ("enableAllProjectMcpServers",) and val is True:
                out.append("turns on every MCP server the project lists")
            elif path[:1] == ("env",):
                out.append(f"sets environment variable {key}")
            elif key in ("postCreateCommand", "postStartCommand", "postAttachCommand", "initializeCommand", "onCreateCommand", "updateContentCommand"):
                out.append(f"{key} runs: {str(val)[:160]}")
            elif base == "tasks.json" and key == "runOn" and val == "folderOpen":
                out.append("a VS Code task runs automatically when the folder is opened")
            elif key in ("defaultMode",) and val in ("bypassPermissions", "acceptEdits", "dontAsk"):
                out.append(f"sets permission mode {val}")
    else:  # an edit fragment: look at the keys in the text
        for m in re.finditer(r"\"(command|url|apiKeyHelper|postCreateCommand|initializeCommand)\"\s*:\s*\"([^\"\n]{1,200})\"", text):
            out.append(f"{m.group(1)}: {m.group(2)[:160]}")
        for m in re.finditer(r"\"(Bash|WebFetch|mcp__[\w-]+)(\([^\"\n]{0,80}\))?\"", text):
            if re.search(r"\"allow\"\s*:", text):
                out.append(f"allows without asking: {m.group(0)[:120]}")
                break
        if "enableAllProjectMcpServers" in text or "bypassPermissions" in text:
            out.append("changes MCP or permission defaults")
    return list(dict.fromkeys(out))[:12]


CONFIG_FILES = re.compile(r"(^|/)(\.mcp\.json|\.claude\.json|\.claude/settings(\.local)?\.json|\.vscode/(tasks|mcp|settings)\.json|"
                          r"\.cursor/mcp\.json|\.devcontainer/devcontainer\.json|claude_desktop_config\.json|managed-settings\.json)$")


# ---------------------------------------------------------------- typo-squatted package names
PYPI = set("""requests numpy pandas scipy matplotlib seaborn scikit-learn sklearn tensorflow torch torchvision torchaudio keras flask django fastapi
uvicorn gunicorn pydantic sqlalchemy alembic psycopg2 psycopg2-binary psycopg pymysql redis celery boto3 botocore awscli pytest pytest-cov
pytest-mock pytest-asyncio coverage black flake8 pylint mypy ruff isort setuptools wheel virtualenv poetry pipenv twine click typer rich tqdm
pyyaml toml tomli jinja2 markupsafe werkzeug itsdangerous certifi urllib3 charset-normalizer chardet attrs packaging python-dateutil
pytz tzdata cryptography pyopenssl paramiko bcrypt pyjwt jsonschema lxml beautifulsoup4 selenium playwright scrapy httpx aiohttp websockets
openai anthropic transformers datasets tokenizers langchain nltk spacy gensim opencv-python pillow imageio sympy networkx jupyter notebook
ipython ipykernel jupyterlab plotly streamlit gradio pyarrow polars numba cython protobuf grpcio docker kubernetes pymongo
elasticsearch openpyxl python-docx pypdf pdfminer.six reportlab fsrs markdown pygments sphinx mkdocs colorama termcolor tabulate
pexpect psutil watchdog schedule arrow pendulum loguru sentry-sdk stripe twilio discord.py tweepy google-auth pyserial pygame kivy tensorboard
xgboost lightgbm catboost statsmodels joblib cffi pycparser wrapt decorator future filelock platformdirs distlib fsspec regex simplejson ujson
orjson msgpack zipp importlib-metadata typing-extensions greenlet gevent eventlet tornado starlette sanic bottle pyramid peewee marshmallow
mock freezegun faker hypothesis responses requests-oauthlib oauthlib httplib2 pycryptodome pynacl ecdsa pyasn1 keyring python-dotenv
environs docopt argcomplete prompt-toolkit pywin32 pyinstaller setuptools-scm build hatchling flit uv ruamel.yaml pyqt5 pyside6 wxpython
tkinter-tooltip boto requests-toolbelt aiofiles anyio sniffio h11 httpcore idna multidict yarl frozenlist aiosignal pyzmq tenacity
backoff cachetools more-itertools toolz jmespath s3transfer google-api-python-client google-cloud-storage azure-storage-blob
llama-index sentence-transformers accelerate diffusers safetensors huggingface-hub einops timm jax jaxlib flax optax mlflow wandb
pymupdf pdfplumber camelot-py tesseract pytesseract easyocr moviepy pydub librosa soundfile""".split())
NPM = set("""react react-dom express lodash axios vue next nuxt svelte typescript webpack webpack-cli vite rollup esbuild eslint prettier jest
mocha chai vitest cypress playwright puppeteer moment dayjs date-fns chalk commander yargs inquirer debug dotenv cors body-parser
cookie-parser morgan helmet jsonwebtoken bcrypt bcryptjs mongoose mongodb mysql mysql2 sequelize prisma redis ioredis socket.io uuid
nanoid classnames clsx tailwindcss postcss autoprefixer sass styled-components redux react-redux zustand react-router react-router-dom
rxjs zone.js core-js tslib rimraf glob minimist semver fs-extra mkdirp cross-env nodemon concurrently ts-node tsx husky lint-staged request
node-fetch got superagent cheerio jsdom marked highlight.js three chart.js electron sharp multer nodemailer passport joi zod yup ajv
graphql apollo-server firebase aws-sdk stripe openai discord.js telegraf bootstrap jquery underscore ramda immer swr formik
react-hook-form framer-motion gsap qs colors ora execa open prompts kleur picocolors ansi-styles supports-color source-map js-yaml yaml
xml2js express-session compression http-proxy-middleware serve http-server pm2 forever browserify gulp grunt karma jasmine sinon nock
supertest ts-jest nx lerna turbo pnpm yarn npm vercel netlify-cli angular @angular/core @angular/cli @babel/core @babel/preset-env
@types/node @types/react @prisma/client @reduxjs/toolkit @emotion/react @apollo/client @tanstack/react-query @anthropic-ai/sdk
@modelcontextprotocol/sdk @playwright/test @playwright/mcp chrome-devtools-mcp typeorm knex pg sqlite3 better-sqlite3 lru-cache
async bluebird events buffer process path-browserify util inherits safe-buffer readable-stream string-width strip-ansi wrap-ansi
cross-spawn which shelljs node-gyp nan bindings prebuild-install esm ws socket.io-client form-data mime mime-types""".split())


def _one_edit(a, b):
    """True if a and b differ by one insertion, deletion, substitution or swap of neighbours."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    if len(a) > len(b):
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


def lookalike(name, eco):
    known = PYPI if eco == "pypi" else NPM
    n = name.lower().replace("_", "-") if eco == "pypi" else name.lower()
    if n in known or len(n) < 5:
        return None
    for k in known:
        if abs(len(k) - len(n)) <= 1 and _one_edit(n, k):
            return k
    return None


def packages(cmd):
    """(ecosystem, name) for every registry package an install command names."""
    out = []
    for seg, _ in walk_segments(cmd, "."):
        w = os.path.basename(seg[0])
        rest = seg[1:]
        if w.startswith("python") and rest[:2] == ["-m", "pip"]:
            w, rest = "pip", rest[2:]
        if w == "uv" and rest[:1] == ["pip"]:
            w, rest = "pip", rest[1:]
        if w.startswith("pip") or w == "pipx":
            if not rest or rest[0] != "install":
                continue
            for t in _args(["x"] + rest[1:], 1, ("-r", "-c", "-i", "--index-url", "--extra-index-url", "-t", "--target", "--prefix", "-e", "--python")):
                if "/" in t or t.startswith(".") or re.search(r"\.(whl|tar\.gz|zip)$", t):
                    continue
                name = re.split(r"[\[=<>!~;@ ]", t, 1)[0]
                if name:
                    out.append(("pypi", name))
        elif w in ("npm", "yarn", "pnpm", "bun") and rest and rest[0] in ("install", "i", "add"):
            for t in _args(["x"] + rest[1:], 1, ("--prefix", "--registry", "-w", "--filter")):
                if "/" in t and not t.startswith("@") or t.startswith((".", "file:", "git+", "http")):
                    continue
                name = re.sub(r"(?<=.)@[^/]*$", "", t)
                out.append(("npm", name))
        elif w in ("npx", "bunx", "pnpx"):
            pos = _args(seg, 1, ("-p", "--package"))
            for i, t in enumerate(seg):
                if t in ("-p", "--package") and i + 1 < len(seg):
                    pos.insert(0, seg[i + 1])
            if pos:
                out.append(("npm", re.sub(r"(?<=.)@[^/]*$", "", pos[0])))
    return out


# ---------------------------------------------------------------- payment details typed into a page
_DIGITS = re.compile(r"(?<![\d.])(?:\d[ -]?){12,18}\d(?![\d.])")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b")


def _luhn(d):
    s, alt = 0, False
    for ch in reversed(d):
        n = int(ch)
        if alt:
            n = n * 2 - 9 if n > 4 else n * 2
        s += n
        alt = not alt
    return s % 10 == 0


def _iban_ok(s):
    s = s.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    r = s[4:] + s[:4]
    try:
        return int("".join(str(int(c, 36)) for c in r)) % 97 == 1
    except ValueError:
        return False


def payment_details(text):
    """'card number' / 'IBAN' when the text holds a checksum-valid one, else None."""
    for m in _DIGITS.finditer(text[:200_000]):
        d = re.sub(r"\D", "", m.group(0))
        if 13 <= len(d) <= 19 and _luhn(d) and len(set(d)) > 1:
            return "a payment card number"
    for m in _IBAN.finditer(text[:200_000]):
        if _iban_ok(m.group(0)):
            return "a bank account number (IBAN)"
    return None


# ---------------------------------------------------------------- file names with shell syntax in a listing
LIST_CMD = re.compile(r"^(ls|ll|dir|find|fd|tree|unzip|tar|7z|zipinfo|git)$")
SHELL_NAME = re.compile(r"\$\(|`[^`\n]{1,200}`|;\s*(rm|curl|wget|sh|bash|python3?|nc)\b|\|\s*(ba)?sh\b|&&\s*\w")


LIST_PIPE = re.compile(r"^(head|tail|sort|uniq|column|less|more|nl)$")


def shell_names(cmd, output):
    """Lines of a pure listing (every command lists files or only trims the list) whose file names hold shell syntax."""
    words = [os.path.basename(seg[0]) for seg, _ in walk_segments(cmd, ".")]
    if not words or not LIST_CMD.match(words[0]) or not all(LIST_CMD.match(w) or LIST_PIPE.match(w) for w in words):
        return []
    if words[0] == "git" and not re.search(r"\bgit\s+(ls-files|ls-tree|status)\b", cmd):
        return []
    return [l.strip()[:120] for l in output.splitlines()[:20_000] if len(l) <= 300 and SHELL_NAME.search(l)][:3]
