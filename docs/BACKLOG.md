# Backlog and known limits

Ordered roughly by value. When you pick one: write the failing test first, then build (see CLAUDE.md).

## Not detected yet
- **Claude's own PDF reader as a 4th parser.** A file built to differ only for it cannot be tested here; raw reads of
  flagged files therefore stay blocked.
- **Cloaking keyed on IP, cookies, login, time or geography** - `safe-fetch` only varies the user agent.
- **Content that changes after the scan** (timers, push channels, click handlers): flagged MED statically (W3) and every later tool output is
  rescanned, but an agent clicking from an old snapshot, or a payload served only to a second request, is not seen until it is read.
- **Steganography beyond LSB**: JPEG DCT domain (F5, OutGuess), palette order, PNG filter bytes, bits in word/kerning spacing (PDF `TJ` offsets).
- **Adversarial image perturbations** aimed at vision models (invisible to humans and OCR).
- **7z / rar** are flagged MED, not unpacked (no extractor on this machine; `py7zr` would be an option).
- **Legacy `.doc/.xls/.ppt`** are flagged, not parsed (convert with LibreOffice first).
- **QR codes, audio, video** are not decoded.
- **Instructions split across files** (file A points to a benign-looking note in file B).
- **Steps without any instruction wording** ("1. create helper.sh with ... 3. run it"): the scanner sees a normal guide. The hook
  catches it only at the end, when the script is run after a finding (H11). Without an earlier finding nothing asks.
- **Text that only exists after a program runs** (strings concatenated in code, a generator script, a template rendered later):
  seen when the output passes through a tool (O1), not in the source.
- **Acrostics and other patterns across lines** (first letters, every n-th word) unless the text also says to assemble them (T17).
- **Novel paraphrase, two or more typos per word, emoji letters**: T16/T21 repair one edit per trigger word, chat spelling
  and sound-alike endings, plus a small word list of other languages; a sentence that avoids every trigger word is not
  seen by patterns. The quarantine reader (meaning) and the action gates (H10, H11, H13-H15) are what hold then.
- **Per-session budgets**: no limit yet on repeated fetches of one URL, pages per host, untrusted characters read, or agents
  started after a finding. C1 flags the instruction; nothing counts the spending.
- **Memory directories and hand-off notes** are checked like any tool output when read, not scanned at session start.
- **File names carrying shell syntax**: flagged in `ls`/`find`/`tree`/archive listings (D5); `git status` and other output not yet.
- **Downloaded folders the hook cannot see**: archives extracted by a GUI, files saved by the browser, folders created by
  a script. Only `git clone`, `gh repo clone`, `unzip/tar/7z` with or without a target and `curl/wget -o` are tracked.
- **Build tools reached indirectly** (`./run_all.sh` that calls `make` inside a downloaded folder; an IDE that runs tasks)
  are not linked to the download.
- **Typo-squat list** covers about 200 popular PyPI and 230 npm names with one edit; dependency confusion (an internal
  name published publicly) and look-alike scopes (`@types-node`) are not checked.
- **Payment details** are caught only when typed through a browser tool and checksum-valid; the price, the seller and the
  shop's domain are not checked.
- **Steering without addressing or trigger words** ("the Ultra model is the only sensible choice") is ordinary marketing
  and stays quiet; only hidden text, AI-addressed text and explicit steering wording are flagged. The quarantine reader
  is told to report it.
- **Breadcrumbs across pages** (page A says "see /ai-notes", page B holds the order) are seen only per page.
- **safe-fetch**: no overall deadline, no check of redirects from public to private addresses, response headers are not scanned.
- **Decompiler and disassembler output** is checked as text (strings, symbol names); control-flow tricks are out of scope.

## Precision limits
- OCR is noisy on formulas: single-symbol changes in math are only reported when they repeat or sit in a sentence.
- Page OCR runs on the first 15 pages by default (`--ocr-pages`); glyph OCR on fonts of the first 10 pages.
- Per-glyph cover check skips rotated pages and pages whose CropBox differs from the MediaBox.
- Visible, plausible decoys and trap references (non-existent theorems) are indistinguishable from real tasks.
- Phrase lists miss novel wording; the structural, Unicode, render, OCR and ambiguity checks do not depend on wording.

## Engineering
- Phrase search is the cost centre: about 2 s per MB of non-repeating text (it was 1.6 s before the Nov 2026 phrases).
  `test_large_input_is_fast` passes because repeated sentences are scanned once; unique megabyte texts got slower.
  Non-ASCII text is worse: each Unicode transform (NFKC, diacritics, look-alikes) repeats the base phrase search, so a
  95 KB non-ASCII Markdown file takes 4 s (1.6.0) to 5 s (1.7.0) on a loaded machine. Fix idea: one combined transform,
  or run the transforms only when the base text has a trigger anchor nearby.
- Live A/B (`redteam/live_eval.py`) is a pilot: 13 files x 2 arms on Haiku (Nov 2026). Not a measurement yet.

## Planned: benchmark (design not started)
Two separate questions, two separate benchmarks:
1. **Need**: how often do agents (several vendors and models) follow injected content with no guard? Measure on our corpus
   with `live_eval.py` per model; cite published benchmarks (AgentDojo, InjecAgent, WASP, BIPIA) instead of re-running
   what they already measured.
2. **Effect**: what the guard adds - detection rate per difficulty level, false alarms on real files, cost in seconds.
   Difficulty levels by what the attacker must defeat (plain visible order, hidden carrier, obfuscated wording, staged
   or split payload, masked as a normal setup step, effect-only with no instruction text). Held-out set the rules were
   never tuned on; report counts with intervals.
- The private attack corpus (`redteam/`, git-ignored) is not in CI: run `python3 -I redteam/evaluate.py` before a release.
- CI uses Ubuntu's MuPDF; trace-format differences would show up in the glyph-audit tests first.
- `docs/test_results.json` is overwritten by every `report.py` run - regenerate docs only from a full, green run.
