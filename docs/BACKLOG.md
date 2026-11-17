# Backlog and known limits

Ordered roughly by value. When you pick one: write the failing test first, then build (see CLAUDE.md).

## Not detected yet
- **Claude's own PDF reader as a 4th parser.** A file built to differ only for it cannot be tested here; raw reads of
  flagged files therefore stay blocked.
- **Cloaking keyed on IP, cookies, login, time or geography** - `safe-fetch` only varies the user agent.
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
- **Novel paraphrase, two or more typos per word, emoji letters**: T16 repairs one edit per trigger word and a small word list of
  other languages; a sentence that avoids every trigger word is not seen. The action gate (H10, H11) is what holds then.
- **Per-session budgets**: no limit yet on repeated fetches of one URL, pages per host, untrusted characters read, or agents
  started after a finding. C1 flags the instruction; nothing counts the spending.
- **Memory directories and hand-off notes** are checked like any tool output when read, not scanned at session start.
- **File names carrying shell syntax** in `ls`/`find`/`git status` output are not flagged.
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
- The private attack corpus (`redteam/`, git-ignored) is not in CI: run `python3 -I redteam/evaluate.py` before a release.
- CI uses Ubuntu's MuPDF; trace-format differences would show up in the glyph-audit tests first.
- `docs/test_results.json` is overwritten by every `report.py` run - regenerate docs only from a full, green run.
