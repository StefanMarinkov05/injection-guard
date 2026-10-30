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

## Precision limits
- OCR is noisy on formulas: single-symbol changes in math are only reported when they repeat or sit in a sentence.
- Page OCR runs on the first 15 pages by default (`--ocr-pages`); glyph OCR on fonts of the first 10 pages.
- Per-glyph cover check skips rotated pages and pages whose CropBox differs from the MediaBox.
- Visible, plausible decoys and trap references (non-existent theorems) are indistinguishable from real tasks.
- Phrase lists miss novel wording; the structural, Unicode, render, OCR and ambiguity checks do not depend on wording.

## Engineering
- CI uses Ubuntu's MuPDF; trace-format differences would show up in the glyph-audit tests first.
- `docs/test_results.json` is overwritten by every `report.py` run - regenerate docs only from a full, green run.
