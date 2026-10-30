# Trap test corpus (29 Oct 2026)
One LaTeX file per hiding technique from `context/09_pdf_traps.md` (01-21), each with the visible task `a(b*c+ab)*c*` and a hidden instruction. `17_clean_control` has none.

Build (Bash tool needs the PATH):
```
export PATH=$HOME/texlive/2026/bin/x86_64-linux:$PATH
cd <copy of this folder>
for f in [01]*.tex 2*.tex; do pdflatex -interaction=nonstopmode $f; pdflatex -interaction=nonstopmode $f; done   # 2 runs for OCG/bookmarks
lualatex 19_zero_width.tex; lualatex 20_homoglyph.tex      # need fontspec
python3 -I ../pdf_trapscan.py *.pdf
```
Expected on 29 Oct 2026: every file except 17 has findings; 18 (image) and 20 (homoglyph) only MED; 19 clean because poppler drops zero-width characters. Build in a scratch copy, not here.
