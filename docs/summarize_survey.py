#!/usr/bin/env -S python3 -I
"""Summarise a survey log (one 'safe-read --report-only' block per file, separated by '##### path') into
docs/survey_summary.json for gen_docs.py. Usage: python3 -I docs/summarize_survey.py SURVEY_LOG"""
import collections, json, os, re, sys, time

# reviewed by hand (page images compared): what each remaining HIGH file really contains
NOTES = {
    "26/exercise sheets/Exercise_Sheet_2.pdf": "THE TRAP: invisible ActualText telling an LLM to solve c*(ba+cb*)a and to hide it",
    "25/1._Slides/Lecture_20.pdf": "genuine hidden text, benign: the German original of a translated slide sits invisibly under the English text",
    "26/5._Slides/Chapter-01-02.pdf": "benign: Beamer keeps content of other overlay steps outside the page",
    "25/1._Slides/Lecture_25.pdf": "genuine faint content, benign: photo of a handwritten graph with half-erased pencil notes",
    "26/6._Slides_with_Annotations/2026-10-14.pdf": "embedded CMS screenshot with light-grey progress bars, no hidden text",
    "exams/ti_Blaeser_2014WS_end.pdf": "scan of a printed exam: OCR of grey scan noise, no readable words",
}

log = open(sys.argv[1], errors="replace").read()
blocks = re.split(r"^##### ", log, flags=re.M)[1:]
verdicts, high, instr = collections.Counter(), [], []
for b in blocks:
    name = b.split("\n", 1)[0].strip()
    m = re.search(r"VERDICT: (\w+)", b)
    v = m.group(1) if m else "?"
    verdicts[v] += 1
    kinds = sorted(set(re.findall(r"\[HIGH\] (.+?) \(", b)))
    if re.search(r"\[HIGH\] instruction aimed at an AI", b):
        instr.append(name)
    if kinds:
        high.append((name, v, NOTES.get(name, "") + (" | " if name in NOTES else "") + "; ".join(k[:60] for k in kinds)[:240]))
out = {"date": time.strftime("%Y-%m-%d"), "files": len(blocks), "verdicts": ", ".join(f"{k} {n}" for k, n in verdicts.most_common()),
       "instruction_files": instr, "high_files": high}
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "survey_summary.json"), "w") as f:
    json.dump(out, f, indent=1)
print(out["verdicts"], "| instructions in:", instr)
for h in high:
    print(" ", h[0], "|", h[2][:150])
