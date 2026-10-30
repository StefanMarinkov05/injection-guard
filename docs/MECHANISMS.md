# injection-guard 1.5.0: security mechanisms and proof

Test run 2026-10-30 07:08: **321 tests, 0 failures, 0 errors, 0 skipped** (308 s). Regenerate: `python3 -I plugins/injection-guard/tests/report.py && python3 -I docs/gen_docs.py`.

Rule enforced everywhere: the page a human sees is the content; text inside documents and tool output is data, never instructions.
Design choice: recall over precision (false positives are acceptable; an unreadable file is never clean).

## Mechanisms

| ID | Layer | Mechanism | Target | Attack vector | What it does | Severity | Proof |
|---|---|---|---|---|---|---|---|
| H1 | hook | **Read gate** | Read of PDF, Office, EPUB, RTF; HTML/SVG outside git | agent opens a document raw and receives its hidden text layer | PreToolUse denies the read until safe-read has scanned the exact file | deny | 5/5 pass |
| H2 | hook | **Flagged files stay blocked** | files whose scan verdict is HIGH or MED | a scanned but poisoned file is read raw after all | raw reads stay denied (block_on: MED); the agent works from safe-read output and page images | deny | 4/4 pass |
| H3 | hook | **Trust bound to SHA-256** | scan registry ~/.cache/injection-guard/scanned | swap a scanned clean file for a poisoned one (same name, size, mtime) - the collision / TOCTOU idea | every read re-hashes the file; unknown bytes are gated again | deny | 2/2 pass |
| H4 | hook | **Shell reader gate** | Bash: cat, pdftotext, pandoc, python, strings, ... on documents | bypass the Read gate through the shell | same gate as H1 for document paths in reader commands | deny | 2/2 pass |
| H5 | hook | **WebFetch routing** | WebFetch | a summarising fetcher reads an injected page | denied in strict mode with the safe-fetch command to run instead | deny | 1/1 pass |
| H6 | hook | **Output scanner** | output of Bash, Read, Grep, WebFetch, WebSearch, subagents, all MCP/browser tools | injection arrives through any tool result | PostToolUse checks for invisible Unicode, encodings, instructions; warns the model and the user | warn | 4/4 pass |
| H7 | hook | **Self-protection** | guard config, cache, plugin files, plugin enable flag | a document tells the agent to disable the guard | edits, deletes and plugin disable/uninstall ask the user | ask | 2/2 pass |
| H8 | hook | **Robust hook** | malformed hook input, internal errors | crash the hook to block or confuse the session | fails open quietly and logs; session notice tells the model about the tools | - | 2/2 pass |
| O1 | output | **Untrusted envelope** | safe-read / safe-fetch output | content forges an end marker and continues as 'instructions' | report first, then content between random-nonce markers; hidden parts removed and quoted in the report | - | 7/7 pass |
| N1 | network | **safe-fetch** | web pages and online files | hidden HTML/PDF content in research reading | downloads with a browser user agent into a quarantine folder and scans it like a local file | per finding | 5/5 pass |
| N2 | network | **Cloaking check** | servers that answer AI agents differently | page shows humans one text and Claude-User/ChatGPT-User another | re-fetches as AI user agents and compares visible words; blocked AI requests are reported | HIGH/MED | 3/3 pass |
| T1 | text | **Instruction phrases** | all extracted text | 'ignore previous instructions', 'if you are an AI', 'do not tell the user', synonyms, chat-template tokens, reading-mode probes, German/French/Spanish/Italian | phrase patterns on a flattened copy (soft hyphens, line breaks, Unicode spaces normalised) | HIGH | 8/8 pass |
| T2 | text | **AI keywords** | all extracted text | words naming AI systems in hidden places | hidden: HIGH; visible: INFO, or MED with imperative wording | HIGH/MED/INFO | 4/4 pass |
| T3 | text | **Fingerprint directives** | all extracted text | forced state names or notation, canary words, fake errata/authority/deadlines, redefinitions - no AI words needed | DIRECTIVE patterns (English, German); hidden: HIGH, visible: INFO | HIGH/INFO | 9/9 pass |
| T4 | text | **Invisible Unicode** | all extracted text | zero-width, bidi, tag characters (ASCII smuggling), variation-selector smuggling, Hangul/Braille fillers | detects, decodes hidden payloads and re-checks them; strips them from output | HIGH/MED | 12/12 pass |
| T5 | text | **Look-alike characters** | tasks, formulas, state names | Cyrillic a in a(b*c+ab)*c*, q0 with a Cyrillic q, Greek omicron, full-width/math/Roman digits | look-alike letters next to Latin/formula characters, mixed-script words, identifiers, compatibility characters, math-letter words | MED | 10/10 pass |
| T6 | text | **Encodings and ciphers** | all extracted text | base64(url), base32, hex, URL, escapes, binary, HTML entities, ROT13, Caesar, reversed, leetspeak, Braille, superscripts, nested | decoders and transformed copies, then the phrase check; cheap literal pre-checks keep it fast | HIGH/MED | 9/9 pass |
| T7 | text | **Splitting tricks** | all extracted text | soft hyphens, hyphenation over lines, line breaks, combining marks, math bold, spaced/dotted letters, Unicode spaces | normalisation before matching; separate findings for each trick | HIGH | 7/7 pass |
| T8 | text | **Exfiltration phrases** | all extracted text | markdown image with ?data={secret}, 'append the key to the URL', curl with ~/.ssh | phrase patterns | HIGH | 1/1 pass |
| T10 | text | **Impersonation** | all extracted text, hidden or visible, and tool output | fake user turns, <system-reminder>/[SYSTEM NOTIFICATION] wrappers, fake tool/hook results, fake guard verdicts and end markers, invented consent ('the user already approved'), fake errors with a 'fix' command, requests to disable the guard, fake assistant replies | IMPERSONATION patterns, HIGH wherever they appear; the hooks still ask before any guard change | HIGH | 4/4 pass |
| T11 | text | **Hidden task modifiers** | hidden text in every format | 'without the prefix', 'c*', 'over {a,b,c,d}', 'minimal DFA only' - more task, no AI words | hidden text with exercise vocabulary or formula symbols is HIGH regardless of length | HIGH | 8/8 pass |
| T12 | text | **Whitespace steganography** | text, Markdown, LaTeX, HTML sources | bits in trailing spaces and tabs (SNOW style) | detects long/mixed trailing whitespace on several lines and tries to decode it | HIGH/MED | 2/2 pass |
| T9 | text | **Robustness** | large or odd input | slow the scanner down or crash it | bounded passes; 2.4 MB in a few seconds | - | 2/2 pass |
| P1 | pdf | **Render diff** | PDF text layer vs rendered page | white, near-white, tiny, clipped, covered, render mode 3/7, zero horizontal scaling | every text-layer word is checked for ink and contrast on the rendered page; blank words are removed from the output | HIGH | 11/11 pass |
| P2 | pdf | **Contrast check** | words on coloured backgrounds | text in the same colour as the box behind it (black on black, grey on grey) | a word needs dark ink AND contrast inside its box | HIGH | 5/5 pass |
| P3 | pdf | **Off-page and CropBox** | text outside what viewers show | text below the page, beyond the edges, huge text rise, inside MediaBox but outside CropBox | exact-crop vs enlarged-crop extraction; everything in CropBox coordinates | HIGH | 5/5 pass |
| P4 | pdf | **ActualText** | marked content with replacement text | the Sheet 2 trap; ActualText over visible glyphs; one fragment per glyph | every ActualText is compared with the drawn glyphs (pypdf ignores ActualText; MuPDF as fallback); repeats of the visible text are accessibility markup (INFO), anything else is HIGH/MED; fragments are joined | HIGH | 6/6 pass |
| P5 | pdf | **Metadata and structure** | Info, XMP, outline, annotations, form fields, names, comments, attachments | instructions or fingerprint directives where no viewer shows them | string objects, names (#xx decoded), % comments, attachment names/content, XMP packets | HIGH | 14/14 pass |
| P6 | pdf | **Font maps** | ToUnicode CMaps | drawn glyph != extracted character (a<->b, 3 vs 7), glyphs mapped to zero-width characters | remaps are confirmed when undoing them turns misspelled text-layer words into real words (HIGH); few unconfirmed remaps MED; many (subset encodings) INFO; invisible targets HIGH | HIGH/MED | 2/2 pass |
| P7 | pdf | **OCR cross-check** | page image vs text layer (tesseract, dictionaries off) | text layer tells another story: swapped letters/numbers, text drawn as image, faint text, text covered by a textured image | systematic swaps HIGH; single word/number MED; page words missing from the layer; layer words missing from the page; faint-ink OCR | HIGH/MED | 8/8 pass |
| P8 | pdf | **Reader differential** | poppler vs MuPDF vs pypdf | text only some readers extract (ActualText, broken structure) | word-level comparison of three independent readers | HIGH/MED | 2/2 pass |
| P9 | pdf | **Parser ambiguity** | polyglots, revisions, duplicates, trailers, damaged files | one file, two readings - the document form of a hash collision | polyglot signatures, every earlier revision extracted and compared, duplicate objects, data after %%EOF, missing %%EOF | HIGH/MED | 9/9 pass |
| P10 | pdf | **Live PDF JavaScript** | OpenAction / field scripts | content written at open time (dates, fields), eval/unescape payloads, encoded strings | runtime-call detection; string literals decoded and checked | HIGH/MED | 4/4 pass |
| P11 | pdf | **Embedded images** | images inside PDFs | EXIF/XMP text in an embedded JPEG; faint text in an image | text-like runs of raw image streams are checked; faint-content check | HIGH/MED | 1/1 pass |
| P12 | pdf | **Fail closed** | damaged, garbage, unparseable files | a file the scanner cannot read is waved through as clean | every failed step adds MED; unreadable never means clean | MED | 3/3 pass |
| O2 | output | **Type detection and options** | any file | a PDF named .txt, a PNG named .pdf, very long documents | type from magic bytes, not the extension; --images, --max-pages, --out, --json; benign texts stay below HIGH | - | 6/6 pass |
| F1 | forensic | **Glyph audit (MuPDF trace)** | every drawn glyph: font, size, colour, alpha, render mode | invisible (3 Tr), clipping-only (7 Tr), white, transparent, microscopic glyphs; ActualText that differs from the glyphs of its own span (e.g. a(b*c+ab)* over a printed a(b*c+ab)*c*) | exact per-glyph attributes instead of pixels; per-span ActualText comparison | HIGH/MED | 2/2 pass |
| F2 | forensic | **Per-glyph cover check** | glyph cells on the rendered page | part of a word covered (a white box over the c* of the task), text under images, same colour | each drawn glyph's padded cell must contain ink and contrast; covered letters are shown in brackets | HIGH/MED | 1/1 pass |
| F3 | forensic | **Provenance** | pages with several content streams | a stream appended by another tool after generation (Sheet 2: stream 261, non-embedded Helvetica among embedded Typst fonts); tool-artefact attachment names | streams that use only non-embedded fonts unlike the rest of the page; attachment names like pdftotext-hidden | HIGH/MED | 1/1 pass |
| F4 | forensic | **Reference diff** | safe-read FILE --reference KNOWN_GOOD.pdf | this week's sheet vs last week's: new fonts, more streams, ActualText, invisible text, attachments, layers, JS, other producer | structural comparison with a trusted earlier document | HIGH/MED | 2/2 pass |
| F5 | forensic | **Glyph OCR** | embedded fonts (TrueType, CFF incl. CID-keyed, Type1) | a font whose glyph for 'a' draws 'b' (and vice versa) - consistent text layer, different picture | every alphanumeric glyph rendered at its own scale and read by tesseract with confidence; symmetric swaps or several confident mismatches HIGH | HIGH/MED | 2/2 pass |
| F6 | forensic | **Tagged reading order** | tagged PDFs (structure tree) | tags put the marked content in another order than it is drawn - screen readers and tag-aware extractors read e.g. 'c* a(b*c+ab)*' | structure-tree MCID order compared with the content-stream order per page (inversions) | MED | 2/2 pass |
| P13 | pdf | **Trap corpus baseline** | 21 LaTeX-built trap PDFs (tools/trap_corpus) | every technique of the handbook | pinned verdicts and finding kinds | - | 2/2 pass |
| W1 | web | **Hidden HTML** | HTML/XHTML/EPUB pages | display:none, visibility, opacity, font-size 0, off-screen, clip, scale(0), transparent, hidden/aria-hidden, CSS classes/ids, noscript, template | hidden elements removed and reported; menus stay quiet, hidden sentences MED | HIGH/MED | 20/20 pass |
| W2 | web | **Split and embedded web content** | comments + hidden spans, data: URIs, iframe srcdoc, CSS generated content | an instruction split over several hiding places, or hidden inside an embedded document | pooled hidden text; data: URIs decoded and scanned recursively; CSS content checked | HIGH | 5/5 pass |
| W3 | web | **Live web content** | scripts | decode/decrypt + DOM write, bot/user-agent/time checks, encoded strings | static script analysis (flags what it cannot see); browser snapshots go through H6 | HIGH/MED | 6/6 pass |
| W6 | web | **Reading direction and accessibility** | HTML/CSS, DOCX, PDF | bdo / dir=rtl / unicode-bidi override on Latin text, mirrored text (scaleX(-1)), custom web fonts, DOCX right-to-left runs, PDF /ReversedChars and vertical writing | display order vs text order is reported, and the displayed (reversed) text is phrase-checked | HIGH/MED/INFO | 4/4 pass |
| W4 | web | **SVG** | SVG files and inline SVG | text with opacity 0, fill none, display none, font-size 0, desc/metadata | hidden SVG text removed and reported | HIGH | 1/1 pass |
| W5 | web | **Markdown and text** | Markdown, JSON, plain text | HTML comments, [//]: # comments, hidden inline HTML, image alt/title, link titles, reference definitions | removed or checked as hidden text | HIGH | 10/10 pass |
| D1 | office | **DOCX** | Word documents | w:vanish, tiny/white runs, tracked deletions, field codes, comments, document variables, custom XML, alt text, macros, AlternateContent fallback | visible text only in the output; everything else reported | HIGH/MED | 19/19 pass |
| D2 | office | **PPTX** | slide decks | hidden slides, hidden/off-slide/tiny shapes, speaker notes, alt text | same | HIGH | 6/6 pass |
| D3 | office | **XLSX, ODF, EPUB, zip** | spreadsheets, LibreOffice, e-books, archives | hidden sheets/rows, cell instructions, comments, hidden ODF text, hidden EPUB spans | same | HIGH/MED | 7/7 pass |
| L1 | latex | **Hidden in LaTeX source** | .tex .sty .cls .bib ... (templates, papers, sheets) | text that never reaches the PDF: comments, \iffalse, comment env, white/phantom/zero-size/tiny/off-page text, ActualText, \pdfinfo/\hypersetup metadata, annotations, raw PDF code, off layers, BibTeX note/abstract fields, \pdfglyphtounicode remaps | AI-directed text HIGH everywhere; directives INFO in comments (author guidance, seen by the editor), MED in typeset-but-invisible text; package code (.cls/.sty) INFO | HIGH/MED/INFO | 18/18 pass |
| L2 | latex | **Compile-time code** | downloaded templates and packages | \write18, shellesc, \directlua os.execute/io.popen, \input|pipe, \openout, minted/pythontex | reported HIGH (shell) / MED (file writes, packages); compile without -shell-escape | HIGH/MED | 3/3 pass |
| L3 | hook | **LaTeX read check** | Read of .tex/.sty/.cls/.bib by an agent | agent reads a template whose comments or invisible text address it | PostToolUse runs the LaTeX checks on the file and warns | warn | 2/2 pass |
| A1 | archive | **Archives and binaries** | zip files, nested zips, macOS metadata (.DS_Store, AppleDouble), unknown binaries | payload inside an archive entry, a Finder comment, path-traversal names | every entry extracted (bounded) and scanned; nested up to depth 2; strings (ASCII/UTF-16) of binaries checked | HIGH/MED/INFO | 10/10 pass |
| I1 | image | **Image metadata and bytes** | PNG, JPEG, GIF, WebP, TIFF | tEXt/zTXt/iTXt, private chunks, bad CRC, EXIF, JPEG COM/APPn, strings, appended data, lying extension | raw chunk/segment walkers and string scan | HIGH/MED | 14/14 pass |
| I2 | image | **Alpha and background tricks** | images with transparency | text in fully transparent pixels, text only visible on dark backgrounds | variation under alpha 0; composite on white vs black | HIGH/MED | 3/3 pass |
| I3 | image | **LSB steganography** | pixel data | payload in the lowest bit planes | R, G, B, RGB planes, both bit orders, readable-text search | HIGH/MED | 2/2 pass |
| I4 | image | **Scaling attack** | images a model downscales | dark pixels exactly at nearest-neighbour sample points | sampled vs averaged downscale, factors 3-8 | MED/HIGH | 2/2 pass |
| I5 | image | **Text in pictures** | screenshots, scans | an instruction a vision model reads in the picture | OCR transcription (as data) + phrase/directive check + faint-text OCR | HIGH | 1/1 pass |
| I6 | image | **Polyglot images** | PNG/JPEG with PDF, ZIP or HTML inside | the file is two things at once | signatures at start and inside | HIGH/MED | 3/3 pass |

## Tests per mechanism

**H1 Read gate**: `Hooks.test_unscanned_document_is_denied` pass, `Hooks.test_clean_scan_unlocks_read` pass, `Hooks.test_source_and_text_files_pass` pass, `Hooks.test_missing_file_passes` pass, `Hooks.test_html_in_git_is_source_outside_is_document` pass

**H2 Flagged files stay blocked**: `Hooks.test_high_and_med_stay_blocked_in_strict` pass, `Hooks.test_block_on_high_only_config` pass, `Hooks.test_warn_and_off_modes` pass, `Hooks.test_trusted_paths` pass

**H3 Trust bound to SHA-256**: `Hooks.test_file_swap_after_scan_is_gated_again` pass, `SafeReadCli.test_registry_written_with_sha256` pass

**H4 Shell reader gate**: `Hooks.test_bash_readers_are_gated` pass, `Hooks.test_bash_non_readers_and_safe_tools_pass` pass

**H5 WebFetch routing**: `Hooks.test_webfetch` pass

**H6 Output scanner**: `Hooks.test_post_warns_on_injection_in_output` pass, `Hooks.test_post_quiet_on_benign_output_and_safe_tools` pass, `Hooks.test_post_reminder_for_web_sources` pass, `Hooks.test_post_read_of_flagged_file` pass

**H7 Self-protection**: `Hooks.test_self_protection` pass, `Hooks.test_reading_the_registry_is_allowed` pass

**H8 Robust hook**: `Hooks.test_malformed_input_fails_open_quietly` pass, `Hooks.test_session_notice` pass

**O1 Untrusted envelope**: `SafeReadCli.test_hidden_text_not_in_output` pass, `SafeReadCli.test_missing_file` pass, `SafeReadCli.test_multiple_files` pass, `SafeReadCli.test_nonce_changes_every_run` pass, `SafeReadCli.test_out_json_truncation_report_only` pass, `SafeReadCli.test_registry_written_with_sha256` pass, `SafeReadCli.test_report_markers_and_rules` pass

**N1 safe-fetch**: `SafeFetch.test_clean_page` pass, `SafeFetch.test_hidden_html` pass, `SafeFetch.test_pdf_by_content_type` pass, `SafeFetch.test_registry_has_source_url` pass, `SafeFetch.test_errors` pass

**N2 Cloaking check**: `SafeFetch.test_cloaking_detected` pass, `SafeFetch.test_cloak_check_can_be_disabled` pass, `SafeFetch.test_blocking_ai_agents_is_reported` pass

**T1 Instruction phrases**: `StrongPhrases.test_entity_and_case_variants` pass, `StrongPhrases.test_negative_phrases_not_high` pass, `StrongPhrases.test_one_finding_per_passage_but_separate_passages_count` pass, `StrongPhrases.test_positive_phrases_are_high` pass, `SplitAndObfuscate.test_synonyms` pass, `SplitAndObfuscate.test_chat_template_tokens` pass, `SplitAndObfuscate.test_reading_mode_probe` pass, `SplitAndObfuscate.test_other_languages` pass

**T2 AI keywords**: `Keywords.test_hidden_mention_is_high` pass, `Keywords.test_keywords_off` pass, `Keywords.test_visible_mention_is_info_only` pass, `Keywords.test_visible_mention_with_imperative_is_med` pass

**T3 Fingerprint directives**: `Directives.test_docx_hidden_directive` pass, `Directives.test_hidden_directives_are_high` pass, `Directives.test_hidden_html_directive_without_ai_words` pass, `Directives.test_hidden_html_sentence_is_med_menu_is_not` pass, `Directives.test_markdown_canary_comment` pass, `Directives.test_ordinary_task_text_has_no_directive` pass, `Directives.test_pdf_white_directive_without_ai_words` pass, `Directives.test_visible_directives_are_info_only` pass, `InvisibleOnPage.test_fingerprint_in_white_text_without_ai_words` pass

**T4 Invisible Unicode**: `InvisibleUnicode.test_bidi` pass, `InvisibleUnicode.test_bom_and_word_joiner` pass, `InvisibleUnicode.test_decode_tags` pass, `InvisibleUnicode.test_plain_zero_width_med` pass, `InvisibleUnicode.test_short_tag_run_med` pass, `InvisibleUnicode.test_soft_hyphen_is_normal` pass, `InvisibleUnicode.test_strip_invisible` pass, `InvisibleUnicode.test_tag_smuggling_decoded` pass, `InvisibleUnicode.test_zero_width_splitting_a_phrase` pass, `UnicodeSmuggling.test_variation_selector_smuggling` pass, `UnicodeSmuggling.test_single_emoji_selector_is_fine` pass, `UnicodeSmuggling.test_other_invisible_fillers` pass

**T5 Look-alike characters**: `Homoglyphs.test_cyrillic_in_latin_word` pass, `Homoglyphs.test_greek_math_is_not_flagged` pass, `Homoglyphs.test_lookalike_greek` pass, `Homoglyphs.test_pure_cyrillic_word_ok` pass, `LookAlikeIdentifiers.test_normal_identifiers` pass, `LookAlikeIdentifiers.test_state_names_with_cyrillic_letters` pass, `AlphabetTricks.test_cyrillic_a_inside_the_regex` pass, `AlphabetTricks.test_fullwidth_and_math_digits_in_task` pass, `AlphabetTricks.test_genuine_math_unicode_is_not_high` pass, `AlphabetTricks.test_greek_omicron_in_state_name_and_zero` pass

**T6 Encodings and ciphers**: `Encodings.test_each_encoding_is_decoded_and_flagged` pass, `Encodings.test_encoded_benign_text_is_not_high` pass, `Encodings.test_readable_encoded_text_is_at_least_med` pass, `Obfuscation.test_base64_payload` pass, `Obfuscation.test_benign_base64_not_high` pass, `Obfuscation.test_spaced_keyword_in_hidden_text` pass, `Obfuscation.test_spaced_letters_phrase` pass, `Encodings2.test_braille` pass, `Encodings2.test_superscript_letters` pass

**T7 Splitting tricks**: `SplitAndObfuscate.test_soft_hyphens` pass, `SplitAndObfuscate.test_hyphenation_across_lines` pass, `SplitAndObfuscate.test_line_broken_phrase` pass, `SplitAndObfuscate.test_combining_marks` pass, `SplitAndObfuscate.test_math_bold_letters` pass, `Encodings2.test_unicode_spaces_between_words` pass, `Encodings2.test_dotted_and_dashed_letters` pass

**T8 Exfiltration phrases**: `UnicodeSmuggling.test_exfiltration_patterns` pass

**T10 Impersonation**: `Impersonation.test_benign_texts` pass, `Impersonation.test_every_forgery_is_high` pass, `Impersonation.test_forgery_in_hidden_html_and_pdf` pass, `Impersonation.test_forgery_in_tool_output_is_warned_by_the_hook` pass

**T11 Hidden task modifiers**: `TaskModifiers.test_actualtext_shortens_the_formula` pass, `TaskModifiers.test_covering_part_of_the_task` pass, `TaskModifiers.test_docx_vanish_modifier` pass, `TaskModifiers.test_html_short_hidden_fragment` pass, `TaskModifiers.test_latex_white_modifier` pass, `TaskModifiers.test_pdf_two_character_formula_extension` pass, `TaskModifiers.test_pdf_white_modifier` pass, `TaskModifiers.test_text_level` pass

**T12 Whitespace steganography**: `WhitespaceStego.test_normal_trailing_spaces` pass, `WhitespaceStego.test_snow_style_trailing_whitespace` pass

**T9 Robustness**: `Robustness.test_large_input_is_fast` pass, `Robustness.test_weird_input` pass

**P1 Render diff**: `Synthetic.test_white_text` pass, `Synthetic.test_near_white_text` pass, `Synthetic.test_render_mode_3` pass, `Synthetic.test_render_mode_7_clip` pass, `Synthetic.test_tiny_font` pass, `Synthetic.test_covered_by_white_box` pass, `Synthetic.test_clipped_away` pass, `Synthetic.test_single_hidden_word_still_reported` pass, `PdfCarriers2.test_zero_horizontal_scaling` pass, `Synthetic.test_visible_injection_kept` pass, `Synthetic.test_clean` pass

**P2 Contrast check**: `InvisibleOnPage.test_black_text_on_black_box` pass, `InvisibleOnPage.test_colour_matched_to_grey_background` pass, `ColourMatched.test_coloured_text_on_same_colour` pass, `ColourMatched.test_contrasting_colours_are_visible` pass, `ColourMatched.test_nearly_same_colour` pass

**P3 Off-page and CropBox**: `Synthetic.test_off_page_each_side` pass, `InvisibleOnPage.test_outside_cropbox_inside_mediabox` pass, `RotatedPages.test_rotated_clean_page_is_clean` pass, `RotatedPages.test_rotated_page_with_hidden_text` pass, `PdfCarriers2.test_huge_text_rise_off_page` pass

**P4 ActualText**: `Synthetic.test_sheet2_replica` pass, `Synthetic.test_actualtext_over_visible_glyphs` pass, `Synthetic.test_short_actualtext_ligature_is_not_high` pass, `SplitAcrossChannels.test_pdf_actualtext_per_glyph` pass, `RealSheets.test_sheet1_clean` pass, `RealSheets.test_sheet2_trap` pass

**P5 Metadata and structure**: `Synthetic.test_info_dictionary` pass, `Synthetic.test_text_annotation` pass, `Synthetic.test_link_uri` pass, `Synthetic.test_xmp_metadata` pass, `Synthetic.test_hidden_ocg_layer` pass, `MetadataChannels.test_directive_in_info_fields` pass, `MetadataChannels.test_directive_in_xmp` pass, `MetadataChannels.test_directive_in_form_field_tooltip_and_value` pass, `MetadataChannels.test_directive_in_annotation` pass, `MetadataChannels.test_instruction_in_attachment_name` pass, `PdfCarriers2.test_instruction_in_a_pdf_name` pass, `PdfCarriers2.test_instruction_in_pdf_comment` pass, `PdfCarriers2.test_directive_in_pdf_comment` pass, `PdfCarriers2.test_bookmark_with_directive` pass

**P6 Font maps**: `Synthetic.test_tounicode_letter_remap` pass, `Synthetic.test_tounicode_zero_width` pass

**P7 OCR cross-check**: `OcrChecks.test_clean_pdf_has_no_ocr_findings` pass, `OcrChecks.test_faint_text_found_by_ocr` pass, `OcrChecks.test_image_file_text_is_transcribed_and_checked` pass, `OcrChecks.test_single_number_swap` pass, `OcrChecks.test_systematic_swap_via_tounicode` pass, `OcrChecks.test_text_drawn_as_image_is_found` pass, `OcrChecks.test_typo_on_page_is_not_flagged_as_swap` pass, `CoveredText.test_text_covered_by_an_image` pass

**P8 Reader differential**: `ReaderDifferential.test_actualtext_only_some_readers_see` pass, `ReaderDifferential.test_clean_pdf_readers_agree` pass

**P9 Parser ambiguity**: `Polyglots.test_clean_pdf_has_no_ambiguity_findings` pass, `Polyglots.test_duplicate_objects_without_update` pass, `Polyglots.test_earlier_revision_differs` pass, `Polyglots.test_garbage_pdf_is_never_clean` pass, `Polyglots.test_html_inside_image` pass, `Polyglots.test_missing_eof` pass, `Polyglots.test_pdf_with_zip_appended` pass, `Polyglots.test_png_then_pdf` pass, `Polyglots.test_trailing_injection` pass

**P10 Live PDF JavaScript**: `LiveContent.test_pdf_javascript_live_date` pass, `LiveContent.test_pdf_javascript_eval_is_high` pass, `PdfCarriers2.test_encoded_string_in_pdf_javascript` pass, `Synthetic.test_javascript` pass

**P11 Embedded images**: `MetadataChannels.test_exif_of_jpeg_embedded_in_pdf` pass

**P12 Fail closed**: `Polyglots.test_garbage_pdf_is_never_clean` pass, `Docx.test_broken_xml_fails_closed` pass, `Synthetic.test_garbage_pdf_does_not_crash` pass

**O2 Type detection and options**: `Synthetic.test_pdf_with_wrong_extension` pass, `Images.test_extension_lies` pass, `Synthetic.test_images_option` pass, `Synthetic.test_multi_page_and_max_pages` pass, `Synthetic.test_benign_mention_of_llms` pass, `Benign.test_normal_texts` pass

**F1 Glyph audit (MuPDF trace)**: `Forensics.test_glyph_audit_sees_invisible_white_tiny` pass, `TaskModifiers.test_actualtext_shortens_the_formula` pass

**F2 Per-glyph cover check**: `TaskModifiers.test_covering_part_of_the_task` pass

**F3 Provenance**: `Forensics.test_provenance_flags_the_appended_stream` pass

**F4 Reference diff**: `Forensics.test_reference_diff` pass, `Forensics.test_reference_diff_of_identical_files_is_quiet` pass

**F5 Glyph OCR**: `Forensics.test_glyph_ocr_catches_the_font_swap` pass, `Forensics.test_glyph_ocr_quiet_on_a_clean_sheet` pass

**F6 Tagged reading order**: `ReadingOrder.test_matching_tags_are_quiet` pass, `ReadingOrder.test_reordered_tags` pass

**P13 Trap corpus baseline**: `Corpus.test_corpus` pass, `Corpus.test_every_fixture_has_an_expectation` pass

**W1 Hidden HTML**: `HiddenHtml.test_attributes` pass, `HiddenHtml.test_benign_comment_info` pass, `HiddenHtml.test_comment` pass, `HiddenHtml.test_css_class_from_style_block` pass, `HiddenHtml.test_css_id_from_style_block` pass, `HiddenHtml.test_each_hiding_technique_is_removed_and_flagged` pass, `HiddenHtml.test_entity_encoded_injection` pass, `HiddenHtml.test_hidden_input_value` pass, `HiddenHtml.test_meta_description` pass, `HiddenHtml.test_script_and_json_ld` pass, `HiddenHtml.test_visible_injection_is_kept_but_flagged` pass, `HiddenHtml.test_white_text_flagged` pass, `HiddenHtml.test_zero_width_and_tags_in_visible_html` pass, `BenignHtml.test_hidden_state_does_not_leak_after_close` pass, `BenignHtml.test_long_hidden_text_is_med` pass, `BenignHtml.test_malformed_html_does_not_crash` pass, `BenignHtml.test_menu_hidden_short_not_high` pass, `BenignHtml.test_title_links_and_images` pass, `Directives.test_hidden_html_directive_without_ai_words` pass, `Directives.test_hidden_html_sentence_is_med_menu_is_not` pass

**W2 Split and embedded web content**: `SplitAcrossChannels.test_html_instruction_split_over_two_hiding_methods` pass, `WebCarriers2.test_css_generated_content` pass, `WebCarriers2.test_html_in_data_uri_iframe_and_plain_text_uri` pass, `WebCarriers2.test_markdown_link_title_and_reference_definition` pass, `WebCarriers2.test_svg_in_data_uri` pass

**W3 Live web content**: `LiveContent.test_decode_and_write` pass, `LiveContent.test_decode_write_with_bot_detection_is_high` pass, `LiveContent.test_time_or_user_agent_dependent_content` pass, `LiveContent.test_encoded_string_in_script` pass, `LiveContent.test_encrypted_payload_is_flagged_even_if_unreadable` pass, `LiveContent.test_plain_analytics_script_not_high` pass

**W6 Reading direction and accessibility**: `DirectionAndAccessibility.test_bdo_and_dir_rtl` pass, `DirectionAndAccessibility.test_docx_rtl_run` pass, `DirectionAndAccessibility.test_mirror_and_custom_font` pass, `DirectionAndAccessibility.test_pdf_reversed_chars` pass

**W4 SVG**: `Svg.test_svg_hidden_text` pass

**W5 Markdown and text**: `MarkdownText.test_benign_markdown_clean` pass, `MarkdownText.test_html_comment` pass, `MarkdownText.test_image_alt_and_title` pass, `MarkdownText.test_inline_hidden_html` pass, `MarkdownText.test_json_value` pass, `MarkdownText.test_multiline_comment` pass, `MarkdownText.test_reference_comment` pass, `MarkdownText.test_tag_characters_stripped_from_output` pass, `Directives.test_markdown_canary_comment` pass, `WebCarriers2.test_markdown_link_title_and_reference_definition` pass

**D1 DOCX**: `Docx.test_broken_xml_fails_closed` pass, `Docx.test_clean` pass, `Docx.test_comments_part` pass, `Docx.test_core_metadata` pass, `Docx.test_custom_xml` pass, `Docx.test_doc_variable` pass, `Docx.test_field_code` pass, `Docx.test_header_footer_visible` pass, `Docx.test_image_alt_text` pass, `Docx.test_macros_flagged` pass, `Docx.test_microscopic_run` pass, `Docx.test_spec_vanish` pass, `Docx.test_textbox_inside_paragraph` pass, `Docx.test_tracked_deletion` pass, `Docx.test_vanish_run` pass, `Docx.test_white_run` pass, `Directives.test_docx_hidden_directive` pass, `MetadataChannels.test_docx_core_title_directive` pass, `OfficeCarriers2.test_docx_alternate_content_differs` pass

**D2 PPTX**: `Pptx.test_clean_and_visible` pass, `Pptx.test_hidden_shape_and_tiny_text` pass, `Pptx.test_hidden_slide` pass, `Pptx.test_shape_alt_text` pass, `Pptx.test_speaker_notes` pass, `OfficeCarriers2.test_pptx_text_off_slide` pass

**D3 XLSX, ODF, EPUB, zip**: `Xlsx.test_hidden_rows` pass, `Xlsx.test_hidden_sheets` pass, `Xlsx.test_instruction_in_cell` pass, `OdfEpubZip.test_epub_hidden_span` pass, `OdfEpubZip.test_odt_annotation` pass, `OdfEpubZip.test_odt_hidden_text` pass, `OdfEpubZip.test_unknown_zip` pass

**L1 Hidden in LaTeX source**: `HiddenInSource.test_comment_directive_is_author_guidance` pass, `HiddenInSource.test_comment_split_over_lines` pass, `HiddenInSource.test_comment_with_ai_instruction` pass, `HiddenInSource.test_directive_in_pdf_metadata_is_med` pass, `HiddenInSource.test_embedded_file` pass, `HiddenInSource.test_escaped_percent_is_not_a_comment` pass, `HiddenInSource.test_glyph_to_unicode_remap` pass, `HiddenInSource.test_iffalse_and_comment_environment` pass, `HiddenInSource.test_kind_is_latex` pass, `HiddenInSource.test_lookalike_and_invisible_in_source` pass, `HiddenInSource.test_pdf_channels` pass, `HiddenInSource.test_phantom_tiny_zero_box_off_page` pass, `HiddenInSource.test_white_text` pass, `Bibtex.test_hidden_bib_fields` pass, `Bibtex.test_normal_bib_is_clean` pass, `PackageCode.test_ai_text_in_package_code_still_high` pass, `PackageCode.test_macro_code_is_info_only` pass, `PackageCode.test_real_template_files_are_clean` pass

**L2 Compile-time code**: `CompileTimeCode.test_catcode_in_document` pass, `CompileTimeCode.test_file_writes_and_packages_are_med` pass, `CompileTimeCode.test_shell_and_file_access` pass

**L3 LaTeX read check**: `LatexHook.test_read_of_clean_tex_is_quiet` pass, `LatexHook.test_read_of_tex_with_hidden_instruction_warns` pass

**A1 Archives and binaries**: `Archives.test_entries_are_scanned` pass, `Archives.test_finder_comment_with_instruction` pass, `Archives.test_macos_metadata` pass, `Archives.test_nested_zip` pass, `Archives.test_path_traversal_name` pass, `Archives.test_unknown_binary_is_med` pass, `OdfEpubZip.test_unknown_zip` pass, `MoreArchives.test_single_file_compression` pass, `MoreArchives.test_tar_path_traversal_and_7z` pass, `MoreArchives.test_tar_variants` pass

**I1 Image metadata and bytes**: `Images.test_appended_payload` pass, `Images.test_clean_png` pass, `Images.test_corrupt_image` pass, `Images.test_extension_lies` pass, `Images.test_faint_text_in_image` pass, `Images.test_jpeg_exif_description` pass, `Images.test_png_tag_chars_in_metadata` pass, `Images.test_png_text_chunk` pass, `ImageDeep.test_unknown_private_chunk` pass, `ImageDeep.test_compressed_private_chunk` pass, `ImageDeep.test_ztxt_and_itxt` pass, `ImageDeep.test_bad_crc` pass, `ImageDeep.test_jpeg_comment_and_app_segment` pass, `MetadataChannels.test_png_metadata_directive` pass

**I2 Alpha and background tricks**: `ImageDeep.test_text_in_fully_transparent_pixels` pass, `ImageDeep.test_text_only_visible_on_dark_background` pass, `ImageDeep.test_normal_logo_with_transparency_is_clean` pass

**I3 LSB steganography**: `ImageDeep.test_lsb_steganography` pass, `ImageDeep.test_lsb_noise_is_clean` pass

**I4 Scaling attack**: `ImageDeep.test_image_scaling_attack` pass, `ImageDeep.test_normal_text_image_not_scaling_attack` pass

**I5 Text in pictures**: `OcrChecks.test_image_file_text_is_transcribed_and_checked` pass

**I6 Polyglot images**: `Polyglots.test_png_then_pdf` pass, `Polyglots.test_html_inside_image` pass, `Polyglots.test_pdf_with_zip_appended` pass

## Red-team log

| Round | Attack | Before the fix | Fix |
|---|---|---|---|
| 1 | Cyrillic a / c inside the regex, single Cyrillic letters in {a, b} | missed | look-alike letters next to Latin/formula characters (T5) |
| 1 | Greek omicron in q0, Cyrillic S in a state name | missed | same |
| 1 | full-width, math and Roman-numeral digits in the task | missed | compatibility-character check (T5) |
| 1 | soft hyphens, hyphenation across lines, line-broken phrases | missed | flattened copy for matching (T7) |
| 1 | combining marks, math bold letters | missed | diacritics/NFKC variants (T7) |
| 1 | synonyms ('pay no attention to the earlier directions') | missed | extra phrase patterns (T1) |
| 1 | chat-template tokens ([INST], <|im_start|>, ### Instruction) | missed | extra phrase patterns (T1) |
| 1 | 'if you can read this' / 'text-only readers:' probes | missed | extra phrase patterns (T1) |
| 1 | German, French, Spanish injections | missed | language patterns, KI keyword (T1, T2) |
| 1 | fingerprint directive (no AI words) in Info, XMP, form fields, annotation, attachment name | missed | DIRECTIVE in all metadata checks (P5) |
| 1 | EXIF of a JPEG embedded in a PDF | missed | text-like runs of raw streams (P11) |
| 1 | ActualText split into one fragment per word | missed | joined ActualText (P4) |
| 1 | instruction split between an HTML comment and a hidden span | missed | pooled hidden text (W2) |
| 1 | black text on a black box, grey on grey | missed | contrast check (P2) |
| 1 | text inside MediaBox but outside CropBox | missed (and real CropBox PDFs were mis-scaled) | CropBox coordinates everywhere (P3) |
| 2 | instruction in a PDF name (/Name#20the#20states) | missed | PDF names decoded (P5) |
| 2 | instruction or directive in a PDF % comment | missed | comment scan (P5) |
| 2 | base64 string in PDF JavaScript | missed | JS literals decoded (P10) |
| 2 | tab / NBSP / em-space between words | tab missed | Unicode space normalisation (T7) |
| 2 | dotted or dashed letters (i.g.n.o.r.e) | missed | separator collapse (T7) |
| 2 | Braille letters | missed | Braille decoder (T6) |
| 2 | SVG or HTML inside a data: URI, iframe srcdoc | missed | data: URI decoding (W2) |
| 2 | CSS generated content (::after { content: ... }) | missed | CSS content check (W2) |
| 2 | Markdown link titles and reference definitions | missed | title checks (W5) |
| 2 | DOCX AlternateContent: Word shows Choice, extractors read Fallback | missed | fallback compared and reported (D1) |
| 2 | PPTX text placed outside the slide | missed | slide-size check (D2) |
| 2 | text covered by a textured image (render diff sees ink) | render diff fooled | reverse OCR: layer words missing from the page (P7) |
| 2 | superscript letters, zero horizontal scaling, huge text rise, bookmark directive | caught already | - |
| 3 | instruction in a LaTeX comment / \iffalse / white or phantom text / BibTeX note | seen only as plain text | LaTeX module (L1) |
| 3 | \write18 without \immediate | missed (pattern bug) | regex fixed (L2) |
| 3 | payload in a zip entry or a macOS Finder comment | zip only listed | archive and binary scanning (A1) |
| 4 | fake <system-reminder>, fake user turn, fake guard verdict, invented consent, fake error with a curl | sh fix | only chat tokens caught | impersonation detector (T10) |
| 4 | hidden 'without the prefix', 'c*', 'over {a,b,c,d}' in HTML/DOCX/LaTeX (short, no AI words) | INFO in HTML/DOCX | hidden task modifier rule (T11) |
| 4 | ActualText a(b*c+ab)* over a printed a(b*c+ab)*c* | looked like a repeat of the visible text | per-span glyph audit (F1) |
| 4 | white box over part of a word (the c* of the task) | word still had ink | per-glyph cover check (F2) |
| 4 | yellow on yellow, red on red, nearly identical blues | caught already (contrast check) | - |
| 4 | bdo / dir=rtl / bidi override, DOCX rtl, PDF ReversedChars | missed | direction checks (W6) |
| 4 | payload in tar, tar.gz/bz2/xz, gz/bz2/xz; 7z/rar | not unpacked | archive support (A1); 7z/rar MED |
| 4 | bits in trailing whitespace | missed | whitespace steganography (T12) |
| 4 | tag reading order reversed against the drawing order | missed | reading-order check (F6) |

## Calibration on real files (false alarms removed)

| Cause | Symptom | Fix |
|---|---|---|
| Typst math fonts have two glyphs for some digits | duplicate-glyph check MED on every sheet | INFO; OCR is the real test |
| MuPDF glues math letters to words (x contains / xcontains) | reader comparison MED on Sheet 1 | spacing-insensitive, dictionary words only |
| thresholded OCR of anti-aliased edges | garbage 'faint text' on clean pages | erase normal ink and its halo first |
| OCR of subscripts (s1 read as s5) | number mismatches | skip digits after one-letter variables |
| tesseract dictionary 'corrected' the typo langugaes printed on Sheet 1 | word mismatch | dictionaries off; page word also in the layer -> INFO |
| Typst writes formula words such as abaab in math italic letters | math-letter words MED | only dictionary words count |
| compressed font bytes read as PDF strings; 'Ki' matched the German KI keyword | 20 HIGH on the 2026 script | stream bodies never scanned as text, KI case-sensitive, text-like runs only |
| Typst outline titles ('Title (E2.1 (Finite Automata') | directive 'title ... automata' HIGH | generic verbs title/number/mark removed |
| embedded font licence ('use the font software') | directive HIGH on fixture 19 | 'font'/'colour' removed from the notation pattern |
| PowerPoint exports put ActualText on every run | HIGH on all 2025 slides | ActualText compared with the drawn glyphs (pypdf, which ignores ActualText) |
| subset fonts with their own encodings (code G -> d) | ToUnicode remap HIGH on 2025 slides | remaps need spelling evidence for HIGH |
| pdftoppm renders the MediaBox, viewers show the CropBox | visible text reported blank in CropBox PDFs | CropBox everywhere |
| MuPDF honours ActualText in some layouts | ActualText over visible glyphs looked 'normal' | pypdf (ignores ActualText) as the glyph reference |
| PDF names scanned inside compressed bytes | 'PDF name' HIGH on old exams and slides | names and % comments only outside stream bodies, text-like only |
| pages with /Rotate 90 (2025 slides): word boxes in the rotated view, page size unrotated | whole slides reported blank | sizes swapped for rotated pages; test RotatedPages |
| LaTeX \not overlay: a zero-width '6' glyph | '6 6 6 6' blank on the 2025 sample solution | lone zero-width glyphs are INFO |
| tesseract reads an isolated bold e as a (every Typst sheet) | glyph OCR MED on clean sheets | a/e added to OCR confusions; symmetric swaps still HIGH |
| narrow glyphs (l, i) fill their own 72-dpi cell | whole script pages 'covered' | cells padded by 2 px; words split at gaps |
| Typst hyphenation ActualText (soft hyphen drawn, '-' read) | glyph audit MED | soft hyphen normalised |
| multi-part math braces (glyph pieces without Unicode) | ActualText mismatch on tutorial 2 | unmapped pieces ignored |
| white quote on a dark Beamer box | white glyphs HIGH | white glyphs only count with AI-directed text |
| PowerPoint export: transparent single '!' glyphs | MED on the kickoff slides | lone glyphs INFO |
| light-grey design text in the 2025 slides | 'faint text' HIGH on 9 decks | faint words also in the text layer are INFO; only missing ones count |

## Survey of the course files (2026-10-30, 119 PDFs)

Verdicts: MED 66, clean 47, HIGH 6. Files with AI-directed instructions: 26/exercise sheets/Exercise_Sheet_2.pdf.

| File | Verdict | HIGH findings |
|---|---|---|
| 25/1._Slides/Lecture_20.pdf | HIGH | genuine hidden text, benign: the German original of a translated slide sits invisibly under the English text | text in text layer but blank on the rendered page |
| 25/1._Slides/Lecture_25.pdf | HIGH | genuine faint content, benign: photo of a handwritten graph with half-erased pencil notes | faint near-white ink |
| 26/5._Slides/Chapter-01-02.pdf | HIGH | benign: Beamer keeps content of other overlay steps outside the page | text outside the visible page |
| 26/6._Slides_with_Annotations/2026-10-14.pdf | HIGH | embedded CMS screenshot with light-grey progress bars, no hidden text | faint near-white ink |
| 26/exercise sheets/Exercise_Sheet_2.pdf | HIGH | THE TRAP: invisible ActualText telling an LLM to solve c*(ba+cb*)a and to hide it | AI-directed words in hidden text; ActualText replacement text; PDF readers disagree: text extracted by poppler but not MuPD; PDF readers disagree: text extracted by poppler but not pypd; PDF string object with AI-directed text; PDF string o |
| exams/ti_Blaeser_2014WS_end.pdf | HIGH | scan of a printed exam: OCR of grey scan noise, no readable words | faint text readable only after removing normal ink and boost |

## Known limits

- A visible, plausible decoy is indistinguishable from a real task - the scanner reports, a human or the agent must compare.
- Phrase and directive lists miss wording nobody anticipated; structural, Unicode, encoding, render, OCR and ambiguity checks do not depend on wording.
- Content produced at runtime (JavaScript, server per visitor) is flagged, not executed; browser snapshots are scanned by the output hook.
- OCR is noisy on mathematics: single-symbol differences in formulas are not reported unless they repeat (systematic swap) or sit in a sentence.
- Glyph-shape swaps inside an embedded font that keep a consistent text layer are only caught by OCR, and only on OCR'd pages (default: first 30).
- QR codes, audio, video and archives inside archives are not decoded.
- Hooks cannot rewrite built-in tool output; they block and redirect, or warn after the fact.
