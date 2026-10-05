#!/usr/bin/env python3
"""An independent check of check_swift.py's string literal values (an
independent review's conformance oracle, adopted with its controls): every
rule about what a literal says (device paths, `~`, `%{public}`, sysctl
names, key equivalents, gated titles) reads the value the lexer decodes, so
that value must be the one the compiler reads.

The 44 cases and their expected values come from The Swift Programming
Language's lexical reference, not from check_swift.py: ordinary and empty
literals; the escapes `\\t`, `\\n`, `\\r`, `\\0`, `\\"` and `\\\\`; `\\u{...}`
scalars, one beyond the BMP and a combining sequence kept as written; raw
strings with one, two and three `#`s (their escapes need as many `#`s, and
a lone backslash is text); multi-line literals under four indentations
(none, spaces, a tab, mixed), with two lines, extra indentation kept, a line
continuation (a backslash and trailing blanks join two lines) and a raw
multi-line escape; and a nested comment before a literal. Every value is
built from `ABCDE` and `KLMNO`, so nothing the key-literal rule refuses is
written here.

Controls: the comparison is shown to fail for a value that is always
empty, has its line breaks dropped or its leading blanks stripped; and a
decoder that returns each literal's source text instead of its value fails
the cases.

Usage: python3 scripts/macos/tests/test_swift_literal_values.py
"""

import importlib.util
import os
import sys
import unittest

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKER = os.path.join(os.path.dirname(HERE), "check_swift.py")


def load_checker():
    spec = importlib.util.spec_from_file_location("check_swift_under_test", CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ATOM = "".join(chr(i) for i in range(65, 70))
OTHER = "".join(chr(i) for i in range(75, 80))
QUOTE = chr(34)
SLASH = chr(92)


def single(text, hashes=0):
    marks = "#" * hashes
    return marks + QUOTE + text + QUOTE + marks


def multiline(body, indent, hashes=0):
    marks = "#" * hashes
    return marks + QUOTE * 3 + "\n" + body + "\n" + indent + QUOTE * 3 + marks


def cases():
    out = []

    def add(name, source, expected):
        out.append((name, source, expected))

    add("ordinary", single(ATOM), ATOM)
    add("empty", single(""), "")
    for name, escaped, value in [
        ("tab", "t", "\t"),
        ("newline", "n", "\n"),
        ("return", "r", "\r"),
        ("zero", "0", "\0"),
        ("quote", QUOTE, QUOTE),
        ("slash", SLASH, SLASH),
    ]:
        add(name, single(ATOM + SLASH + escaped + OTHER), ATOM + value + OTHER)
    encoded = "".join(SLASH + "u{" + format(ord(ch), "X") + "}" for ch in ATOM)
    add("unicode-scalar-sequence", single(encoded), ATOM)
    add("unicode-astral", single(SLASH + "u{1F30D}"), chr(0x1F30D))
    combining = chr(65) + chr(0x301)
    add("combining-preserved", single(combining), combining)
    for count in (1, 2, 3):
        marks = "#" * count
        prefix = "raw-" + str(count)
        add(prefix + "-ordinary", single(ATOM, count), ATOM)
        add(prefix + "-escape", single(ATOM + SLASH + marks + "n" + OTHER, count), ATOM + "\n" + OTHER)
        add(prefix + "-literal-slash", single(ATOM + SLASH + "n" + OTHER, count), ATOM + SLASH + "n" + OTHER)
        raw_encoded = "".join(SLASH + marks + "u{" + format(ord(ch), "X") + "}" for ch in ATOM)
        add(prefix + "-unicode", single(raw_encoded, count), ATOM)
    for index, indent in enumerate(("", "  ", "\t", " \t")):
        prefix = "multiline-" + str(index)
        add(prefix + "-single", multiline(indent + ATOM, indent), ATOM)
        add(prefix + "-two", multiline(indent + ATOM + "\n" + indent + OTHER, indent), ATOM + "\n" + OTHER)
        add(prefix + "-extra-space", multiline(indent + "  " + ATOM, indent), "  " + ATOM)
        add(prefix + "-continuation", multiline(indent + ATOM + SLASH + " \t\n" + indent + OTHER, indent), ATOM + OTHER)
        add(prefix + "-extended", multiline(indent + ATOM + SLASH + "#n" + OTHER, indent, 1), ATOM + "\n" + OTHER)
    add("nested-comments", "/* outer /* inner */ end */ " + single(ATOM), ATOM)
    return out


def decoded(module, source, value_of=None):
    """The one literal's value as the lexer gives it (or as value_of reads
    the token), or None when the source does not lex to one literal."""
    try:
        tokens = module.Lexer(source).lex()
    except Exception:
        return None
    if len(tokens) != 1 or tokens[0].parts is None:
        return None
    return value_of(tokens[0]) if value_of else tokens[0].value


class LiteralValues(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_checker()
        cls.cases = cases()

    def test_there_are_44_cases(self):
        self.assertEqual(len(self.cases), 44)
        self.assertEqual(len({name for name, _, _ in self.cases}), 44)

    def test_each_literal_has_the_value_the_compiler_reads(self):
        failed = [name for name, source, expected in self.cases if decoded(self.module, source) != expected]
        self.assertEqual(failed, [], "literals whose decoded value differs from the reference's")

    def test_the_comparison_finds_a_wrong_value(self):
        # Controls on the comparison itself: each wrong reading differs from
        # the expected value in at least one case.
        expected = [e for _, _, e in self.cases]
        self.assertTrue(any("" != e for e in expected), "an always-empty value would pass")
        self.assertTrue(any(e.replace("\n", "") != e for e in expected), "dropping line breaks would pass")
        self.assertTrue(any(e.lstrip(" \t") != e for e in expected), "stripping leading blanks would pass")

    def test_a_decoder_that_returns_the_source_text_fails(self):
        # Positive control: reading each literal's source text between its
        # delimiters, as the rules did before values were decoded, fails
        # the cases with escapes, raw delimiters and multi-line forms.
        def source_text(tok):
            return "".join(text for kind, text in tok.parts if kind == "lit")

        failed = [name for name, source, expected in self.cases if decoded(self.module, source, source_text) != expected]
        self.assertGreaterEqual(len(failed), 20, failed)
        for name in ("newline", "unicode-scalar-sequence", "raw-1-escape", "multiline-1-continuation"):
            self.assertIn(name, failed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
