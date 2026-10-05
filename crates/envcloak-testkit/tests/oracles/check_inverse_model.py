#!/usr/bin/env python3
"""An independent model of the `check_inverse` rule of
scripts/check-reservations.py (task M3-01).

The rule: a decoder's (number, variant) pairs pass exactly when, taken as
a multiset, they are the declaration's (number, variant) pairs less the
entries `NOT_DECODED` names for that enum, and every entry `NOT_DECODED`
names for it is declared. So every declared entry is read back once,
under its own number, and the never-stored ones not at all.

The model takes `check_inverse` and `NOT_DECODED` from the script's source
with `ast` (nothing else of the script runs), calls it on every list of
up to three pairs drawn from numbers 0 to 3 and four variant names, for
five declarations, and compares each verdict with the multiset rule
written here. Its positive controls are the lists the rule accepts: the
model fails when there is none, and when any verdict differs.

Usage: check_inverse_model.py <path to check-reservations.py>
Prints one JSON line (cases, positive controls, rejected, mismatches) and
exits 0, or names the first disagreement and exits 1.
"""

import ast
import builtins
import json
import sys
import types
from collections import Counter
from itertools import product

# (enum, {variant: number}): two plain enums, and `ItemClass` with and
# without the never-stored `None`, and with nothing else.
DECLARATIONS = [
    ("Kind", {"Alpha": 1, "Beta": 2}),
    ("Kind", {"Alpha": 1, "Beta": 2, "Gamma": 3}),
    ("ItemClass", {"None": 0, "Alpha": 1, "Beta": 2}),
    ("ItemClass", {"Alpha": 1, "Beta": 2}),
    ("ItemClass", {"None": 0}),
]
NUMBERS = range(4)
VARIANTS = ["None", "Alpha", "Beta", "Gamma"]
LONGEST = 3


class SourceError(Exception):
    pass


def load(path):
    """`check_inverse`, built from its own definition in the script with
    the model's `SourceError` and the script's `NOT_DECODED`, and that
    table."""
    with open(path, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    fns = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "check_inverse"]
    tables = [n for n in tree.body if isinstance(n, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == "NOT_DECODED" for t in n.targets)]
    if len(fns) != 1 or len(tables) != 1:
        sys.exit("check_inverse_model: the script has %d `check_inverse` and %d `NOT_DECODED`, not one each" % (len(fns), len(tables)))
    not_decoded = ast.literal_eval(tables[0].value)
    module = compile(ast.Module(body=fns, type_ignores=[]), "<check_inverse>", "exec")
    code = [c for c in module.co_consts if isinstance(c, types.CodeType) and c.co_name == "check_inverse"]
    scope = {"__builtins__": builtins, "SourceError": SourceError, "NOT_DECODED": not_decoded}
    return types.FunctionType(code[0], scope), not_decoded


def main(argv):
    if len(argv) != 2:
        sys.exit(__doc__)
    check_inverse, not_decoded = load(argv[1])
    universe = list(product(NUMBERS, VARIANTS))
    cases = accepted = 0
    for enum, declared in DECLARATIONS:
        never = {v for e, v in not_decoded if e == enum}
        expected = Counter((n, v) for v, n in declared.items() if v not in never)
        for size in range(LONGEST + 1):
            for decoded in product(universe, repeat=size):
                want = never <= set(declared) and Counter(decoded) == expected
                try:
                    check_inverse(types.SimpleNamespace(rel="model.rs"), enum, "the decoder", declared, list(decoded))
                    got = True
                except SourceError:
                    got = False
                cases += 1
                accepted += got
                if got != want:
                    print("check_inverse_model: %s %s, decoded %s: the script says %s, the rule says %s" % (
                        enum, declared, list(decoded), "pass" if got else "fail", "pass" if want else "fail"), file=sys.stderr)
                    return 1
    if not accepted:
        print("check_inverse_model: no list passed, so the model has no positive control", file=sys.stderr)
        return 1
    print(json.dumps({"cases": cases, "positive_controls": accepted, "rejected": cases - accepted, "mismatches": 0}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
