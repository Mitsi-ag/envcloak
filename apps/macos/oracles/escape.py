#!/usr/bin/env python3
"""Independent GRANTS.md display oracle: Unicode categories, not Rust tables.

Default-ignorable reserved code points and visible combining fillers are
explicit contract additions. json.dumps supplies the independent JSON escape
oracle. Fixtures contain runtime-generated synthetic metadata only.
"""
import json
import random
import sys
import unicodedata


def display(text):
    special = {"\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
    out = []
    for c in text:
        n = ord(c)
        invisible = (unicodedata.category(c) in {"Cc", "Cf", "Zl", "Zp"}
                     or n in {0x34F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x2065, 0x3164, 0xFFA0}
                     or 0x180B <= n <= 0x180F or 0xFE00 <= n <= 0xFE0F
                     or 0xFFF9 <= n <= 0xFFFB or 0xE0000 <= n <= 0xE0FFF)
        out.append(special.get(c, "\\u{%x}" % n if invisible else c))
    return "".join(out)


def vectors():
    randomizer = random.Random(303)
    # Every Unicode format/control scalar, plus targeted invisible and
    # visible controls. Fillers are independent of General_Category.
    special = [n for n in range(0x110000)
               if unicodedata.category(chr(n)) in {"Cc", "Cf", "Zl", "Zp"}]
    special += [0x202E, 0x200D, 0x7F, 0x85, 0x34F, 0x115F, 0x180B, 0x3164,
                0xFE0F, 0xFFA0, 0xE0100, 0xE0FFF, 0x2065, 92, 34]
    for index in range(10_000):
        codes = [special[index % len(special)]]
        for _ in range(randomizer.randrange(1, 20)):
            n = randomizer.randrange(0x110000)
            if not 0xD800 <= n <= 0xDFFF:
                codes.append(n)
        text = "".join(map(chr, codes))
        yield {"input": text, "scalars": codes, "display": display(text), "json": json.dumps(text, ensure_ascii=True)}


if __name__ == "__main__":
    # The fixture writer owns and permissions the containing directory.
    with open(sys.argv[1], "x", encoding="utf-8") as output:
        json.dump(list(vectors()), output, ensure_ascii=True)
