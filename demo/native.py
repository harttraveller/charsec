"""
If you run this with:

```sh
python native.py
```

It will execute the hidden code.
"""

# 󠅙󠅝󠅠󠅟󠅢󠅤󠄐󠅧󠅕󠅒󠅒󠅢󠅟󠅧󠅣󠅕󠅢︊︊󠅧󠅕󠅒󠅒󠅢󠅟󠅧󠅣󠅕󠅢󠄞󠅟󠅠󠅕󠅞󠄘󠄒󠅘󠅤󠅤󠅠󠅣󠄪󠄟󠄟󠅧󠅧󠅧󠄞󠅩󠅟󠅥󠅤󠅥󠅒󠅕󠄞󠅓󠅟󠅝󠄟󠅧󠅑󠅤󠅓󠅘󠄯󠅦󠄭󠅨󠅦󠄶󠅊󠅚󠅟󠄥󠅀󠅗󠄷󠄠󠄒󠄙!/usr/bin/python3


def _x(x: int) -> int | None:
    if 0xFE00 <= x <= 0xFE0F:
        return x - 0xFE00
    elif 0xE0100 <= x <= 0xE01EF:
        return x - 0xE0100 + 16
    return None


exec(bytes([_x(ord(c)) for c in open(__file__).read() if _x(ord(c)) is not None]))  # type: ignore
