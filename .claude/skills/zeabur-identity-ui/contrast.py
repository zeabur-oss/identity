#!/usr/bin/env python3
"""WCAG 2.2 contrast of every colour pair the sign-in pages render.

Reads the ``:root`` colour tokens of the design system package and ``ui/styles/app.css``.
Alpha is composited in gamma-encoded sRGB, as browsers do; ratios follow
https://www.w3.org/TR/WCAG22/#dfn-contrast-ratio. Text needs 4.5:1 (1.4.3), boundaries and
focus indicators 3:1 (1.4.11, 2.4.13). Disabled controls, decorative separators, the card's
edge, the mark and button edges are exempt (Understanding 1.4.11) and not checked.

Usage, from the repository root inside ``nix develop``::

    python3 .claude/skills/zeabur-identity-ui/contrast.py
    python3 .claude/skills/zeabur-identity-ui/contrast.py --set light:input='rgb(126, 122, 133)'

Exit status: 0 when every pair passes, 1 when any fails, 2 on bad input.
"""

from __future__ import annotations

import argparse
import enum
import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

type Rgb = tuple[float, float, float]
"""Linear-light sRGB, each channel in ``[0, 1]``."""

type Tokens = dict[str, Colour]
"""Colour custom properties of one theme, keyed without the leading ``--``."""

type Layers = tuple[Paint, ...]
"""Paints from the bottom up; the first is opaque."""

DEFAULT_CSS = (
    Path("ui/node_modules/@zeabur/design-system/src/tokens.css"),
    Path("ui/styles/app.css"),
)
THEMES = ("light", "dark")
# base.html <body class="bg-zGray-50 dark:bg-zGray-950">
PAGE = {"light": "zGray-50", "dark": "zGray-950"}

_ROOT_BLOCK = re.compile(r"(?<![\w.-]):root\s*\{(?P<body>[^}]*)\}")
_DECLARATION = re.compile(r"--(?P<name>[\w-]+)\s*:\s*(?P<value>[^;]+);")
_HEX = re.compile(r"#([0-9a-fA-F]{6})")
_RGB = re.compile(r"rgba?\(\s*([\d.]+)[\s,]+([\d.]+)[\s,]+([\d.]+)\s*(?:[,/]\s*([\d.]+)(%?))?\s*\)")
_TRIPLET = re.compile(r"\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)\s*")


@dataclass(frozen=True, slots=True)
class Colour:
    """An sRGB colour, stored in linear light; ``alpha`` is in ``[0, 1]``."""

    linear: Rgb
    alpha: float = 1.0

    @classmethod
    def from_srgb(cls, r: float, g: float, b: float, alpha: float = 1.0) -> Colour:
        """From gamma-encoded channels in ``[0, 255]``.

        >>> Colour.from_srgb(255, 255, 255).linear
        (1.0, 1.0, 1.0)
        """
        return cls(_clip(_decode(c / 255) for c in (r, g, b)), alpha)

    def to_linear_srgb(self) -> Rgb:
        return self.linear


def _clip(rgb: Iterable[float]) -> Rgb:
    r, g, b = (min(1.0, max(0.0, c)) for c in rgb)
    return (r, g, b)


def _encode(c: float) -> float:
    return 12.92 * c if c <= 0.0031308 else 1.055 * c ** (1 / 2.4) - 0.055


def _decode(c: float) -> float:
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def composite(top: Rgb, bottom: Rgb, alpha: float) -> Rgb:
    """Draw ``top`` at ``alpha`` over opaque ``bottom``, blending in gamma-encoded sRGB."""
    return _clip(_decode(alpha * _encode(t) + (1 - alpha) * _encode(b)) for t, b in zip(top, bottom, strict=True))


def luminance(rgb: Rgb) -> float:
    """WCAG relative luminance of a linear sRGB colour."""
    r, g, b = rgb
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: Rgb, b: Rgb) -> float:
    """WCAG contrast ratio, from 1 to 21.

    >>> round(contrast((1.0, 1.0, 1.0), (0.0, 0.0, 0.0)), 2)
    21.0
    """
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


@dataclass(frozen=True, slots=True)
class Paint:
    """A token drawn at a Tailwind opacity modifier: ``bg-input/30`` is ``Paint("input", 0.3)``."""

    token: str
    opacity: float = 1.0

    def __str__(self) -> str:
        return self.token if self.opacity == 1 else f"{self.token}/{round(self.opacity * 100)}"

    def over(self, below: Rgb, tokens: Tokens) -> Rgb:
        """Draw this paint, including its token's own alpha, over an opaque colour."""
        colour = lookup(tokens, self.token)
        return composite(colour.to_linear_srgb(), below, colour.alpha * self.opacity)


def lookup(tokens: Tokens, token: str) -> Colour:
    """A token's colour, or a literal ``#rrggbb`` (the button surfaces' fixed gradients)."""
    return parse_colour(token, {}) if token.startswith("#") else tokens[token]


def flatten(layers: Layers, tokens: Tokens) -> Rgb:
    """Composite ``layers`` into the opaque colour a viewer sees."""
    base, *rest = layers
    colour = lookup(tokens, base.token)
    if colour.alpha * base.opacity != 1:
        raise ValueError(f"bottom layer {base} is not opaque")
    rgb = colour.to_linear_srgb()
    for paint in rest:
        rgb = paint.over(rgb, tokens)
    return rgb


class Kind(enum.Enum):
    """What a pair is, and the WCAG success criterion and minimum ratio that apply."""

    TEXT = ("1.4.3", 4.5)
    BOUNDARY = ("1.4.11", 3.0)
    FOCUS = ("2.4.13", 3.0)

    def __init__(self, criterion: str, minimum: float) -> None:
        self.criterion = criterion
        self.minimum = minimum


@dataclass(frozen=True, slots=True, kw_only=True)
class Pair:
    """A foreground paint against the colour beside it, as a template renders it.

    ``fg`` is drawn over ``drawn_on``, which defaults to ``bg``. They differ for
    borders: with ``bg-clip-padding`` a border sits on the card, not on the
    control's own fill, yet must still contrast with that fill.
    """

    name: str
    kind: Kind
    fg: Paint
    bg: Layers
    source: str
    drawn_on: Layers | None = None

    def ratio(self, tokens: Tokens) -> float:
        fg = self.fg.over(flatten(self.drawn_on or self.bg, tokens), tokens)
        return contrast(fg, flatten(self.bg, tokens))


def paint(token: str, opacity: float = 1.0) -> Paint:
    return Paint(token, opacity)


def stack(*paints: Paint) -> Layers:
    return paints


# Keep in step with the templates.

PAGE_BG = stack(paint("page"))  # base.html body: bg-zGray-50 dark:bg-zGray-950
CARD = stack(paint("card"))  # ds.html card: bg-card
ALERT = stack(paint("card"), paint("v2-surface-hover"))  # alert default: bg-v2-surface-hover
ALERT_WARN = stack(paint("card"), paint("amber", 0.08))  # alert warn: bg-amber/8
ALERT_FAIL = stack(paint("card"), paint("danger", 0.06))  # alert destructive: bg-danger/6
DIALOG = stack(paint("popover"))  # ds.html dialog: bg-popover
DIALOG_FOOTER = stack(paint("popover"), paint("v2-surface-hover"))  # dialog footer: bg-v2-surface-hover
# button-primary and button-destructive: the lightest gradient stop.
PRIMARY_LIGHTEST = stack(paint("#8340ff"))
DESTRUCTIVE_LIGHTEST = stack(paint("destructive-from"))

COMMON: tuple[Pair, ...] = (
    Pair(name="card text", kind=Kind.TEXT, fg=paint("text-main"), bg=CARD,
         source="card title, field label and input text (text-main)"),
    Pair(name="secondary text on card", kind=Kind.TEXT, fg=paint("text-secondary"), bg=CARD,
         source="card and field descriptions, #status, separator text, badge (text-secondary)"),
    Pair(name="error text on card", kind=Kind.TEXT, fg=paint("fail-strong"), bg=CARD,
         source="login/setup #error (text-fail-strong)"),
    Pair(name="product name on page", kind=Kind.TEXT, fg=paint("text-main"), bg=PAGE_BG,
         source="base.html header (text-main)"),
    Pair(name="language link", kind=Kind.TEXT, fg=paint("text-secondary"), bg=PAGE_BG,
         source="base.html nav (text-secondary)"),
    Pair(name="alert title", kind=Kind.TEXT, fg=paint("text-main"), bg=ALERT,
         source="ds.html alert default"),
    Pair(name="alert description", kind=Kind.TEXT, fg=paint("text-secondary"), bg=ALERT,
         source="ds.html alert default, description text-secondary"),
    Pair(name="warning alert text", kind=Kind.TEXT, fg=paint("warn-strong"), bg=ALERT_WARN,
         source="ds.html alert warn (account.html backup notice), text-warn-strong"),
    Pair(name="error alert text", kind=Kind.TEXT, fg=paint("fail-strong"), bg=ALERT_FAIL,
         source="ds.html alert destructive (account.html), text-fail-strong"),
    Pair(name="primary button text", kind=Kind.TEXT, fg=paint("#ffffff"), bg=PRIMARY_LIGHTEST,
         source="ds.html button primary (button-primary), lightest gradient stop"),
    Pair(name="destructive button text", kind=Kind.TEXT, fg=paint("on-primary"), bg=DESTRUCTIVE_LIGHTEST,
         source="account.html confirm, ds.html button destructive (button-destructive), lightest gradient stop"),
    Pair(name="quiet destructive button text", kind=Kind.TEXT, fg=paint("fail-strong"),
         bg=stack(paint("secondary-from")),
         source="account.html remove, ds.html button secondary-destructive, upper gradient stop"),
    Pair(name="quiet destructive button text", kind=Kind.TEXT, fg=paint("fail-strong"),
         bg=stack(paint("secondary-to")),
         source="account.html remove, ds.html button secondary-destructive, lower gradient stop"),
    Pair(name="quiet destructive button hover", kind=Kind.TEXT, fg=paint("fail-strong"),
         bg=stack(paint("secondary-danger-from")),
         source="account.html remove, ds.html button secondary-destructive, hover upper stop"),
    Pair(name="quiet destructive button hover", kind=Kind.TEXT, fg=paint("fail-strong"),
         bg=stack(paint("secondary-danger-to")),
         source="account.html remove, ds.html button secondary-destructive, hover lower stop"),
    Pair(name="input border against card", kind=Kind.BOUNDARY, fg=paint("input"), bg=CARD,
         source="ds.html input border-input"),
    Pair(name="input focus edge against card", kind=Kind.FOCUS, fg=paint("ring"), bg=CARD,
         source="ds.html input focus:border-ring"),
    Pair(name="focus outline against card", kind=Kind.FOCUS, fg=paint("focus-ring"), bg=CARD,
         source="design system base.css :focus-visible outline var(--focus-ring)"),
    Pair(name="focus outline against page", kind=Kind.FOCUS, fg=paint("focus-ring"), bg=PAGE_BG,
         source="design system base.css :focus-visible, base.html language links"),
    Pair(name="dialog title", kind=Kind.TEXT, fg=paint("text-main"), bg=DIALOG,
         source="ui.html dialog title (text-main), rename input text"),
    Pair(name="dialog description", kind=Kind.TEXT, fg=paint("text-secondary"), bg=DIALOG,
         source="account.html remove and unlink dialogs (text-secondary)"),
    Pair(name="input border against dialog", kind=Kind.BOUNDARY, fg=paint("input"), bg=DIALOG,
         source="account.html rename dialog, ds.html input border-input"),
    Pair(name="input focus edge against dialog", kind=Kind.FOCUS, fg=paint("ring"), bg=DIALOG,
         source="account.html rename dialog, ds.html input focus:border-ring"),
    Pair(name="focus outline against dialog footer", kind=Kind.FOCUS, fg=paint("focus-ring"),
         bg=DIALOG_FOOTER, source="ui.html dialog footer buttons, base.css :focus-visible"),
)

# button-secondary: the hover's lower gradient stop.
LIGHT: tuple[Pair, ...] = (
    Pair(name="secondary button text", kind=Kind.TEXT, fg=paint("text-main"), bg=stack(paint("#ebebec")),
         source="upstream.html, ds.html button secondary (button-secondary), hover stop #ebebec"),
)

DARK: tuple[Pair, ...] = (
    Pair(name="secondary button text", kind=Kind.TEXT, fg=paint("text-main"), bg=stack(paint("#34343a")),
         source="upstream.html, ds.html button secondary (button-secondary), hover stop #34343a"),
)

PAIRS: dict[str, tuple[Pair, ...]] = {"light": COMMON + LIGHT, "dark": COMMON + DARK}


def split_top_level(text: str) -> list[str]:
    """Split at commas outside parentheses.

    >>> split_top_level("rgb(1, 2, 3), #fff")
    ['rgb(1, 2, 3)', ' #fff']
    """
    parts, depth, start = [], 0, 0
    for i, ch in enumerate(text):
        depth += {"(": 1, ")": -1}.get(ch, 0)
        if ch == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    return parts


def side(value: str, theme: str) -> str:
    """Pick ``theme``'s side of every ``light-dark()`` in ``value``.

    >>> side("light-dark(#000000, rgb(var(--x)))", "dark")
    'rgb(var(--x))'
    """
    while (start := value.find("light-dark(")) != -1:
        depth, end = 0, start + len("light-dark")
        for end in range(start + len("light-dark"), len(value)):
            depth += {"(": 1, ")": -1}.get(value[end], 0)
            if depth == 0:
                break
        light, dark = split_top_level(value[start + len("light-dark(") : end])
        value = value[:start] + (light if theme == "light" else dark).strip() + value[end + 1 :]
    return value


def substitute(value: str, raw: dict[str, str], seen: frozenset[str] = frozenset()) -> str:
    """Replace ``var(--name)`` by its raw value, recursively."""

    def one(match: re.Match[str]) -> str:
        name = match[1]
        if name in seen or name not in raw:
            raise ValueError(f"unresolvable var(--{name})")
        return substitute(raw[name], raw, seen | {name})

    return re.sub(r"var\(--([\w-]+)\)", one, value)


def parse_colour(value: str, raw: dict[str, str]) -> Colour:
    """Parse a resolved value: ``#rrggbb``, ``rgb()``/``rgba()`` or an ``R, G, B`` triplet.

    >>> parse_colour("rgb(0 0 0 / 0.5)", {}).alpha
    0.5
    """
    text = substitute(value, raw).strip()
    if match := _HEX.fullmatch(text):
        h = match[1]
        return Colour.from_srgb(int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))
    if match := _RGB.fullmatch(text):
        r, g, b, alpha, percent = match.groups()
        a = 1.0 if alpha is None else float(alpha) / (100 if percent else 1)
        return Colour.from_srgb(float(r), float(g), float(b), a)
    if match := _TRIPLET.fullmatch(text):
        return Colour.from_srgb(*(float(c) for c in match.groups()))
    raise ValueError(f"not a colour: {value!r}")


def read_tokens(stylesheets: Iterable[str]) -> dict[str, Tokens]:
    """Colour tokens of every ``:root`` block, later declarations winning, resolved per theme.

    >>> css = ":root { --a: 0, 0, 0; --b: light-dark(rgb(var(--a)), #ffffff); }"
    >>> themes = read_tokens([css])
    >>> themes["light"]["b"].linear, themes["dark"]["b"].linear
    ((0.0, 0.0, 0.0), (1.0, 1.0, 1.0))
    """
    declared: dict[str, str] = {}
    for css in stylesheets:
        css = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
        for block in _ROOT_BLOCK.finditer(css):
            for declaration in _DECLARATION.finditer(block["body"]):
                declared[declaration["name"]] = " ".join(declaration["value"].split())
    themes: dict[str, Tokens] = {}
    for theme in THEMES:
        raw = {name: side(value, theme) for name, value in declared.items()}
        tokens: Tokens = {}
        for name in raw:
            try:
                tokens[name] = parse_colour(raw[name], raw)
            except ValueError:
                continue  # not a colour (sizes, shadows, fonts …)
        if PAGE[theme] in tokens:
            tokens["page"] = tokens[PAGE[theme]]
        themes[theme] = tokens
    return themes


def apply_overrides(themes: dict[str, Tokens], overrides: Iterable[str]) -> None:
    """Apply ``THEME:TOKEN=<colour>`` overrides in place, to try a value before editing the CSS."""
    for override in overrides:
        target, _, value = override.partition("=")
        theme, _, token = target.partition(":")
        token = token.removeprefix("--")
        if token not in themes.get(theme, {}):
            raise ValueError(f"--set {override!r}: expected light:TOKEN or dark:TOKEN with an existing token")
        themes[theme][token] = parse_colour(value, {})


@dataclass(frozen=True, slots=True)
class Result:
    theme: str
    pair: Pair
    ratio: float

    @property
    def passed(self) -> bool:
        return self.ratio >= self.pair.kind.minimum


def evaluate(themes: dict[str, Tokens]) -> list[Result]:
    return [Result(theme, pair, pair.ratio(themes[theme])) for theme in THEMES for pair in PAIRS[theme]]


def report(results: Sequence[Result]) -> str:
    """Format results as an aligned table; the last column is not padded."""
    rows = [("theme", "pair", "fg / bg", "ratio", "need", "", "rendered by")]
    rows += [
        (
            r.theme,
            r.pair.name,
            f"{r.pair.fg} / {' + '.join(map(str, r.pair.bg))}",
            f"{r.ratio:.2f}",
            f"{r.pair.kind.minimum:g} ({r.pair.kind.criterion})",
            "ok" if r.passed else "FAIL",
            r.pair.source,
        )
        for r in results
    ]
    widths = [max(map(len, column)) for column in zip(*rows, strict=True)]
    return "\n".join(
        "  ".join(cell.ljust(width) for cell, width in zip(row[:-1], widths, strict=False)) + "  " + row[-1]
        for row in rows
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    parser.add_argument(
        "--css",
        type=Path,
        action="append",
        help="stylesheet, repeatable, later ones winning (default: the vendored tokens, then app.css)",
    )
    parser.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="THEME:TOKEN=COLOUR",
        help="try a token value without editing the stylesheet; repeatable",
    )
    args = parser.parse_args(argv)
    try:
        themes = read_tokens(path.read_text(encoding="utf-8") for path in args.css or DEFAULT_CSS)
        apply_overrides(themes, args.set)
    except (OSError, ValueError) as error:
        print(f"contrast.py: {error}", file=sys.stderr)
        return 2
    results = evaluate(themes)
    print(report(results))
    if failed := sum(not r.passed for r in results):
        print(f"\n{failed} pair(s) below the WCAG minimum", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
