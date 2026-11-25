# SPDX-FileCopyrightText: 2026 SpanProof Contributors
# SPDX-License-Identifier: MIT
"""Exact-Decimal Metrology, UN/CEFACT Rec 20 Units, and Piecewise Statutory Math.

Pure Python standard-library engine (``decimal.Decimal`` + ``fractions.Fraction``)
eliminating IEEE-754 binary floating-point drift, locale numeral ambiguity,
affine vs. delta confusion, and unit-scale spoofing across regulatory grading.

Zero external dependencies; zero ``float`` arithmetic in unit, tolerance, or
statutory calculations.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from decimal import (
    ROUND_CEILING,
    ROUND_FLOOR,
    ROUND_HALF_EVEN,
    ROUND_HALF_UP,
    Decimal,
    InvalidOperation,
    localcontext,
)
from fractions import Fraction
from typing import Iterable, Mapping, Union

NumberLike = Union[int, str, Decimal, Fraction]


# ---------------------------------------------------------------------------
# Typed exceptions
# ---------------------------------------------------------------------------


class MetrologyError(ValueError):
    """Base error for deterministic metrology and locale failures."""


class DimensionMismatchError(MetrologyError):
    """Raised when converting or comparing dimensionally incompatible units."""


class UnknownUnitError(MetrologyError):
    """Raised when a unit symbol or UN/CEFACT Rec 20 code is not registered."""


class LocaleParseError(MetrologyError):
    """Raised when a numeric string violates deterministic locale grammar."""


# ---------------------------------------------------------------------------
# Dimensional vector:
#   [Mass, Length, Time, Temperature, Pressure, Volume, Radioactivity, Dose, Currency]
# ---------------------------------------------------------------------------

DIMENSION_NAMES: tuple[str, ...] = (
    "Mass",
    "Length",
    "Time",
    "Temperature",
    "Pressure",
    "Volume",
    "Radioactivity",
    "Dose",
    "Currency",
)


@dataclass(frozen=True)
class DimensionVector:
    """9-component regulatory dimensional basis vector."""

    mass: int = 0
    length: int = 0
    time: int = 0
    temperature: int = 0
    pressure: int = 0
    volume: int = 0
    radioactivity: int = 0
    dose: int = 0
    currency: int = 0

    def as_tuple(self) -> tuple[int, int, int, int, int, int, int, int, int]:
        return (
            self.mass,
            self.length,
            self.time,
            self.temperature,
            self.pressure,
            self.volume,
            self.radioactivity,
            self.dose,
            self.currency,
        )

    def is_dimensionless(self) -> bool:
        return self.as_tuple() == (0, 0, 0, 0, 0, 0, 0, 0, 0)

    def __add__(self, other: "DimensionVector") -> "DimensionVector":
        return DimensionVector(
            mass=self.mass + other.mass,
            length=self.length + other.length,
            time=self.time + other.time,
            temperature=self.temperature + other.temperature,
            pressure=self.pressure + other.pressure,
            volume=self.volume + other.volume,
            radioactivity=self.radioactivity + other.radioactivity,
            dose=self.dose + other.dose,
            currency=self.currency + other.currency,
        )

    def __sub__(self, other: "DimensionVector") -> "DimensionVector":
        return DimensionVector(
            mass=self.mass - other.mass,
            length=self.length - other.length,
            time=self.time - other.time,
            temperature=self.temperature - other.temperature,
            pressure=self.pressure - other.pressure,
            volume=self.volume - other.volume,
            radioactivity=self.radioactivity - other.radioactivity,
            dose=self.dose - other.dose,
            currency=self.currency - other.currency,
        )

    def __mul__(self, power: int) -> "DimensionVector":
        return DimensionVector(
            mass=self.mass * power,
            length=self.length * power,
            time=self.time * power,
            temperature=self.temperature * power,
            pressure=self.pressure * power,
            volume=self.volume * power,
            radioactivity=self.radioactivity * power,
            dose=self.dose * power,
            currency=self.currency * power,
        )

    def __str__(self) -> str:
        parts = [
            f"{name}^{exp}" if exp != 1 else name
            for name, exp in zip(DIMENSION_NAMES, self.as_tuple())
            if exp != 0
        ]
        return " * ".join(parts) if parts else "Dimensionless"


DIM_NONE = DimensionVector()
DIM_MASS = DimensionVector(mass=1)
DIM_LENGTH = DimensionVector(length=1)
DIM_TIME = DimensionVector(time=1)
DIM_TEMPERATURE = DimensionVector(temperature=1)
DIM_PRESSURE = DimensionVector(pressure=1)
DIM_VOLUME = DimensionVector(volume=1)
DIM_RADIOACTIVITY = DimensionVector(radioactivity=1)
DIM_DOSE = DimensionVector(dose=1)
DIM_CURRENCY = DimensionVector(currency=1)
DIM_AREA = DimensionVector(length=2)
DIM_FREQUENCY = DimensionVector(time=-1)
DIM_SPEED = DimensionVector(length=1, time=-1)
DIM_CONCENTRATION = DimensionVector(mass=1, volume=-1)


# ---------------------------------------------------------------------------
# Exact Decimal / Fraction conversion helpers (zero float arithmetic)
# ---------------------------------------------------------------------------


def to_decimal(value: NumberLike) -> Decimal:
    """Convert int, str, Decimal, or Fraction to exact Decimal without float ops."""
    if isinstance(value, Decimal):
        if value.is_nan() or value.is_infinite():
            raise LocaleParseError(f"Non-finite Decimal not permitted: {value!r}")
        return value
    if isinstance(value, bool):
        raise TypeError(f"Boolean is not a numeric quantity: {value!r}")
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, Fraction):
        return _fraction_to_decimal(value)
    if isinstance(value, str):
        return parse_locale_decimal(value)
    if isinstance(value, float):
        # Convert decimal representation of float if passed at legacy boundaries;
        # no float arithmetic is performed.
        return Decimal(str(value))
    raise TypeError(f"Unsupported numeric type: {type(value).__name__}")


def to_fraction(value: NumberLike) -> Fraction:
    """Convert int, str, Decimal, or Fraction to an exact rational Fraction."""
    if isinstance(value, Fraction):
        return value
    if isinstance(value, bool):
        raise TypeError(f"Boolean is not a numeric quantity: {value!r}")
    if isinstance(value, int):
        return Fraction(value, 1)
    if isinstance(value, Decimal):
        if value.is_nan() or value.is_infinite():
            raise LocaleParseError(f"Non-finite Decimal not permitted: {value!r}")
        return Fraction(value)
    if isinstance(value, str):
        return Fraction(parse_locale_decimal(value))
    if isinstance(value, float):
        return Fraction(Decimal(str(value)))
    raise TypeError(f"Unsupported numeric type: {type(value).__name__}")


def _fraction_to_decimal(frac: Fraction, max_precision: int = 34) -> Decimal:
    """Convert Fraction to exact Decimal when terminating, else 34-digit Decimal."""
    num = frac.numerator
    den = frac.denominator
    if num == 0:
        return Decimal("0")

    rem = den
    pow2 = 0
    while rem % 2 == 0:
        rem //= 2
        pow2 += 1
    pow5 = 0
    while rem % 5 == 0:
        rem //= 5
        pow5 += 1

    if rem == 1:
        k = pow2 if pow2 >= pow5 else pow5
        scaled = num * (2 ** (k - pow2)) * (5 ** (k - pow5))
        while k > 0 and scaled % 10 == 0:
            scaled //= 10
            k -= 1
        return Decimal(scaled).scaleb(-k)

    with localcontext() as ctx:
        ctx.prec = max_precision
        out = Decimal(num) / Decimal(den)
    return out


# ---------------------------------------------------------------------------
# UN/CEFACT Rec 20 Unit Registry + SI prefixes (pico .. tera)
# ---------------------------------------------------------------------------

SI_PREFIX_SYMBOLS: Mapping[str, Fraction] = {
    "p": Fraction(1, 10**12),
    "n": Fraction(1, 10**9),
    "u": Fraction(1, 10**6),
    "µ": Fraction(1, 10**6),
    "μ": Fraction(1, 10**6),
    "mc": Fraction(1, 10**6),
    "m": Fraction(1, 10**3),
    "c": Fraction(1, 10**2),
    "d": Fraction(1, 10),
    "da": Fraction(10),
    "h": Fraction(10**2),
    "k": Fraction(10**3),
    "M": Fraction(10**6),
    "G": Fraction(10**9),
    "T": Fraction(10**12),
}

SI_PREFIX_WORDS: Mapping[str, Fraction] = {
    "pico": Fraction(1, 10**12),
    "nano": Fraction(1, 10**9),
    "micro": Fraction(1, 10**6),
    "milli": Fraction(1, 10**3),
    "centi": Fraction(1, 10**2),
    "deci": Fraction(1, 10),
    "deca": Fraction(10),
    "deka": Fraction(10),
    "hecto": Fraction(10**2),
    "kilo": Fraction(10**3),
    "mega": Fraction(10**6),
    "giga": Fraction(10**9),
    "tera": Fraction(10**12),
}


@dataclass(frozen=True)
class UnitSpec:
    """Exact rational specification of a unit relative to its dimension base."""

    symbol: str
    un_cefact: str
    name: str
    dimension: DimensionVector
    scale: Fraction
    offset: Fraction = Fraction(0)
    is_affine: bool = False
    quantity_kind: str = ""


# Exact SI / NIST SP 811 / 10 CFR / UN/CEFACT Rec 20 base constants
_POUND_IN_G = Fraction(45359237, 100000)       # 453.59237 g exact
_INCH_IN_M = Fraction(254, 10000)              # 0.0254 m exact
_FOOT_IN_M = _INCH_IN_M * 12                   # 0.3048 m exact
_YARD_IN_M = _FOOT_IN_M * 3                    # 0.9144 m exact
_IN3_IN_L = (_INCH_IN_M ** 3) * 1000           # 0.016387064 L exact
_US_GAL_IN_L = _IN3_IN_L * 231                 # 3.785411784 L exact (231 in^3)
_IMP_GAL_IN_L = Fraction(454609, 100000)       # 4.54609 L exact
_BARREL_IN_L = _US_GAL_IN_L * 42               # 158.987294928 L exact (42 US gal)
_AVDP_OZ_IN_G = _POUND_IN_G / 16               # 28.349523125 g exact
_TROY_OZ_IN_G = Fraction(311034768, 10**7)     # 31.1034768 g exact
_FL_OZ_IN_L = _US_GAL_IN_L / 128               # 0.0295735295625 L exact
_IMP_FL_OZ_IN_L = _IMP_GAL_IN_L / 160          # 0.0284130625 L exact

_KELVIN_OFFSET_C = Fraction(5463, 20)          # 273.15 K exact
_FAHRENHEIT_SCALE = Fraction(5, 9)
_FAHRENHEIT_OFFSET = _KELVIN_OFFSET_C - Fraction(32) * _FAHRENHEIT_SCALE  # 459.67 * 5/9 K

_ATM_IN_PA = Fraction(101325)                  # 101.325 kPa exact
_PSIA_PER_ATM = Fraction("14.6959488")         # Standard NIST/engineering psia/atm
_PSI_IN_PA = _ATM_IN_PA / _PSIA_PER_ATM

_CURIE_IN_BQ = Fraction(37_000_000_000)        # 3.7e10 Bq exact (10 CFR)
_REM_IN_SV = Fraction(1, 100)                  # 0.01 Sv exact
_RAD_IN_GY = Fraction(1, 100)                  # 0.01 Gy exact


# Exact case registry first; lowercase fallback second.
_EXACT_UNITS: dict[str, UnitSpec] = {}
_LOWER_UNITS: dict[str, UnitSpec] = {}


def _register(spec: UnitSpec, *aliases: str, lower_aliases: tuple[str, ...] = ()) -> UnitSpec:
    for token in (spec.symbol, spec.un_cefact, *aliases):
        if token:
            _EXACT_UNITS[token] = spec
            _LOWER_UNITS.setdefault(token.lower(), spec)
    for token in lower_aliases:
        if token:
            _LOWER_UNITS[token.lower()] = spec
    return spec


def _register_si_family(
    base_symbol: str,
    base_name: str,
    dimension: DimensionVector,
    base_scale: Fraction,
    *,
    un_cefact_base: str = "",
    prefix_codes: Mapping[str, str] | None = None,
    word_stem: str = "",
    word_plurals: tuple[str, ...] = (),
    extra_base_aliases: tuple[str, ...] = (),
    quantity_kind: str = "",
    allow_mc_prefix: bool = False,
) -> None:
    prefix_codes = prefix_codes or {}
    base_spec = _register(
        UnitSpec(
            symbol=base_symbol,
            un_cefact=un_cefact_base,
            name=base_name,
            dimension=dimension,
            scale=base_scale,
            quantity_kind=quantity_kind,
        ),
        *extra_base_aliases,
        lower_aliases=(word_stem, *word_plurals) if word_stem else word_plurals,
    )
    _ = base_spec
    for pfx, factor in SI_PREFIX_SYMBOLS.items():
        if pfx == "mc" and not allow_mc_prefix:
            continue
        sym = f"{pfx}{base_symbol}"
        code = prefix_codes.get(pfx, "")
        _register(
            UnitSpec(
                symbol=sym,
                un_cefact=code,
                name=f"{pfx}{base_name}",
                dimension=dimension,
                scale=base_scale * factor,
                quantity_kind=quantity_kind,
            )
        )
    if word_stem:
        for pfx_word, factor in SI_PREFIX_WORDS.items():
            full = f"{pfx_word}{word_stem}"
            _register(
                UnitSpec(
                    symbol=f"{pfx_word}-{base_symbol}",
                    un_cefact="",
                    name=full,
                    dimension=dimension,
                    scale=base_scale * factor,
                    quantity_kind=quantity_kind,
                ),
                lower_aliases=(full, f"{full}s"),
            )


# --- Mass (base: gram) ---
_register_si_family(
    "g",
    "gram",
    DIM_MASS,
    Fraction(1),
    un_cefact_base="GRM",
    prefix_codes={"k": "KGM", "m": "MGM", "u": "MC", "µ": "MC", "μ": "MC", "n": "C45", "p": "Q33"},
    word_stem="gram",
    word_plurals=("grams",),
    allow_mc_prefix=True,
)
_register(
    UnitSpec("kg", "KGM", "kilogram", DIM_MASS, Fraction(1000)),
    "kgs", "kilo", "kilos",
    lower_aliases=("kilogram", "kilograms", "kilogramme", "kilogrammes"),
)
_register(
    UnitSpec("TNE", "TNE", "metric tonne", DIM_MASS, Fraction(1_000_000)),
    "t", "tonne", "tonnes", "MT",
    lower_aliases=("metric ton", "metric tons", "metric tonne", "metric tonnes"),
)
_register(
    UnitSpec("LBR", "LBR", "avoirdupois pound", DIM_MASS, _POUND_IN_G),
    "lb", "lbs", "lbm",
    lower_aliases=("pound", "pounds", "avoirdupois pound", "avoirdupois pounds"),
)
_register(
    UnitSpec("STN", "STN", "US short ton", DIM_MASS, _POUND_IN_G * 2000),
    "ton", "tons",
    lower_aliases=("short ton", "short tons", "us ton", "us tons", "net ton", "net tons"),
)
_register(
    UnitSpec("LTN", "LTN", "imperial long ton", DIM_MASS, _POUND_IN_G * 2240),
    lower_aliases=(
        "long ton", "long tons", "uk ton", "uk tons",
        "gross ton", "gross tons", "imperial ton", "imperial tons",
    ),
)
_register(
    UnitSpec("ONZ", "ONZ", "avoirdupois ounce", DIM_MASS, _AVDP_OZ_IN_G),
    "oz", "ozs",
    lower_aliases=(
        "ounce", "ounces", "avoirdupois oz", "avoirdupois ounce",
        "avoirdupois ounces", "oz avdp",
    ),
)
_register(
    UnitSpec("APZ", "APZ", "troy ounce", DIM_MASS, _TROY_OZ_IN_G),
    "ozt", "oz t",
    lower_aliases=("troy oz", "troy ounce", "troy ounces"),
)
_register(
    UnitSpec("GRN", "GRN", "grain", DIM_MASS, _POUND_IN_G / 7000),
    "gr",
    lower_aliases=("grain", "grains"),
)

# --- Length (base: metre) ---
_register_si_family(
    "m",
    "metre",
    DIM_LENGTH,
    Fraction(1),
    un_cefact_base="MTR",
    prefix_codes={"k": "KMT", "c": "CMT", "m": "MMT", "u": "4H", "µ": "4H", "n": "C45"},
    word_stem="meter",
    word_plurals=("meters", "metre", "metres"),
)
for _pfx_w, _f in SI_PREFIX_WORDS.items():
    _LOWER_UNITS[f"{_pfx_w}metre"] = UnitSpec(
        f"{_pfx_w}-m", "", f"{_pfx_w}metre", DIM_LENGTH, _f
    )
    _LOWER_UNITS[f"{_pfx_w}metres"] = _LOWER_UNITS[f"{_pfx_w}metre"]

_register(
    UnitSpec("INH", "INH", "inch", DIM_LENGTH, _INCH_IN_M),
    "in", "inch", "inches",
)
_register(
    UnitSpec("FOT", "FOT", "foot", DIM_LENGTH, _FOOT_IN_M),
    "ft", "foot", "feet",
)
_register(
    UnitSpec("YRD", "YRD", "yard", DIM_LENGTH, _YARD_IN_M),
    "yd", "yds", "yard", "yards",
)
_register(
    UnitSpec("SMI", "SMI", "statute mile", DIM_LENGTH, _FOOT_IN_M * 5280),
    "mi", "mile", "miles",
)
_register(
    UnitSpec("NMI", "NMI", "nautical mile", DIM_LENGTH, Fraction(1852)),
    "nmi",
    lower_aliases=("nautical mile", "nautical miles"),
)

# --- Area (base: m^2) ---
_register(UnitSpec("MTK", "MTK", "square metre", DIM_AREA, Fraction(1)), "m2", "m^2", lower_aliases=("square meter", "square meters", "square metre", "square metres"))
_register(UnitSpec("CMK", "CMK", "square centimetre", DIM_AREA, Fraction(1, 10**4)), "cm2", "cm^2")
_register(UnitSpec("MMK", "MMK", "square millimetre", DIM_AREA, Fraction(1, 10**6)), "mm2", "mm^2")
_register(UnitSpec("KMK", "KMK", "square kilometre", DIM_AREA, Fraction(10**6)), "km2", "km^2")
_register(UnitSpec("INK", "INK", "square inch", DIM_AREA, _INCH_IN_M ** 2), "in2", "in^2", lower_aliases=("square inch", "square inches"))
_register(UnitSpec("FTK", "FTK", "square foot", DIM_AREA, _FOOT_IN_M ** 2), "ft2", "ft^2", "sqft", lower_aliases=("square foot", "square feet"))
_register(UnitSpec("YDK", "YDK", "square yard", DIM_AREA, _YARD_IN_M ** 2), "yd2", "yd^2", lower_aliases=("square yard", "square yards"))
_register(UnitSpec("HAR", "HAR", "hectare", DIM_AREA, Fraction(10_000)), "ha", lower_aliases=("hectare", "hectares"))
_register(UnitSpec("ACR", "ACR", "acre", DIM_AREA, (_FOOT_IN_M ** 2) * 43560), "ac", lower_aliases=("acre", "acres"))

# --- Volume (base: litre) ---
_register_si_family(
    "L",
    "litre",
    DIM_VOLUME,
    Fraction(1),
    un_cefact_base="LTR",
    prefix_codes={"m": "MLT", "d": "DLT", "c": "CLT", "k": "KLT"},
    word_stem="liter",
    word_plurals=("liters", "litre", "litres"),
    extra_base_aliases=("l",),
)
# Also explicit lowercase/uppercase mL/ml, uL/ul, etc.
for _p, _f in SI_PREFIX_SYMBOLS.items():
    if _p == "mc":
        continue
    _spec_l = UnitSpec(f"{_p}L", "", f"{_p}liter", DIM_VOLUME, _f)
    _EXACT_UNITS[f"{_p}l"] = _spec_l
    if _p in ("m", "c", "d", "u", "µ", "μ", "n", "p", "k"):
        _LOWER_UNITS[f"{_p}l"] = _spec_l
        _LOWER_UNITS[f"{_p}ls"] = _spec_l
_LOWER_UNITS["ml"] = _EXACT_UNITS["mL"]
_LOWER_UNITS["mls"] = _EXACT_UNITS["mL"]
for _pfx_w, _f in SI_PREFIX_WORDS.items():
    _LOWER_UNITS[f"{_pfx_w}litre"] = UnitSpec(f"{_pfx_w}-L", "", f"{_pfx_w}litre", DIM_VOLUME, _f)
    _LOWER_UNITS[f"{_pfx_w}litres"] = _LOWER_UNITS[f"{_pfx_w}litre"]

_register(UnitSpec("MTQ", "MTQ", "cubic metre", DIM_VOLUME, Fraction(1000)), "m3", "m^3", lower_aliases=("cubic meter", "cubic meters", "cubic metre", "cubic metres"))
_register(UnitSpec("DMQ", "DMQ", "cubic decimetre", DIM_VOLUME, Fraction(1)), "dm3", "dm^3")
_register(UnitSpec("CMQ", "CMQ", "cubic centimetre", DIM_VOLUME, Fraction(1, 1000)), "cm3", "cm^3", "cc")
_register(UnitSpec("MMQ", "MMQ", "cubic millimetre", DIM_VOLUME, Fraction(1, 1_000_000)), "mm3", "mm^3")
_register(UnitSpec("INQ", "INQ", "cubic inch", DIM_VOLUME, _IN3_IN_L), "in3", "in^3", lower_aliases=("cubic inch", "cubic inches"))
_register(UnitSpec("FTQ", "FTQ", "cubic foot", DIM_VOLUME, _IN3_IN_L * 1728), "ft3", "ft^3", lower_aliases=("cubic foot", "cubic feet"))
_register(
    UnitSpec("GLL", "GLL", "US liquid gallon", DIM_VOLUME, _US_GAL_IN_L),
    "gal", "gals",
    lower_aliases=(
        "gallon", "gallons", "us gal", "us gallon", "us gallons",
        "us liquid gallon", "us liquid gallons",
    ),
)
_register(
    UnitSpec("GLI", "GLI", "Imperial gallon", DIM_VOLUME, _IMP_GAL_IN_L),
    lower_aliases=(
        "imp gal", "imp. gal.", "imperial gallon", "imperial gallons",
        "uk gal", "uk gallon", "uk gallons",
    ),
)
_register(
    UnitSpec("BLL", "BLL", "petroleum barrel (42 US gal)", DIM_VOLUME, _BARREL_IN_L),
    "bbl", "bbls",
    lower_aliases=("barrel", "barrels", "petroleum barrel", "petroleum barrels", "oil barrel", "oil barrels"),
)
_register(
    UnitSpec("OZA", "OZA", "US fluid ounce", DIM_VOLUME, _FL_OZ_IN_L),
    "fl oz", "fl. oz.", "floz",
    lower_aliases=("us fl oz", "fluid oz", "fluid ounce", "fluid ounces", "us fluid ounce", "us fluid ounces"),
)
_register(
    UnitSpec("OZI", "OZI", "Imperial fluid ounce", DIM_VOLUME, _IMP_FL_OZ_IN_L),
    lower_aliases=("imp fl oz", "imperial fluid ounce", "imperial fluid ounces"),
)
_register(UnitSpec("PTD", "PTD", "US liquid pint", DIM_VOLUME, _US_GAL_IN_L / 8), "pt", lower_aliases=("pint", "pints"))
_register(UnitSpec("QTD", "QTD", "US liquid quart", DIM_VOLUME, _US_GAL_IN_L / 4), "qt", lower_aliases=("quart", "quarts"))

# --- Time (base: second) & Frequency (base: Hz = 1/s) ---
_register_si_family(
    "s",
    "second",
    DIM_TIME,
    Fraction(1),
    un_cefact_base="SEC",
    prefix_codes={"m": "C26", "u": "B98", "µ": "B98", "n": "C47", "p": "H70"},
    word_stem="second",
    word_plurals=("seconds",),
    extra_base_aliases=("sec", "secs"),
)
_register(UnitSpec("MIN", "MIN", "minute", DIM_TIME, Fraction(60)), "min", "mins", lower_aliases=("minute", "minutes"))
_register(UnitSpec("HUR", "HUR", "hour", DIM_TIME, Fraction(3600)), "h", "hr", "hrs", lower_aliases=("hour", "hours"))
_register(UnitSpec("DAY", "DAY", "day", DIM_TIME, Fraction(86400)), "d", lower_aliases=("day", "days"))
_register(UnitSpec("WEE", "WEE", "week", DIM_TIME, Fraction(604800)), "wk", "wks", lower_aliases=("week", "weeks"))

_register_si_family(
    "Hz",
    "hertz",
    DIM_FREQUENCY,
    Fraction(1),
    un_cefact_base="HTZ",
    prefix_codes={"k": "KHZ", "M": "MHZ", "G": "GHZ", "T": "THZ"},
    word_stem="hertz",
)
# Lowercase CFR alias defaults for MHz/GHz/kHz
_LOWER_UNITS.setdefault("khz", _EXACT_UNITS["kHz"])
_LOWER_UNITS.setdefault("mhz", _EXACT_UNITS["MHz"])
_LOWER_UNITS.setdefault("ghz", _EXACT_UNITS["GHz"])
_LOWER_UNITS.setdefault("thz", _EXACT_UNITS["THz"])

# --- Speed (base: m/s) ---
_register(UnitSpec("MTS", "MTS", "metre per second", DIM_SPEED, Fraction(1)), "m/s")
_register(UnitSpec("KMH", "KMH", "kilometre per hour", DIM_SPEED, Fraction(1000, 3600)), "km/h", "kph")
_register(UnitSpec("HM", "HM", "mile per hour", DIM_SPEED, (_FOOT_IN_M * 5280) / 3600), "mph")
_register(UnitSpec("KNT", "KNT", "knot", DIM_SPEED, Fraction(1852, 3600)), "kt", "kts", lower_aliases=("knot", "knots"))

# --- Power (base: watt = kg*m^2/s^3) ---
_DIM_POWER = DimensionVector(mass=1, length=2, time=-3)
_register_si_family(
    "W",
    "watt",
    _DIM_POWER,
    Fraction(1),
    un_cefact_base="WTT",
    prefix_codes={"m": "J57", "k": "KWT", "M": "MAW", "G": "A90"},
    word_stem="watt",
    word_plurals=("watts",),
)
_LOWER_UNITS.setdefault("kw", _EXACT_UNITS["kW"])
_LOWER_UNITS.setdefault("mw", _EXACT_UNITS["MW"])
_LOWER_UNITS.setdefault("gw", _EXACT_UNITS["GW"])
_register(UnitSpec("BHP", "BHP", "mechanical horsepower", _DIM_POWER, Fraction(745699872, 1_000_000)), "hp", lower_aliases=("horsepower",))

# --- Temperature (base: kelvin; AFFINE!) ---
_register(
    UnitSpec("K", "KEL", "kelvin", DIM_TEMPERATURE, Fraction(1), Fraction(0), is_affine=False),
    "°K",
    lower_aliases=("kelvin", "kelvins"),
)
_register(
    UnitSpec("°C", "CEL", "degree Celsius", DIM_TEMPERATURE, Fraction(1), _KELVIN_OFFSET_C, is_affine=True),
    "C", "degC", "deg C",
    lower_aliases=("celsius", "degrees celsius", "degree celsius", "°c"),
)
_register(
    UnitSpec("°F", "FAH", "degree Fahrenheit", DIM_TEMPERATURE, _FAHRENHEIT_SCALE, _FAHRENHEIT_OFFSET, is_affine=True),
    "F", "degF", "deg F",
    lower_aliases=("fahrenheit", "degrees fahrenheit", "degree fahrenheit", "°f"),
)
_register(
    UnitSpec("°R", "A1", "degree Rankine", DIM_TEMPERATURE, _FAHRENHEIT_SCALE, Fraction(0), is_affine=False),
    "degR",
    lower_aliases=("rankine", "degrees rankine"),
)

# --- Pressure (base: pascal; psig is AFFINE gauge pressure!) ---
_register_si_family(
    "Pa",
    "pascal",
    DIM_PRESSURE,
    Fraction(1),
    un_cefact_base="PAL",
    prefix_codes={"h": "HPA", "k": "KPA", "M": "MPA", "G": "GPA"},
    word_stem="pascal",
    word_plurals=("pascals",),
)
_LOWER_UNITS.setdefault("kpa", _EXACT_UNITS["kPa"])
_LOWER_UNITS.setdefault("mpa", _EXACT_UNITS["MPa"])
_LOWER_UNITS.setdefault("gpa", _EXACT_UNITS["GPa"])
_LOWER_UNITS.setdefault("hpa", _EXACT_UNITS["hPa"])

_register_si_family(
    "bar",
    "bar",
    DIM_PRESSURE,
    Fraction(100_000),
    un_cefact_base="BAR",
    prefix_codes={"m": "MBR", "k": "KBA"},
    extra_base_aliases=("bars",),
)
_register(UnitSpec("ATM", "ATM", "standard atmosphere", DIM_PRESSURE, _ATM_IN_PA), "atm")
_register(UnitSpec("PSI", "PSI", "pound-force per square inch", DIM_PRESSURE, _PSI_IN_PA), "psi")
_register(UnitSpec("psia", "PS", "pound-force per square inch absolute", DIM_PRESSURE, _PSI_IN_PA, Fraction(0), is_affine=False))
_register(UnitSpec("psig", "PIG", "pound-force per square inch gauge", DIM_PRESSURE, _PSI_IN_PA, _ATM_IN_PA, is_affine=True))
_register(UnitSpec("TORR", "TORR", "torr", DIM_PRESSURE, _ATM_IN_PA / 760), "torr", "mmHg")

# --- Radiobiology (10 CFR): Radioactivity & Dose ---
_register_si_family(
    "Bq",
    "becquerel",
    DIM_RADIOACTIVITY,
    Fraction(1),
    un_cefact_base="BQL",
    prefix_codes={"k": "2R", "M": "4N", "G": "GBQ", "T": "TBQ"},
    word_stem="becquerel",
    word_plurals=("becquerels",),
)
_LOWER_UNITS.setdefault("kbq", _EXACT_UNITS["kBq"])
_LOWER_UNITS.setdefault("mbq", _EXACT_UNITS["MBq"])
_LOWER_UNITS.setdefault("gbq", _EXACT_UNITS["GBq"])
_LOWER_UNITS.setdefault("tbq", _EXACT_UNITS["TBq"])

_register_si_family(
    "Ci",
    "curie",
    DIM_RADIOACTIVITY,
    _CURIE_IN_BQ,
    un_cefact_base="CUR",
    prefix_codes={"m": "MCU", "u": "M5", "µ": "M5", "p": "2U"},
    word_stem="curie",
    word_plurals=("curies",),
)
_LOWER_UNITS.setdefault("ci", _EXACT_UNITS["Ci"])
_LOWER_UNITS.setdefault("mci", _EXACT_UNITS["mCi"])
_LOWER_UNITS.setdefault("uci", _EXACT_UNITS["uCi"])
_LOWER_UNITS.setdefault("µci", _EXACT_UNITS["µCi"])
_LOWER_UNITS.setdefault("pci", _EXACT_UNITS["pCi"])

# Dose equivalent (Sv <-> rem) — quantity_kind="dose_equivalent"
_register_si_family(
    "Sv",
    "sievert",
    DIM_DOSE,
    Fraction(1),
    un_cefact_base="SIE",
    prefix_codes={"m": "MSV", "u": "USV", "µ": "USV"},
    word_stem="sievert",
    word_plurals=("sieverts",),
    quantity_kind="dose_equivalent",
)
_LOWER_UNITS.setdefault("msv", _EXACT_UNITS["mSv"])
_LOWER_UNITS.setdefault("usv", _EXACT_UNITS["uSv"])
_LOWER_UNITS.setdefault("µsv", _EXACT_UNITS["µSv"])

_register_si_family(
    "rem",
    "rem",
    DIM_DOSE,
    _REM_IN_SV,
    un_cefact_base="REM",
    quantity_kind="dose_equivalent",
    extra_base_aliases=("rems",),
)

# Absorbed dose (Gy <-> rad) — quantity_kind="absorbed_dose"
_register_si_family(
    "Gy",
    "gray",
    DIM_DOSE,
    Fraction(1),
    un_cefact_base="GRY",
    prefix_codes={"m": "MGY", "k": "KGY"},
    word_stem="gray",
    word_plurals=("grays",),
    quantity_kind="absorbed_dose",
)
_LOWER_UNITS.setdefault("mgy", _EXACT_UNITS["mGy"])
_LOWER_UNITS.setdefault("kgy", _EXACT_UNITS["kGy"])

_register_si_family(
    "rad",
    "rad",
    DIM_DOSE,
    _RAD_IN_GY,
    un_cefact_base="RAD",
    quantity_kind="absorbed_dose",
    extra_base_aliases=("rads",),
)

# --- Currency ---
_register(UnitSpec("USD", "USD", "US dollar", DIM_CURRENCY, Fraction(1), quantity_kind="USD"), "$", "US$", lower_aliases=("dollar", "dollars", "us dollar", "us dollars"))
_register(UnitSpec("cent", "CNT", "US cent", DIM_CURRENCY, Fraction(1, 100), quantity_kind="USD"), "cents", "¢")
_register(UnitSpec("EUR", "EUR", "euro", DIM_CURRENCY, Fraction(1), quantity_kind="EUR"), "€", lower_aliases=("euro", "euros"))
_register(UnitSpec("GBP", "GBP", "pound sterling", DIM_CURRENCY, Fraction(1), quantity_kind="GBP"), "£")
_register(UnitSpec("JPY", "JPY", "Japanese yen", DIM_CURRENCY, Fraction(1), quantity_kind="JPY"), "¥")

# --- Dimensionless ratios & angles (separated by quantity_kind) ---
_register(UnitSpec("%", "P1", "percent", DIM_NONE, Fraction(1, 100), quantity_kind="ratio"), "percent", "pct", "percentage")
_register(UnitSpec("bps", "BPS", "basis point", DIM_NONE, Fraction(1, 10_000), quantity_kind="ratio"), lower_aliases=("basis point", "basis points"))
_register(UnitSpec("ppm", "59", "parts per million", DIM_NONE, Fraction(1, 10**6), quantity_kind="ratio"), lower_aliases=("parts per million",))
_register(UnitSpec("ppb", "61", "parts per billion", DIM_NONE, Fraction(1, 10**9), quantity_kind="ratio"), lower_aliases=("parts per billion",))
_register(UnitSpec("ppt", "PPT", "parts per trillion", DIM_NONE, Fraction(1, 10**12), quantity_kind="ratio"), lower_aliases=("parts per trillion",))
_register(UnitSpec("°", "DD", "degree of arc", DIM_NONE, Fraction(1), quantity_kind="angle"), "deg", "degree", "degrees", "arcdegree")

UN_CEFACT_REGISTRY: Mapping[str, UnitSpec] = {
    spec.un_cefact: spec
    for spec in _EXACT_UNITS.values()
    if spec.un_cefact
}


def _normalize_unit_text(unit: str) -> str:
    s = unit.strip()
    s = s.replace("²", "2").replace("³", "3")
    s = re.sub(r"\s+", " ", s)
    # Collapse spaces around '/'
    s = re.sub(r"\s*/\s*", "/", s)
    # Normalize "deg C" / "degrees Celsius" etc.
    s = re.sub(r"^degrees?\s+celsius$", "°C", s, flags=re.IGNORECASE)
    s = re.sub(r"^degrees?\s+fahrenheit$", "°F", s, flags=re.IGNORECASE)
    s = re.sub(r"^deg\.?\s*c$", "°C", s, flags=re.IGNORECASE)
    s = re.sub(r"^deg\.?\s*f$", "°F", s, flags=re.IGNORECASE)
    return s


def _lookup_atom(atom: str) -> UnitSpec | None:
    if atom in _EXACT_UNITS:
        return _EXACT_UNITS[atom]
    low = atom.lower()
    if low in _LOWER_UNITS:
        return _LOWER_UNITS[low]
    if low.endswith(".") and low[:-1] in _LOWER_UNITS:
        return _LOWER_UNITS[low[:-1]]
    return None


def resolve_unit(unit: str) -> UnitSpec:
    """Resolve a unit symbol, prose label, compound rate, or UN/CEFACT Rec 20 code."""
    if not isinstance(unit, str) or not unit.strip():
        raise UnknownUnitError(f"Empty or non-string unit: {unit!r}")
    norm = _normalize_unit_text(unit)
    direct = _lookup_atom(norm)
    if direct is not None:
        return direct

    if "/" in norm:
        parts = [p.strip() for p in norm.split("/")]
        if any(not p for p in parts):
            raise UnknownUnitError(f"Malformed compound unit: {unit!r}")
        num = resolve_unit(parts[0])
        dim = num.dimension
        scale = num.scale
        kinds = [num.quantity_kind] if num.quantity_kind else []
        for den_raw in parts[1:]:
            den = resolve_unit(den_raw)
            dim = dim - den.dimension
            scale = scale / den.scale
            if den.quantity_kind:
                kinds.append(f"/{den.quantity_kind}")
        return UnitSpec(
            symbol="/".join(parts),
            un_cefact="",
            name=f"{num.name} per {' per '.join(parts[1:])}",
            dimension=dim,
            scale=scale,
            offset=Fraction(0),
            is_affine=False,
            quantity_kind="".join(kinds),
        )

    raise UnknownUnitError(f"Unknown unit: {unit!r}")


def unit_dimension(unit: str) -> DimensionVector:
    """Return the 9-component DimensionVector for ``unit``."""
    return resolve_unit(unit).dimension


def _units_compatible(u1: UnitSpec, u2: UnitSpec) -> bool:
    if u1.dimension != u2.dimension:
        return False
    if u1.quantity_kind != u2.quantity_kind:
        return False
    return True


def same_dimension_exact(u1: str, u2: str) -> bool:
    """True iff ``u1`` and ``u2`` belong to the exact same dimension and kind."""
    try:
        s1 = resolve_unit(u1)
        s2 = resolve_unit(u2)
    except UnknownUnitError:
        return False
    return _units_compatible(s1, s2)


# ---------------------------------------------------------------------------
# Affine (point) vs. Delta (interval) exact physics conversions
# ---------------------------------------------------------------------------


def convert_point_fraction(value: NumberLike, from_unit: str, to_unit: str) -> Fraction:
    """Convert an absolute reading (point) between compatible units as exact Fraction."""
    u_from = resolve_unit(from_unit)
    u_to = resolve_unit(to_unit)
    if not _units_compatible(u_from, u_to):
        raise DimensionMismatchError(
            f"Incompatible dimensions: {from_unit!r} ({u_from.dimension}"
            f"{f' [{u_from.quantity_kind}]' if u_from.quantity_kind else ''}) -> "
            f"{to_unit!r} ({u_to.dimension}"
            f"{f' [{u_to.quantity_kind}]' if u_to.quantity_kind else ''})"
        )
    v = to_fraction(value)
    base = v * u_from.scale + u_from.offset
    return (base - u_to.offset) / u_to.scale


def convert_point(value: NumberLike, from_unit: str, to_unit: str) -> Decimal:
    """Convert an absolute reading (point) in exact Fraction/Decimal arithmetic."""
    return _fraction_to_decimal(convert_point_fraction(value, from_unit, to_unit))


def convert_delta_fraction(delta: NumberLike, from_unit: str, to_unit: str) -> Fraction:
    """Convert a difference/step (delta) between compatible units, ignoring offsets."""
    u_from = resolve_unit(from_unit)
    u_to = resolve_unit(to_unit)
    if not _units_compatible(u_from, u_to):
        raise DimensionMismatchError(
            f"Incompatible dimensions for delta: {from_unit!r} ({u_from.dimension}) -> "
            f"{to_unit!r} ({u_to.dimension})"
        )
    v = to_fraction(delta)
    return v * u_from.scale / u_to.scale


def convert_delta(delta: NumberLike, from_unit: str, to_unit: str) -> Decimal:
    """Convert a difference/interval (delta) in exact Decimal without offset shift."""
    return _fraction_to_decimal(convert_delta_fraction(delta, from_unit, to_unit))


# ---------------------------------------------------------------------------
# International Locale Number Parser (NIST HB 44-2026 / EUR-Lex / CFR)
# ---------------------------------------------------------------------------

_SPACE_CHARS = "\u00a0\u202f\u2009 "
_RE_PLAIN = re.compile(r"^\d+(?:[eE][+-]?\d+)?$")
_RE_BARE_DOT = re.compile(r"^\.\d+(?:[eE][+-]?\d+)?$")
_RE_BARE_COMMA = re.compile(r"^,\d+(?:[eE][+-]?\d+)?$")
_RE_SPACE_GROUPED = re.compile(
    r"^[1-9]\d{0,2}(?: \d{3})+(?:([.,])\d+)?(?:[eE][+-]?\d+)?$"
)
_RE_COMMA_GROUPS_ONLY = re.compile(r"^[1-9]\d{0,2}(?:,\d{3})+$")
_RE_DOT_GROUPS_ONLY = re.compile(r"^[1-9]\d{0,2}(?:\.\d{3})+$")
_RE_US_MIXED = re.compile(r"^[1-9]\d{0,2}(?:,\d{3})+\.\d+(?:[eE][+-]?\d+)?$")
_RE_EU_MIXED = re.compile(r"^[1-9]\d{0,2}(?:\.\d{3})+,\d+(?:[eE][+-]?\d+)?$")
_RE_SINGLE_DOT_DEC = re.compile(r"^\d+\.\d+(?:[eE][+-]?\d+)?$")
_RE_SINGLE_COMMA_DEC = re.compile(r"^\d+,\d+(?:[eE][+-]?\d+)?$")


def parse_locale_decimal(
    raw: NumberLike,
    *,
    locale: str = "auto",
    strict: bool = False,
) -> Decimal:
    """Deterministically parse US, EU (EUR-Lex), and ISO/NIST numerals to Decimal.

    Rejects malformed group widths (e.g. ``1,00,50`` or ``12 34``) with
    ``LocaleParseError`` so silent 1000x misreads never occur.
    """
    if isinstance(raw, Decimal):
        return to_decimal(raw)
    if isinstance(raw, (int, Fraction)) and not isinstance(raw, bool):
        return to_decimal(raw)
    if not isinstance(raw, str):
        raise LocaleParseError(f"Expected string or numeric value, got {type(raw).__name__}")

    s = raw.strip()
    if not s:
        raise LocaleParseError("Empty numeric string")

    # Normalize Unicode minus sign and grouping whitespace
    s = s.replace("\u2212", "-").replace("\u2013", "-")
    for sp in ("\u00a0", "\u202f", "\u2009"):
        s = s.replace(sp, " ")

    sign = ""
    if s[0] in ("+", "-"):
        sign = "-" if s[0] == "-" else ""
        s = s[1:].strip()

    # Strip leading currency marker if present cleanly
    for cur in ("US$", "$", "€", "£", "¥"):
        if s.startswith(cur):
            s = s[len(cur):].strip()
            break

    if not s:
        raise LocaleParseError(f"No digits in numeric literal: {raw!r}")

    loc = locale.upper()
    is_eu = loc in ("EU", "EUR", "EUR-LEX", "DE", "FR")
    is_us = loc in ("US", "CFR", "EN-US")

    canonical: str | None = None

    if _RE_PLAIN.match(s):
        canonical = s
    elif _RE_BARE_DOT.match(s):
        if strict and is_eu:
            raise LocaleParseError(f"Dot decimal disallowed in strict EU locale: {raw!r}")
        canonical = "0" + s
    elif _RE_BARE_COMMA.match(s):
        if strict and is_us:
            raise LocaleParseError(f"Comma decimal disallowed in strict US locale: {raw!r}")
        canonical = "0." + s[1:]
    elif _RE_SPACE_GROUPED.match(s):
        canonical = s.replace(" ", "").replace(",", ".")
    elif _RE_US_MIXED.match(s):
        if strict and is_eu:
            raise LocaleParseError(f"US mixed grouping disallowed in strict EU locale: {raw!r}")
        canonical = s.replace(",", "")
    elif _RE_EU_MIXED.match(s):
        if strict and is_us:
            raise LocaleParseError(f"EU mixed grouping disallowed in strict US locale: {raw!r}")
        canonical = s.replace(".", "").replace(",", ".")
    elif _RE_COMMA_GROUPS_ONLY.match(s):
        # e.g. "1,000" or "1,234,567"
        if s.count(",") >= 2:
            if strict and is_eu:
                raise LocaleParseError(f"Comma thousands disallowed in strict EU locale: {raw!r}")
            canonical = s.replace(",", "")
        elif is_eu:
            # In EU, single "1,000" is 1.000 (thousandths precision)
            canonical = s.replace(",", ".")
        else:
            canonical = s.replace(",", "")
    elif _RE_DOT_GROUPS_ONLY.match(s):
        # e.g. "1.000" or "1.234.567"
        if s.count(".") >= 2:
            if strict and is_us:
                raise LocaleParseError(f"Dot thousands disallowed in strict US locale: {raw!r}")
            canonical = s.replace(".", "")
        elif is_eu:
            canonical = s.replace(".", "")
        else:
            # In US/CFR/auto, single "1.000" is 1.000 (exact 3-decimal value)
            canonical = s
    elif _RE_SINGLE_DOT_DEC.match(s):
        if strict and is_eu:
            raise LocaleParseError(f"Dot decimal disallowed in strict EU locale: {raw!r}")
        canonical = s
    elif _RE_SINGLE_COMMA_DEC.match(s):
        if strict and is_us:
            raise LocaleParseError(f"Comma decimal disallowed in strict US locale: {raw!r}")
        canonical = s.replace(",", ".")
    else:
        raise LocaleParseError(f"Malformed or ambiguous locale numeral: {raw!r}")

    try:
        dec = Decimal(f"{sign}{canonical}")
    except InvalidOperation as exc:
        raise LocaleParseError(f"Invalid decimal literal {raw!r}: {exc}") from exc
    if dec.is_nan() or dec.is_infinite():
        raise LocaleParseError(f"Non-finite decimal literal: {raw!r}")
    return dec


parse_locale_number = parse_locale_decimal

_ROUNDING_MODES: Mapping[str, str] = {
    ROUND_HALF_UP: ROUND_HALF_UP,
    "ROUND_HALF_UP": ROUND_HALF_UP,
    "HALF_UP": ROUND_HALF_UP,
    ROUND_HALF_EVEN: ROUND_HALF_EVEN,
    "ROUND_HALF_EVEN": ROUND_HALF_EVEN,
    "HALF_EVEN": ROUND_HALF_EVEN,
    "BANKERS": ROUND_HALF_EVEN,
    ROUND_FLOOR: ROUND_FLOOR,
    "ROUND_FLOOR": ROUND_FLOOR,
    "FLOOR": ROUND_FLOOR,
    ROUND_CEILING: ROUND_CEILING,
    "ROUND_CEILING": ROUND_CEILING,
    "CEILING": ROUND_CEILING,
    "CEIL": ROUND_CEILING,
}


def statutory_round(
    value: NumberLike,
    quantum: NumberLike = Decimal("1"),
    mode: str = ROUND_HALF_UP,
) -> Decimal:
    """Round ``value`` to multiples of ``quantum`` using a statutory rounding mode."""
    norm_mode = _ROUNDING_MODES.get(mode) or _ROUNDING_MODES.get(str(mode).upper())
    if not norm_mode:
        raise MetrologyError(f"Unsupported statutory rounding mode: {mode!r}")

    val_frac = to_fraction(value)
    step_frac = to_fraction(quantum)
    if step_frac <= 0:
        raise MetrologyError(f"Rounding quantum must be positive, got {quantum!r}")

    step_dec = to_decimal(quantum)
    ratio_frac = val_frac / step_frac
    # If exact integer multiple of step, skip division approximation
    if ratio_frac.denominator == 1:
        rounded_units = Decimal(ratio_frac.numerator)
    else:
        with localcontext() as ctx:
            ctx.prec = 50
            ratio_dec = Decimal(ratio_frac.numerator) / Decimal(ratio_frac.denominator)
        rounded_units = ratio_dec.quantize(Decimal("1"), rounding=norm_mode)
    return rounded_units * step_dec


# ---------------------------------------------------------------------------
# NIST HB 44-2026 Section 2.20 Accuracy Class & Verification Scale e Lookup
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NISTHB44ClassSpec:
    """NIST Handbook 44 (2026) Section 2.20 Table 3 accuracy class parameters."""

    accuracy_class: str
    min_e_g: Decimal
    min_n: int
    max_n: int | None
    high_threshold_e_g: Decimal | None = None
    high_min_n: int | None = None


_HB44_CLASSES: Mapping[str, NISTHB44ClassSpec] = {
    "I": NISTHB44ClassSpec("I", Decimal("0.001"), 50_000, None),
    "II": NISTHB44ClassSpec(
        "II",
        Decimal("0.001"),
        100,
        100_000,
        high_threshold_e_g=Decimal("0.1"),
        high_min_n=5_000,
    ),
    "III": NISTHB44ClassSpec(
        "III",
        Decimal("0.1"),
        100,
        10_000,
        high_threshold_e_g=Decimal("5"),
        high_min_n=500,
    ),
    "IIIL": NISTHB44ClassSpec("IIIL", Decimal("2000"), 2_000, 10_000),
    "IIII": NISTHB44ClassSpec("IIII", Decimal("5"), 100, 1_200),
}


def nist_hb44_class_spec(accuracy_class: str) -> NISTHB44ClassSpec:
    """Return NIST HB 44-2026 Table 3 parameters for an accuracy class."""
    key = re.sub(r"[\s\-_]+", "", str(accuracy_class).upper())
    if key not in _HB44_CLASSES:
        raise MetrologyError(f"Unknown NIST HB 44 accuracy class: {accuracy_class!r}")
    return _HB44_CLASSES[key]


def _snap_1_2_5(raw: Fraction) -> Fraction:
    """Return the smallest standard 1/2/5 * 10^k value >= raw."""
    if raw <= 0:
        raise MetrologyError("Verification scale interval must be positive")
    exp = 0
    cur = raw
    while cur < 1:
        cur *= 10
        exp -= 1
    while cur >= 10:
        cur /= 10
        exp += 1
    for mant in (1, 2, 5, 10):
        if cur <= mant:
            if mant == 10:
                return Fraction(10) ** (exp + 1)
            return Fraction(mant) * (Fraction(10) ** exp)
    return Fraction(10) ** (exp + 1)


def nist_hb44_verification_scale_e(
    accuracy_class: str,
    max_capacity: NumberLike | None = None,
    *,
    unit: str = "g",
    d: NumberLike | None = None,
    n_divisions: int | None = None,
) -> Decimal:
    """Lookup/compute NIST HB 44-2026 §2.20 verification scale interval ``e`` in ``unit``.

    - If ``max_capacity`` and ``d`` are both omitted, returns the class minimum ``e``.
    - If ``d`` (actual scale division) is supplied, validates/clamps against the class
      minimum ``e`` (and ``max_capacity / e`` bounds if ``max_capacity`` is supplied).
    - If ``max_capacity`` is supplied without ``d``, chooses the finest valid
      ``1/2/5 * 10^k`` verification scale ``e`` satisfying Table 3 bounds.
    """
    spec = nist_hb44_class_spec(accuracy_class)
    if not same_dimension_exact(unit, "g"):
        raise DimensionMismatchError(f"Mass unit required for NIST HB 44 lookup, got {unit!r}")

    min_e_unit_frac = convert_delta_fraction(spec.min_e_g, "g", unit)

    if d is not None:
        d_frac = to_fraction(d)
        if d_frac <= 0:
            raise MetrologyError(f"Scale division d must be positive, got {d!r}")
        e_frac = d_frac if d_frac >= min_e_unit_frac else _snap_1_2_5(min_e_unit_frac)
        if max_capacity is not None:
            cap_frac = to_fraction(max_capacity)
            n = cap_frac / e_frac
            if spec.max_n is not None and n > spec.max_n:
                raise MetrologyError(
                    f"Class {spec.accuracy_class} exceeds max n={spec.max_n} (got {float(n):.1f})"
                )
        return _fraction_to_decimal(e_frac)

    if max_capacity is None:
        return _fraction_to_decimal(min_e_unit_frac)

    cap_frac = to_fraction(max_capacity)
    if cap_frac <= 0:
        raise MetrologyError(f"max_capacity must be positive, got {max_capacity!r}")

    if n_divisions is not None:
        if n_divisions <= 0:
            raise MetrologyError(f"n_divisions must be positive, got {n_divisions!r}")
        raw_e = cap_frac / n_divisions
        e_frac = _snap_1_2_5(max(raw_e, min_e_unit_frac))
    elif spec.max_n is None:
        # Unbounded max_n (Class I): finest legal scale interval is min_e
        e_frac = _snap_1_2_5(min_e_unit_frac)
    else:
        raw_e = cap_frac / spec.max_n
        e_frac = _snap_1_2_5(max(raw_e, min_e_unit_frac))

    # Enforce Class II / III tiered min_n when e reaches high_threshold_e_g
    if spec.high_threshold_e_g is not None and spec.high_min_n is not None:
        e_g = convert_delta_fraction(e_frac, unit, "g")
        cap_g = convert_delta_fraction(cap_frac, unit, "g")
        req_n = spec.high_min_n if e_g >= to_fraction(spec.high_threshold_e_g) else spec.min_n
        if cap_g / e_g < req_n:
            raise MetrologyError(
                f"Capacity {max_capacity} {unit} yields fewer than min_n={req_n} "
                f"divisions at e={_fraction_to_decimal(e_frac)} {unit} for Class {spec.accuracy_class}"
            )
    else:
        n_actual = cap_frac / e_frac
        if n_actual < spec.min_n:
            raise MetrologyError(
                f"Capacity {max_capacity} {unit} yields fewer than min_n={spec.min_n} "
                f"divisions for Class {spec.accuracy_class}"
            )

    return _fraction_to_decimal(e_frac)


def nist_hb44_tolerance(
    accuracy_class: str,
    load: NumberLike,
    e: NumberLike,
    *,
    tolerance_type: str = "maintenance",
) -> Decimal:
    """Compute NIST HB 44-2026 §2.20 Table 6 tolerance in the same unit as ``load`` & ``e``."""
    spec = nist_hb44_class_spec(accuracy_class)
    ttype = tolerance_type.strip().lower()
    if ttype not in ("acceptance", "maintenance"):
        raise MetrologyError(f"tolerance_type must be 'acceptance' or 'maintenance', got {tolerance_type!r}")

    load_f = abs(to_fraction(load))
    e_f = to_fraction(e)
    if e_f <= 0:
        raise MetrologyError(f"Verification scale e must be positive, got {e!r}")

    m_in_e = load_f / e_f
    mult_2 = 1 if ttype == "acceptance" else 2

    if spec.accuracy_class == "I":
        if m_in_e <= 50_000:
            factor = Fraction(1, 2) * mult_2
        elif m_in_e <= 200_000:
            factor = Fraction(1) * mult_2
        else:
            factor = Fraction(3, 2) * mult_2
    elif spec.accuracy_class == "II":
        if m_in_e <= 5_000:
            factor = Fraction(1, 2) * mult_2
        elif m_in_e <= 20_000:
            factor = Fraction(1) * mult_2
        else:
            factor = Fraction(3, 2) * mult_2
    elif spec.accuracy_class == "III":
        if m_in_e <= 500:
            factor = Fraction(1, 2) * mult_2
        elif m_in_e <= 2_000:
            factor = Fraction(1) * mult_2
        elif m_in_e <= 4_000:
            factor = Fraction(3, 2) * mult_2
        else:
            factor = Fraction(5, 2) * mult_2
    elif spec.accuracy_class == "IIIL":
        if m_in_e <= 500:
            factor = Fraction(1, 2) * mult_2
        elif m_in_e <= 2_000:
            factor = Fraction(1) * mult_2
        elif m_in_e <= 4_000:
            factor = Fraction(3, 2) * mult_2
        else:
            # Add 0.5e (acceptance) / 1.0e (maintenance) per 1,000e (or fraction) over 4,000e
            excess = m_in_e - 4_000
            steps = (excess.numerator + (1000 * excess.denominator) - 1) // (1000 * excess.denominator)
            factor = (Fraction(3, 2) + Fraction(steps, 2)) * mult_2
    else:  # IIII
        if m_in_e <= 50:
            factor = Fraction(1, 2) * mult_2
        elif m_in_e <= 200:
            factor = Fraction(1) * mult_2
        elif m_in_e <= 400:
            factor = Fraction(3, 2) * mult_2
        else:
            factor = Fraction(5, 2) * mult_2

    return _fraction_to_decimal(factor * e_f)


# ---------------------------------------------------------------------------
# Piecewise Statutory Combinators & Federal Calendar Math
# ---------------------------------------------------------------------------


def whichever_is_less(a: NumberLike | "Quantity", b: NumberLike | "Quantity") -> Decimal | "Quantity":
    """Return the exact lesser of ``a`` and ``b`` (or compatible ``Quantity`` objects)."""
    if isinstance(a, Quantity) and isinstance(b, Quantity):
        if a.unit and b.unit:
            b_in_a = convert_point_fraction(b.value, b.unit, a.unit)
            return a if to_fraction(a.value) <= b_in_a else b
        if not a.unit and not b.unit:
            return a if a.value <= b.value else b
        raise DimensionMismatchError(f"Cannot compare unit-bearing {a.unit!r} with {b.unit!r}")
    da, db = to_decimal(a), to_decimal(b)  # type: ignore[arg-type]
    return da if da <= db else db


def whichever_is_greater(a: NumberLike | "Quantity", b: NumberLike | "Quantity") -> Decimal | "Quantity":
    """Return the exact greater of ``a`` and ``b`` (or compatible ``Quantity`` objects)."""
    if isinstance(a, Quantity) and isinstance(b, Quantity):
        if a.unit and b.unit:
            b_in_a = convert_point_fraction(b.value, b.unit, a.unit)
            return a if to_fraction(a.value) >= b_in_a else b
        if not a.unit and not b.unit:
            return a if a.value >= b.value else b
        raise DimensionMismatchError(f"Cannot compare unit-bearing {a.unit!r} with {b.unit!r}")
    da, db = to_decimal(a), to_decimal(b)  # type: ignore[arg-type]
    return da if da >= db else db


def compound_tariff(
    quantity: NumberLike,
    unit_rate: NumberLike,
    custom_value: NumberLike,
    ad_valorem_pct: NumberLike,
) -> Decimal:
    """Compute exact HTSUS compound duty: (quantity * unit_rate) + (custom_value * ad_valorem_pct / 100)."""
    q = to_decimal(quantity)
    r = to_decimal(unit_rate)
    v = to_decimal(custom_value)
    pct = to_decimal(ad_valorem_pct)
    specific = q * r
    ad_valorem = (v * pct) / Decimal("100")
    return specific + ad_valorem


def _coerce_date(value: date | datetime | str) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        return date.fromisoformat(value.strip())
    raise TypeError(f"Expected date, datetime, or ISO YYYY-MM-DD string, got {type(value).__name__}")


def _observed_fixed(year: int, month: int, day: int) -> date:
    d = date(year, month, day)
    wd = d.weekday()
    if wd == 5:  # Saturday -> observed Friday
        return d - timedelta(days=1)
    if wd == 6:  # Sunday -> observed Monday
        return d + timedelta(days=1)
    return d


def _nth_weekday(year: int, month: int, weekday: int, n: int) -> date:
    first = date(year, month, 1)
    offset = (weekday - first.weekday()) % 7
    return first + timedelta(days=offset + 7 * (n - 1))


def _last_weekday(year: int, month: int, weekday: int) -> date:
    if month == 12:
        last = date(year, 12, 31)
    else:
        last = date(year, month + 1, 1) - timedelta(days=1)
    offset = (last.weekday() - weekday) % 7
    return last - timedelta(days=offset)


def us_federal_holidays(year: int) -> frozenset[date]:
    """Return observed US Federal Holidays under 5 U.S.C. § 6103(a) for ``year``."""
    holidays = {
        _observed_fixed(year, 1, 1),          # New Year's Day
        _nth_weekday(year, 1, 0, 3),          # Martin Luther King Jr. Day (3rd Mon Jan)
        _nth_weekday(year, 2, 0, 3),          # Washington's Birthday (3rd Mon Feb)
        _last_weekday(year, 5, 0),            # Memorial Day (last Mon May)
        _observed_fixed(year, 7, 4),          # Independence Day
        _nth_weekday(year, 9, 0, 1),          # Labor Day (1st Mon Sep)
        _nth_weekday(year, 10, 0, 2),         # Columbus Day (2nd Mon Oct)
        _observed_fixed(year, 11, 11),        # Veterans Day
        _nth_weekday(year, 11, 3, 4),         # Thanksgiving Day (4th Thu Nov)
        _observed_fixed(year, 12, 25),        # Christmas Day
    }
    if year >= 2021:
        holidays.add(_observed_fixed(year, 6, 19))  # Juneteenth National Independence Day
    # Next year's Jan 1 falling on Saturday is observed on Dec 31 of ``year``.
    if date(year + 1, 1, 1).weekday() == 5:
        holidays.add(date(year, 12, 31))
    return frozenset(holidays)


def is_business_day(
    d: date | datetime | str,
    holidays: Iterable[date] | None = None,
) -> bool:
    """True iff ``d`` is Monday-Friday and not an observed US federal holiday."""
    dt = _coerce_date(d)
    if dt.weekday() >= 5:
        return False
    hols = frozenset(holidays) if holidays is not None else us_federal_holidays(dt.year)
    return dt not in hols


def calendar_days_add(start_date: date | datetime | str, n: int) -> date:
    """Add ``n`` calendar days to ``start_date``."""
    return _coerce_date(start_date) + timedelta(days=int(n))


def business_days_add(
    start_date: date | datetime | str,
    n: int,
    holidays: Iterable[date] | None = None,
) -> date:
    """Add ``n`` US federal business days, skipping weekends and 5 U.S.C. § 6103 holidays."""
    cur = _coerce_date(start_date)
    steps = int(n)
    if steps == 0:
        return cur
    direction = 1 if steps > 0 else -1
    remaining = abs(steps)
    custom_hols = frozenset(holidays) if holidays is not None else None
    year_cache: dict[int, frozenset[date]] = {}

    while remaining > 0:
        cur += timedelta(days=direction)
        if cur.weekday() >= 5:
            continue
        if custom_hols is not None:
            if cur in custom_hols:
                continue
        else:
            hols = year_cache.get(cur.year)
            if hols is None:
                hols = us_federal_holidays(cur.year)
                year_cache[cur.year] = hols
            if cur in hols:
                continue
        remaining -= 1
    return cur


# ---------------------------------------------------------------------------
# Quantities, Exact Comparison, and Unit-Scale Anti-Spoofing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Quantity:
    """Exact Decimal quantity paired with an optional registered unit."""

    value: Decimal
    unit: str | None = None
    original_text: str | None = None

    @property
    def dimension(self) -> DimensionVector:
        return unit_dimension(self.unit) if self.unit else DIM_NONE

    def to(self, target_unit: str) -> "Quantity":
        if not self.unit:
            raise DimensionMismatchError(f"Dimensionless quantity cannot convert to {target_unit!r}")
        return Quantity(value=convert_point(self.value, self.unit, target_unit), unit=target_unit)

    def to_delta(self, target_unit: str) -> "Quantity":
        if not self.unit:
            raise DimensionMismatchError(f"Dimensionless quantity cannot convert to {target_unit!r}")
        return Quantity(value=convert_delta(self.value, self.unit, target_unit), unit=target_unit)


@dataclass(frozen=True)
class ExactComparisonResult:
    """Deterministic verdict from ``compare_quantities_exact``."""

    matched: bool
    expected_value: Decimal
    got_in_expected_unit: Decimal | None
    diff: Decimal | None
    tolerance: Decimal
    dimension_mismatch: bool
    reason: str


@dataclass(frozen=True)
class SpoofDetectionResult:
    """Result from ``detect_unit_scale_spoof`` for adjudicators and firewalls."""

    spoofed: bool
    reason: str
    expected_value: Decimal | None
    expected_unit: str | None
    got_value: Decimal | None
    got_unit: str | None
    ratio: Decimal | None = None


_QTY_NUM_UNIT_RE = re.compile(
    r"^\s*([+\-\u2212]?\s*(?:US\$|[$€£¥])?\s*"
    r"(?:\d[\d,.\u00a0\u202f ]*\d|\.\d+|,\d+|\d)"
    r"(?:[eE][+-]?\d+)?)"
    r"(?:\s*(.+?))?\s*$"
)
_LEADING_CURRENCY_RE = re.compile(r"^\s*[+\-\u2212]?\s*(US\$|[$€£¥])\s*(.+)$")


def extract_quantity(text: str, *, locale: str = "auto") -> Quantity:
    """Extract a ``Quantity(Decimal, unit)`` from a regulatory value string."""
    if not isinstance(text, str) or not text.strip():
        raise LocaleParseError(f"Cannot extract quantity from empty input: {text!r}")

    cur_unit: str | None = None
    m_cur = _LEADING_CURRENCY_RE.match(text)
    if m_cur:
        cur_sym = m_cur.group(1)
        cur_unit = {"$": "USD", "US$": "USD", "€": "EUR", "£": "GBP", "¥": "JPY"}.get(cur_sym)

    m = _QTY_NUM_UNIT_RE.match(text)
    if not m:
        raise LocaleParseError(f"Could not parse quantity from: {text!r}")

    num_str = m.group(1)
    unit_raw = (m.group(2) or "").strip()
    val = parse_locale_decimal(num_str, locale=locale)

    unit: str | None = None
    if unit_raw:
        # Clean trailing punctuation
        cleaned_u = unit_raw.rstrip(".,;:!?)")
        if cleaned_u:
            try:
                spec = resolve_unit(cleaned_u)
                unit = cleaned_u if cleaned_u in _EXACT_UNITS else spec.symbol
            except UnknownUnitError:
                unit = cleaned_u
    elif cur_unit:
        unit = cur_unit

    return Quantity(value=val, unit=unit, original_text=text)


def compare_quantities_exact(
    expected_val: NumberLike,
    expected_unit: str | None,
    got_val: NumberLike,
    got_unit: str | None,
    tolerance: NumberLike = Decimal("0"),
    *,
    is_delta: bool = False,
    locale: str = "auto",
    raise_on_mismatch: bool = False,
) -> ExactComparisonResult:
    """Compare two values (and optional units) using exact Fraction/Decimal math."""
    exp_dec = parse_locale_decimal(expected_val, locale=locale) if isinstance(expected_val, str) else to_decimal(expected_val)
    got_dec = parse_locale_decimal(got_val, locale=locale) if isinstance(got_val, str) else to_decimal(got_val)
    tol_dec = to_decimal(tolerance)
    if tol_dec < 0:
        raise MetrologyError(f"Tolerance must be non-negative, got {tolerance!r}")

    exp_frac = Fraction(exp_dec)
    tol_frac = Fraction(tol_dec)

    if expected_unit and got_unit:
        try:
            if is_delta:
                got_converted_frac = convert_delta_fraction(got_dec, got_unit, expected_unit)
            else:
                got_converted_frac = convert_point_fraction(got_dec, got_unit, expected_unit)
        except DimensionMismatchError as exc:
            if raise_on_mismatch:
                raise
            return ExactComparisonResult(
                matched=False,
                expected_value=exp_dec,
                got_in_expected_unit=None,
                diff=None,
                tolerance=tol_dec,
                dimension_mismatch=True,
                reason=str(exc),
            )
        except UnknownUnitError as exc:
            if expected_unit.strip().lower() != got_unit.strip().lower():
                return ExactComparisonResult(
                    matched=False,
                    expected_value=exp_dec,
                    got_in_expected_unit=None,
                    diff=None,
                    tolerance=tol_dec,
                    dimension_mismatch=True,
                    reason=str(exc),
                )
            got_converted_frac = Fraction(got_dec)
    elif expected_unit is None and got_unit is None:
        got_converted_frac = Fraction(got_dec)
    else:
        msg = f"Dimension mismatch: expected unit={expected_unit!r}, got unit={got_unit!r}"
        if raise_on_mismatch:
            raise DimensionMismatchError(msg)
        return ExactComparisonResult(
            matched=False,
            expected_value=exp_dec,
            got_in_expected_unit=None,
            diff=None,
            tolerance=tol_dec,
            dimension_mismatch=True,
            reason=msg,
        )

    diff_frac = abs(exp_frac - got_converted_frac)
    matched = diff_frac <= tol_frac
    got_conv_dec = _fraction_to_decimal(got_converted_frac)
    diff_dec = _fraction_to_decimal(diff_frac)
    reason = "exact match" if matched else f"delta {diff_dec} exceeds tolerance {tol_dec}"
    return ExactComparisonResult(
        matched=matched,
        expected_value=exp_dec,
        got_in_expected_unit=got_conv_dec,
        diff=diff_dec,
        tolerance=tol_dec,
        dimension_mismatch=False,
        reason=reason,
    )


def detect_unit_scale_spoof(
    expected_text: str,
    got_text: str,
    *,
    locale: str = "auto",
) -> SpoofDetectionResult:
    """Detect SI-prefix, tonnage, gallon, ounce, affine, or locale 1000x unit spoofing."""
    try:
        q_exp = extract_quantity(expected_text, locale=locale)
    except LocaleParseError as exc:
        return SpoofDetectionResult(
            spoofed=True,
            reason=f"expected_locale_parse_error: {exc}",
            expected_value=None,
            expected_unit=None,
            got_value=None,
            got_unit=None,
        )

    try:
        q_got = extract_quantity(got_text, locale=locale)
    except LocaleParseError as exc:
        return SpoofDetectionResult(
            spoofed=True,
            reason=f"locale_grouping_spoof: {exc}",
            expected_value=q_exp.value,
            expected_unit=q_exp.unit,
            got_value=None,
            got_unit=None,
        )

    # Dimensionless vs unit-bearing
    if bool(q_exp.unit) != bool(q_got.unit):
        return SpoofDetectionResult(
            spoofed=True,
            reason=f"unit_presence_mismatch: expected {q_exp.unit!r} vs got {q_got.unit!r}",
            expected_value=q_exp.value,
            expected_unit=q_exp.unit,
            got_value=q_got.value,
            got_unit=q_got.unit,
        )

    if q_exp.unit is None and q_got.unit is None:
        if q_exp.value == q_got.value:
            return SpoofDetectionResult(
                spoofed=False,
                reason="ok",
                expected_value=q_exp.value,
                expected_unit=None,
                got_value=q_got.value,
                got_unit=None,
                ratio=Decimal("1"),
            )
        ratio = _fraction_to_decimal(Fraction(q_got.value) / Fraction(q_exp.value)) if q_exp.value != 0 else None
        return SpoofDetectionResult(
            spoofed=True,
            reason=f"numeric_mismatch: {q_exp.value} vs {q_got.value}",
            expected_value=q_exp.value,
            expected_unit=None,
            got_value=q_got.value,
            got_unit=None,
            ratio=ratio,
        )

    assert q_exp.unit is not None and q_got.unit is not None
    cmp_res = compare_quantities_exact(
        q_exp.value,
        q_exp.unit,
        q_got.value,
        q_got.unit,
        tolerance=Decimal("0"),
        locale=locale,
    )
    if cmp_res.dimension_mismatch:
        return SpoofDetectionResult(
            spoofed=True,
            reason=f"dimension_mismatch: {cmp_res.reason}",
            expected_value=q_exp.value,
            expected_unit=q_exp.unit,
            got_value=q_got.value,
            got_unit=q_got.unit,
        )

    if cmp_res.matched:
        return SpoofDetectionResult(
            spoofed=False,
            reason="exact_metrology_equivalence",
            expected_value=q_exp.value,
            expected_unit=q_exp.unit,
            got_value=q_got.value,
            got_unit=q_got.unit,
            ratio=Decimal("1"),
        )

    ratio_val: Decimal | None = None
    if cmp_res.got_in_expected_unit is not None and q_exp.value != 0:
        ratio_val = _fraction_to_decimal(
            Fraction(cmp_res.got_in_expected_unit) / Fraction(q_exp.value)
        )
    same_raw_num = q_exp.value == q_got.value
    tag = "unit_scale_spoof" if same_raw_num else "quantity_scale_mismatch"
    return SpoofDetectionResult(
        spoofed=True,
        reason=(
            f"{tag}: {q_exp.value} {q_exp.unit} != {q_got.value} {q_got.unit} "
            f"(converted={cmp_res.got_in_expected_unit} {q_exp.unit})"
        ),
        expected_value=q_exp.value,
        expected_unit=q_exp.unit,
        got_value=q_got.value,
        got_unit=q_got.unit,
        ratio=ratio_val,
    )
