#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SpanProof Contributors
# SPDX-License-Identifier: MIT
"""Torture test suite for regeval.metrology (exact-Decimal metrology & statutory math)."""
from __future__ import annotations

import os
import sys
from datetime import date
from decimal import (
    ROUND_CEILING,
    ROUND_FLOOR,
    ROUND_HALF_EVEN,
    ROUND_HALF_UP,
    Decimal,
)

import pytest

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from regeval.metrology import (  # noqa: E402
    DIMENSION_NAMES,
    UN_CEFACT_REGISTRY,
    DimensionMismatchError,
    DimensionVector,
    LocaleParseError,
    Quantity,
    UnknownUnitError,
    business_days_add,
    calendar_days_add,
    compare_quantities_exact,
    compound_tariff,
    convert_delta,
    convert_point,
    detect_unit_scale_spoof,
    extract_quantity,
    nist_hb44_class_spec,
    nist_hb44_tolerance,
    nist_hb44_verification_scale_e,
    parse_locale_decimal,
    resolve_unit,
    same_dimension_exact,
    statutory_round,
    unit_dimension,
    us_federal_holidays,
    whichever_is_greater,
    whichever_is_less,
)


# ---------------------------------------------------------------------------
# 1. Dimensional Vectors & UN/CEFACT Rec 20 Unit Disambiguation
# ---------------------------------------------------------------------------


def test_dimensional_vector_basis_and_un_cefact_codes() -> None:
    assert DIMENSION_NAMES == (
        "Mass", "Length", "Time", "Temperature", "Pressure",
        "Volume", "Radioactivity", "Dose", "Currency",
    )
    assert unit_dimension("STN") == DimensionVector(mass=1)
    assert unit_dimension("MTR") == DimensionVector(length=1)
    assert unit_dimension("SEC") == DimensionVector(time=1)
    assert unit_dimension("CEL") == DimensionVector(temperature=1)
    assert unit_dimension("KPA") == DimensionVector(pressure=1)
    assert unit_dimension("GLL") == DimensionVector(volume=1)
    assert unit_dimension("BQL") == DimensionVector(radioactivity=1)
    assert unit_dimension("SIE") == DimensionVector(dose=1)
    assert unit_dimension("USD") == DimensionVector(currency=1)
    assert unit_dimension("mg/L") == DimensionVector(mass=1, volume=-1)
    for code in ("STN", "TNE", "LTN", "GLL", "GLI", "BLL", "ONZ", "APZ", "OZA", "BQL", "CUR", "REM", "RAD"):
        assert code in UN_CEFACT_REGISTRY


def test_tonnage_disambiguation_exact() -> None:
    # US short ton = 2000 lb; metric tonne = 1000 kg; long ton = 2240 lb
    assert convert_point(1, "STN", "lb") == Decimal("2000")
    assert convert_point(1, "short ton", "lb") == Decimal("2000")
    assert convert_point(1, "TNE", "kg") == Decimal("1000")
    assert convert_point(1, "metric tonne", "kg") == Decimal("1000")
    assert convert_point(1, "LTN", "lb") == Decimal("2240")
    assert convert_point(1, "long ton", "lb") == Decimal("2240")
    assert convert_point(1, "STN", "kg") == Decimal("907.18474")
    assert convert_point(1, "LTN", "kg") == Decimal("1016.0469088")
    assert convert_point(1, "TNE", "STN") > Decimal("1.1023")
    assert convert_point(1, "LTN", "TNE") == Decimal("1.0160469088")


def test_gallon_and_barrel_disambiguation_exact() -> None:
    # US liquid gallon = 231 in^3 = 3.785411784 L; Imperial = 4.54609 L; Barrel = 42 US gal
    assert convert_point(1, "GLL", "in3") == Decimal("231")
    assert convert_point(1, "GLL", "L") == Decimal("3.785411784")
    assert convert_point(1, "US liquid gallon", "mL") == Decimal("3785.411784")
    assert convert_point(1, "GLI", "L") == Decimal("4.54609")
    assert convert_point(1, "Imperial gallon", "L") == Decimal("4.54609")
    assert convert_point(1, "BLL", "GLL") == Decimal("42")
    assert convert_point(1, "BLL", "L") == Decimal("158.987294928")
    assert convert_point(1, "GLI", "GLL") > Decimal("1.2009")


def test_ounce_disambiguation_exact() -> None:
    # Avoirdupois oz = 1/16 lb; troy oz = 31.1034768 g; US fl oz = 1/128 US gal
    assert convert_point(16, "ONZ", "lb") == Decimal("1")
    assert convert_point(1, "ONZ", "g") == Decimal("28.349523125")
    assert convert_point(1, "APZ", "g") == Decimal("31.1034768")
    assert convert_point(1, "troy oz", "g") == Decimal("31.1034768")
    assert convert_point(128, "OZA", "GLL") == Decimal("1")
    assert convert_point(1, "fl oz", "mL") == Decimal("29.5735295625")
    assert convert_point(175, "APZ", "ONZ") == Decimal("192")  # exact 192/175 ratio
    with pytest.raises(DimensionMismatchError):
        convert_point(1, "ONZ", "OZA")


def test_radiobiology_10_cfr_exact() -> None:
    assert convert_point(1, "Ci", "Bq") == Decimal("37000000000")
    assert convert_point(1, "Ci", "GBq") == Decimal("37")
    assert convert_point("3.7e10", "Bq", "Ci") == Decimal("1")
    assert convert_point(1, "pCi", "Bq") == Decimal("0.037")
    assert convert_point(1, "mCi", "MBq") == Decimal("37")
    assert convert_point(100, "rem", "Sv") == Decimal("1")
    assert convert_point("0.01", "Sv", "rem") == Decimal("1")
    assert convert_point(1, "rem", "mSv") == Decimal("10")
    assert convert_point(100, "rad", "Gy") == Decimal("1")
    assert convert_point("0.01", "Gy", "rad") == Decimal("1")
    assert convert_point(1, "rad", "mGy") == Decimal("10")


def test_si_prefixes_pico_to_tera_and_case_sensitivity() -> None:
    assert convert_point(1, "Tg", "pg") == Decimal("1e24")
    assert convert_point(1, "TBq", "pBq") == Decimal("1e24")
    assert convert_point(1, "Tm", "pm") == Decimal("1e24")
    assert convert_point(1, "TCi", "pCi") == Decimal("1e24")
    # Case-sensitive SI prefixes: mBq (milli) != MBq (mega)
    assert convert_point(1, "MBq", "mBq") == Decimal("1000000000")
    assert convert_point(1, "Mg", "mg") == Decimal("1000000000")
    assert convert_point(1, "daL", "dL") == Decimal("100")
    assert convert_point(1, "hg", "cg") == Decimal("10000")
    assert convert_point(1, "mcg", "ng") == Decimal("1000")
    assert convert_point(1, "mg/L", "g/m3") == Decimal("1")


def test_dimension_mismatch_errors() -> None:
    with pytest.raises(DimensionMismatchError):
        convert_point(1, "kg", "m")
    with pytest.raises(DimensionMismatchError):
        convert_point(1, "STN", "GLL")
    with pytest.raises(DimensionMismatchError):
        convert_point(1, "°C", "psia")
    with pytest.raises(DimensionMismatchError):
        convert_point(1, "rem", "Gy")
    with pytest.raises(DimensionMismatchError):
        convert_point(1, "rad", "Sv")
    with pytest.raises(DimensionMismatchError):
        convert_point(1, "Hz", "Bq")
    with pytest.raises(DimensionMismatchError):
        convert_point(1, "USD", "EUR")
    with pytest.raises(UnknownUnitError):
        resolve_unit("furlong_unknown")
    assert same_dimension_exact("STN", "TNE") is True
    assert same_dimension_exact("rem", "Gy") is False


# ---------------------------------------------------------------------------
# 2. Affine vs. Delta Physics
# ---------------------------------------------------------------------------


def test_affine_point_conversions_exact() -> None:
    assert convert_point(60, "°C", "°F") == Decimal("140")
    assert convert_point(140, "°F", "°C") == Decimal("60")
    assert convert_point(0, "°C", "K") == Decimal("273.15")
    assert convert_point("273.15", "K", "°C") == Decimal("0")
    assert convert_point(-40, "°C", "°F") == Decimal("-40")
    assert convert_point(0, "psig", "psia") == Decimal("14.6959488")
    assert convert_point("14.6959488", "psia", "psig") == Decimal("0")
    assert convert_point("14.6959488", "psia", "kPa") == Decimal("101.325")
    assert convert_point("14.6959488", "psia", "bar") == Decimal("1.01325")
    assert convert_point("101.325", "kPa", "psig") == Decimal("0")
    assert convert_point("1.01325", "bar", "psia") == Decimal("14.6959488")


def test_delta_interval_conversions_ignore_offsets() -> None:
    assert convert_delta(5, "°C", "°F") == Decimal("9")
    assert convert_delta(-5, "°C", "°F") == Decimal("-9")
    assert convert_delta(9, "°F", "°C") == Decimal("5")
    assert convert_delta(5, "°C", "K") == Decimal("5")
    assert convert_delta(5, "psig", "psia") == Decimal("5")
    assert convert_delta(5, "psig", "psi") == Decimal("5")
    assert convert_delta(5, "psia", "psi") == Decimal("5")
    assert convert_delta("14.6959488", "psig", "kPa") == Decimal("101.325")


# ---------------------------------------------------------------------------
# 3. International Locale Number Parser, Rounding & NIST HB 44-2026
# ---------------------------------------------------------------------------


def test_locale_number_parser_us_eu_iso_and_failures() -> None:
    # US
    assert parse_locale_decimal("1,000.50") == Decimal("1000.50")
    assert parse_locale_decimal("$1,234,567.89") == Decimal("1234567.89")
    assert parse_locale_decimal(".01") == Decimal("0.01")
    assert parse_locale_decimal("−50") == Decimal("-50")
    assert parse_locale_decimal("1,000") == Decimal("1000")
    assert parse_locale_decimal("1.000") == Decimal("1.000")
    # EU / EUR-Lex
    assert parse_locale_decimal("1.000,50") == Decimal("1000.50")
    assert parse_locale_decimal("1.234.567,89") == Decimal("1234567.89")
    assert parse_locale_decimal("1.234.567") == Decimal("1234567")
    assert parse_locale_decimal("0,500") == Decimal("0.500")
    assert parse_locale_decimal("1,000", locale="EU") == Decimal("1.000")
    assert parse_locale_decimal("1.000", locale="EU") == Decimal("1000")
    # ISO / NIST space-grouped
    assert parse_locale_decimal("1 000,50") == Decimal("1000.50")
    assert parse_locale_decimal("1 000.50") == Decimal("1000.50")
    assert parse_locale_decimal("1\u00a0000,50") == Decimal("1000.50")
    assert parse_locale_decimal("1\u202f000.50") == Decimal("1000.50")
    assert parse_locale_decimal("1 000 000") == Decimal("1000000")
    # Reject malformed groupings (no silent 1000x misreads)
    for bad in ("1,00,50", "1,000,50", "12 34", "1.000.50", "0 500", ""):
        with pytest.raises(LocaleParseError):
            parse_locale_decimal(bad)


def test_statutory_rounding_modes_and_nist_hb44() -> None:
    assert statutory_round("1.025", "0.01", ROUND_HALF_UP) == Decimal("1.03")
    assert statutory_round("1.025", "0.01", ROUND_HALF_EVEN) == Decimal("1.02")
    assert statutory_round("1.035", "0.01", ROUND_HALF_EVEN) == Decimal("1.04")
    assert statutory_round("1.09", "0.05", ROUND_FLOOR) == Decimal("1.05")
    assert statutory_round("1.01", "0.05", ROUND_CEILING) == Decimal("1.05")
    assert statutory_round("-1.5", "1", ROUND_FLOOR) == Decimal("-2")
    assert statutory_round("-1.5", "1", ROUND_CEILING) == Decimal("-1")

    # NIST HB 44-2026 Table 3 & Table 6
    assert nist_hb44_class_spec("III").max_n == 10_000
    assert nist_hb44_verification_scale_e("I", 200, unit="g") == Decimal("0.001")
    assert nist_hb44_verification_scale_e("II", 5000, unit="g") == Decimal("0.05")
    assert nist_hb44_verification_scale_e("III", 15000, unit="g") == Decimal("2")
    assert nist_hb44_verification_scale_e("III", 50, unit="kg") == Decimal("0.005")
    assert nist_hb44_verification_scale_e("IIIL", 50000, unit="kg") == Decimal("5")
    assert nist_hb44_verification_scale_e("IIII", 1200, unit="kg") == Decimal("1")
    assert nist_hb44_tolerance("III", 500, 1, tolerance_type="acceptance") == Decimal("0.5")
    assert nist_hb44_tolerance("III", 500, 1, tolerance_type="maintenance") == Decimal("1")
    assert nist_hb44_tolerance("III", 1500, 1, tolerance_type="maintenance") == Decimal("2")
    assert nist_hb44_tolerance("III", 3000, 1, tolerance_type="acceptance") == Decimal("1.5")
    assert nist_hb44_tolerance("IIIL", 5000, 1, tolerance_type="maintenance") == Decimal("4")


# ---------------------------------------------------------------------------
# 4. Piecewise Statutory Combinators & Federal Calendar Math
# ---------------------------------------------------------------------------


def test_piecewise_statutory_combinators() -> None:
    assert whichever_is_less("0.3", "0.3001") == Decimal("0.3")
    assert whichever_is_greater("0.3", "0.2999") == Decimal("0.3")
    q_ton = Quantity(Decimal("1"), "STN")
    q_tonne = Quantity(Decimal("1"), "TNE")
    assert whichever_is_less(q_ton, q_tonne) == q_ton
    assert whichever_is_greater(q_ton, q_tonne) == q_tonne
    assert compound_tariff(100, "2.50", "1000", "5") == Decimal("300.00")
    assert compound_tariff("0.1", "1", "0.2", "100") == Decimal("0.3")


def test_calendar_and_us_federal_business_days() -> None:
    assert calendar_days_add("2026-11-24", 10) == date(2026, 12, 4)
    # 2026-11-25 (Wed) + 1 business day skips Thanksgiving (2026-11-26) -> Fri 2026-11-27
    assert business_days_add("2026-11-25", 1) == date(2026, 11, 27)
    # 2026-11-25 (Wed) + 2 business days skips Thu Thanksgiving, Sat, Sun -> Mon 2026-11-30
    assert business_days_add("2026-11-25", 2) == date(2026, 11, 30)
    # 2026-07-04 is Saturday -> observed Friday 2026-07-03
    hols_2026 = us_federal_holidays(2026)
    assert date(2026, 7, 3) in hols_2026
    assert business_days_add("2026-07-02", 1) == date(2026, 7, 6)
    # 2027: Jan 1, 2028 is Saturday -> observed Dec 31, 2027
    assert date(2027, 12, 31) in us_federal_holidays(2027)
    assert business_days_add("2027-12-30", 1) == date(2028, 1, 3)
    # Negative business days
    assert business_days_add("2026-11-30", -2) == date(2026, 11, 25)


# ---------------------------------------------------------------------------
# 5. Anti-Spoofing & Zero IEEE-754 Float Drift
# ---------------------------------------------------------------------------


def test_exact_comparison_and_anti_spoofing() -> None:
    # IEEE-754 drift immunity: 0.1 + 0.2 == 0.3 with ZERO tolerance
    exact_sum = Decimal("0.1") + Decimal("0.2")
    assert exact_sum == Decimal("0.3")
    res = compare_quantities_exact(Decimal("0.3"), "kg", exact_sum * 1000, "g", tolerance=0)
    assert res.matched is True and res.diff == Decimal("0")

    # Cross-unit exact equivalences not flagged as spoofs
    assert detect_unit_scale_spoof("0.5 kg", "500 g").spoofed is False
    assert detect_unit_scale_spoof("60 °C", "140 °F").spoofed is False
    assert detect_unit_scale_spoof("14.6959488 psia", "101.325 kPa").spoofed is False
    assert detect_unit_scale_spoof("1 Ci", "37 GBq").spoofed is False
    assert detect_unit_scale_spoof("100 rem", "1 Sv").spoofed is False
    assert detect_unit_scale_spoof("1,000.50 kg", "1.000,50 kg").spoofed is False
    assert detect_unit_scale_spoof("1 000,50 L", "1,000.50 L").spoofed is False

    # Unit-scale & ambiguity spoofs MUST be caught
    assert detect_unit_scale_spoof("8,200 kg", "8200 g").spoofed is True
    assert detect_unit_scale_spoof("1 STN", "1 TNE").spoofed is True
    assert detect_unit_scale_spoof("1 GLL", "1 GLI").spoofed is True
    assert detect_unit_scale_spoof("1 ONZ", "1 OZA").spoofed is True
    assert detect_unit_scale_spoof("1 APZ", "1 ONZ").spoofed is True
    assert detect_unit_scale_spoof("20 °C", "20 °F").spoofed is True
    assert detect_unit_scale_spoof("0 psig", "0 psia").spoofed is True
    assert detect_unit_scale_spoof("1 Ci", "1 Bq").spoofed is True
    assert detect_unit_scale_spoof("100 kg", "1,00,0 kg").spoofed is True

    # Quantity extraction smoke
    q = extract_quantity("1,000.50 US liquid gallons")
    assert q.value == Decimal("1000.50") and q.unit == "GLL"
    assert q.to("L").value == Decimal("3787.304489892")
