"""
ASN.1 GeneralizedTime Validator
 
Per ITU-T X.680 / RFC 5280, GeneralizedTime has the form:
 
    YYYYMMDDHHMMSS[.fff][Z | +hhmm | -hhmm]
 
Rules enforced:
  - Mandatory: YYYYMMDDHHMMSS  (14 digits)
  - Optional fractional seconds: '.' followed by one or more digits
  - Optional timezone:
      'Z'                  → UTC
      '+hhmm' / '-hhmm'   → UTC offset
      (absent)             → local time (allowed by ASN.1, rejected by DER/RFC 5280)
  - Calendar validity: month 1-12, day 1-last day of month, hours 0-23,
    minutes 0-59, seconds 0-59 (leap seconds, i.e. second == 60, are
    optionally accepted via a flag)
"""
 
import re
import calendar
from dataclasses import dataclass
from typing import Optional
 
 
# ---------------------------------------------------------------------------
# Regex
# ---------------------------------------------------------------------------
 
_GT_PATTERN = re.compile(
    r"""
    ^
    (?P<year>   \d{4})
    (?P<month>  \d{2})
    (?P<day>    \d{2})
    (?P<hour>   \d{2})
    (?P<minute> \d{2})
    (?P<second> \d{2})
    (?:\.(?P<frac>\d+))?          # optional fractional seconds
    (?P<tz>Z|[+-]\d{4})?          # optional timezone
    $
    """,
    re.VERBOSE,
)
 
 
# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------
 
@dataclass
class ValidationResult:
    valid: bool
    error: Optional[str] = None
 
    def __bool__(self) -> bool:
        return self.valid
 
    def __repr__(self) -> str:
        if self.valid:
            return "ValidationResult(valid=True)"
        return f"ValidationResult(valid=False, error={self.error!r})"
 
 
# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
 
def validate_generalized_time(
    value: str,
    *,
    require_utc: bool = False,
    allow_leap_second: bool = False,
) -> ValidationResult:
    """
    Validate an ASN.1 GeneralizedTime string.
 
    Parameters
    ----------
    value : str
        The string to validate.
    require_utc : bool
        If True, reject values that do not carry an explicit timezone
        designator (i.e. bare local-time strings).  RFC 5280 certificates
        must use 'Z'; pass require_utc=True to enforce that stricter rule.
    allow_leap_second : bool
        If True, accept second == 60 (leap second).  Disabled by default
        because most applications do not handle leap seconds.
 
    Returns
    -------
    ValidationResult
        .valid is True on success; .error contains a human-readable message
        on failure.
    """
    if not isinstance(value, str):
        return ValidationResult(False, "Value must be a string")
 
    m = _GT_PATTERN.match(value)
    if not m:
        return ValidationResult(
            False,
            "String does not match GeneralizedTime format "
            "YYYYMMDDHHMMSS[.frac][Z|+hhmm|-hhmm]",
        )
 
    year   = int(m.group("year"))
    month  = int(m.group("month"))
    day    = int(m.group("day"))
    hour   = int(m.group("hour"))
    minute = int(m.group("minute"))
    second = int(m.group("second"))
    tz     = m.group("tz")          # 'Z', '+0530', '-0500', or None
 
    # --- month ----------------------------------------------------------
    if not 1 <= month <= 12:
        return ValidationResult(False, f"Month {month} is out of range [1, 12]")
 
    # --- day ------------------------------------------------------------
    max_day = calendar.monthrange(year, month)[1]
    if not 1 <= day <= max_day:
        return ValidationResult(
            False, f"Day {day} is out of range [1, {max_day}] for {year}-{month:02d}"
        )
 
    # --- time -----------------------------------------------------------
    if not 0 <= hour <= 23:
        return ValidationResult(False, f"Hour {hour} is out of range [0, 23]")
 
    if not 0 <= minute <= 59:
        return ValidationResult(False, f"Minute {minute} is out of range [0, 59]")
 
    max_second = 60 if allow_leap_second else 59
    if not 0 <= second <= max_second:
        return ValidationResult(
            False, f"Second {second} is out of range [0, {max_second}]"
        )
 
    # --- timezone -------------------------------------------------------
    if require_utc and tz is None:
        return ValidationResult(
            False,
            "Timezone designator is required (RFC 5280 / DER require 'Z')",
        )
 
    if tz and tz != "Z":
        tz_hour   = int(tz[1:3])
        tz_minute = int(tz[3:5])
        if not 0 <= tz_hour <= 23:
            return ValidationResult(
                False, f"Timezone hour offset {tz_hour} is out of range [0, 23]"
            )
        if not 0 <= tz_minute <= 59:
            return ValidationResult(
                False, f"Timezone minute offset {tz_minute} is out of range [0, 59]"
            )
 
    return ValidationResult(True)
 
 
# ---------------------------------------------------------------------------
# CLI / smoke tests
# ---------------------------------------------------------------------------
 
if __name__ == "__main__":
    test_cases = [
        # (value, require_utc, allow_leap_second, expected_valid)
        ("20231015123045Z",         False, False, True),   # basic UTC
        ("20231015123045.123Z",     False, False, True),   # fractional seconds
        ("20231015123045+0530",     False, False, True),   # positive offset
        ("20231015123045-0500",     False, False, True),   # negative offset
        ("20231015123045",          False, False, True),   # local time (no tz)
        ("20231015123045",          True,  False, False),  # local time rejected when require_utc
        ("20231301123045Z",         False, False, False),  # month 13
        ("20230229123045Z",         False, False, False),  # Feb 29 on non-leap year
        ("20240229123045Z",         False, False, True),   # Feb 29 on leap year
        ("20231015253045Z",         False, False, False),  # hour 25
        ("20231015126045Z",         False, False, False),  # minute 60
        ("20231015123060Z",         False, False, False),  # second 60 (no leap)
        ("20231015123060Z",         False, True,  True),   # second 60 (leap allowed)
        ("2023101512304",           False, False, False),  # too short
        ("notadate",                False, False, False),  # garbage
        ("20231015123045.Z",        False, False, False),  # dot with no digits
        ("20231015123045+2500",     False, False, False),  # bad tz hour
    ]
 
    passed = failed = 0
    for value, req_utc, leap, expected in test_cases:
        result = validate_generalized_time(
            value, require_utc=req_utc, allow_leap_second=leap
        )
        status = "PASS" if result.valid == expected else "FAIL"
        if status == "PASS":
            passed += 1
        else:
            failed += 1
        note = f"  ← {result.error}" if not result.valid else ""
        print(f"[{status}]  {value!r:35s}  valid={result.valid}{note}")
 
    print(f"\n{passed} passed, {failed} failed")
    