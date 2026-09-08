from filecleaner import format as fmt


def test_human_size_bytes():
    assert fmt.human_size(0) == "0 B"
    assert fmt.human_size(500) == "500 B"


def test_human_size_kilobytes():
    assert fmt.human_size(1536) == "1.5 KB"


def test_human_size_scales_up_through_units():
    assert fmt.human_size(1024**2) == "1.0 MB"
    assert fmt.human_size(1024**3) == "1.0 GB"
    assert fmt.human_size(1024**4) == "1.0 TB"


def test_human_size_negative():
    assert fmt.human_size(-500) == "-500 B"


def test_human_age_today():
    assert fmt.human_age(100.0, now=100.5) == "today"


def test_human_age_one_day():
    assert fmt.human_age(0.0, now=86400.0 + 10) == "1 day"


def test_human_age_days():
    assert fmt.human_age(0.0, now=5 * 86400) == "5 days"


def test_human_age_months():
    assert fmt.human_age(0.0, now=90 * 86400) == "3 months"


def test_human_age_years():
    assert fmt.human_age(0.0, now=800 * 86400) == "2 years"


def test_human_age_never_negative_for_future_mtime():
    # Clock skew / not-yet-synced mtimes should never render as "negative days".
    assert fmt.human_age(1000.0, now=500.0) == "today"


def test_iso_now_round_trips():
    from datetime import datetime

    text = fmt.iso_now()
    parsed = datetime.fromisoformat(text)
    assert parsed.tzinfo is not None


def test_short_timestamp_trims_and_reformats():
    assert fmt.short_timestamp("2024-01-02T03:04:05.678901+00:00") == "2024-01-02 03:04"
