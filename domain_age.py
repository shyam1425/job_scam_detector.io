import whois
from datetime import datetime, timezone


def get_domain_age_days(domain):
    """Return domain age in days, or None when WHOIS data is unavailable."""
    if not domain or "." not in domain:
        return None

    try:
        creation_date = whois.whois(domain).creation_date
        if isinstance(creation_date, (list, tuple)):
            creation_date = next((value for value in creation_date if value), None)
        if not isinstance(creation_date, datetime):
            return None

        now = datetime.now(timezone.utc)
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        else:
            creation_date = creation_date.astimezone(timezone.utc)

        return max(0, (now - creation_date).days)
    except Exception:
        return None


def get_domain_age(domain):
    """Backward-compatible alias for older diagnostic scripts."""
    return get_domain_age_days(domain)


def format_domain_age_display(age_days):
    """Convert a numeric domain age into a human-readable label."""
    if age_days is None:
        return "Domain Age Unknown"
    if age_days < 90:
        return f"New Domain ({age_days} days old)"
    if age_days < 365:
        return f"{age_days} days old"
    return f"{age_days // 365} years old"
