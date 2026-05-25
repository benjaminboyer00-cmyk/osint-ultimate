"""Registre unifié des modules de scan."""
from scan_modules import EXTRA_SCAN_FUNCTIONS
from scans.core_scans import (
    scan_email,
    scan_facebook,
    scan_github,
    scan_instagram,
    scan_ip,
    scan_linkedin,
    scan_phone,
    scan_pseudo,
    scan_sherlock,
    scan_site,
    scan_snapchat,
    scan_tiktok,
    scan_twitter,
)

CORE_SCAN_FUNCTIONS = {
    "site": scan_site,
    "email": scan_email,
    "phone": scan_phone,
    "ip": scan_ip,
    "pseudo": scan_pseudo,
    "sherlock": scan_sherlock,
    "instagram": scan_instagram,
    "twitter": scan_twitter,
    "tiktok": scan_tiktok,
    "github": scan_github,
    "facebook": scan_facebook,
    "linkedin": scan_linkedin,
    "snapchat": scan_snapchat,
}

SCAN_FUNCTIONS = {**CORE_SCAN_FUNCTIONS, **EXTRA_SCAN_FUNCTIONS}
