import html
import re


def esc(s: str) -> str:
    """Escape HTML characters."""
    return html.escape(s)


def is_turnstile_enabled(site_key: str = None) -> bool:
    """Check if Turnstile is enabled based on site key."""
    if not site_key:
        return False
    
    v = str(site_key).strip().lower()
    if not v:
        return False
    if v in ["false", "0", "null", "undefined"]:
        return False
    
    return True


def replace_template(template: str, replacements: dict) -> str:
    """Replace {{key}} placeholders in template with values."""
    result = template
    for key, value in replacements.items():
        result = re.sub(r'\{\{' + key + r'\}\}', value, result)
    return result


def layout(title: str, body: str, include_turnstile_script: bool) -> str:
    """Wrap content in the main layout template."""
    # Read layout HTML
    with open("src/pages/layout.html", "r") as f:
        layout_html = f.read()
    
    turnstile_script = (
        '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
        if include_turnstile_script else ''
    )
    
    return replace_template(layout_html, {
        "TITLE": esc(title),
        "BODY": body,
        "TURNSTILE_SCRIPT": turnstile_script
    })


def submit_page(opts: dict) -> str:
    """Generate the submission page HTML."""
    domain_prefill = opts.get("domainPrefill", "")
    turnstile_site_key = opts.get("turnstileSiteKey", "")
    max_files = opts.get("maxFiles", 3)
    max_total_bytes = opts.get("maxTotalBytes", 3145728)
    
    ts_enabled = is_turnstile_enabled(turnstile_site_key)
    
    turnstile_widget = (
        f'<div class="cf-turnstile" data-sitekey="{esc(turnstile_site_key)}"></div>'
        if ts_enabled else
        '<p class="text-sm text-muted-foreground">Turnstile disabled (local testing).</p>'
    )
    
    # Read submit page HTML
    with open("src/pages/submit.html", "r") as f:
        submit_html = f.read()
    
    body = replace_template(submit_html, {
        "MAX_FILES": str(max_files),
        "MAX_MB": str(max_total_bytes // (1024 * 1024)),
        "DOMAIN_PREFILL": esc(domain_prefill),
        "TURNSTILE_WIDGET": turnstile_widget,
        "MAX_TOTAL_BYTES": str(max_total_bytes),
        "TURNSTILE_ENABLED": "true" if ts_enabled else "false"
    })
    
    return layout("BLT-Zero — Submit Encrypted Report", body, ts_enabled)


def docs_security() -> str:
    """Generate the security documentation page."""
    with open("src/pages/docs-security.html", "r") as f:
        docs_security_html = f.read()
    
    return layout("BLT-Zero — Security Model", docs_security_html, False)


def docs_org_onboarding(app_origin: str) -> str:
    """Generate the organization onboarding documentation page."""
    with open("src/pages/docs-org-onboarding.html", "r") as f:
        docs_org_onboarding_html = f.read()
    
    body = replace_template(docs_org_onboarding_html, {
        "APP_ORIGIN": esc(app_origin)
    })
    
    return layout("BLT-Zero — Org Onboarding", body, False)


def docs_decrypt() -> str:
    """Generate the decryption guide page."""
    with open("src/pages/docs-decrypt.html", "r") as f:
        docs_decrypt_html = f.read()
    
    return layout("BLT-Zero — Decrypt Guide", docs_decrypt_html, False)


def admin_onboard_page(turnstile_site_key: str = None) -> str:
    """Generate the admin onboarding page."""
    ts_enabled = is_turnstile_enabled(turnstile_site_key)
    
    turnstile_widget = (
        f'<div class="cf-turnstile" data-sitekey="{esc(turnstile_site_key or "")}"></div>'
        if ts_enabled else
        '<p class="text-sm text-muted-foreground">Turnstile disabled (local testing).</p>'
    )
    
    turnstile_status = "+ Turnstile" if ts_enabled else "(Turnstile disabled)"
    
    with open("src/pages/admin-onboard.html", "r") as f:
        admin_onboard_html = f.read()
    
    body = replace_template(admin_onboard_html, {
        "TURNSTILE_WIDGET": turnstile_widget,
        "TURNSTILE_STATUS": turnstile_status,
        "TURNSTILE_ENABLED": "true" if ts_enabled else "false"
    })
    
    return layout("BLT-Zero — Org Admin Onboarding", body, ts_enabled)


def onboarding_email_body(app_origin: str, domain: str) -> str:
    """Generate the onboarding email body text."""
    return f"""Hello Security Team,

You have been onboarded to BLT-Zero (zero.blt.owasp.org) for domain: {domain}

How it works:
- Reporters encrypt in their browser using your public key.
- BLT-Zero receives only ciphertext and emails it to you.
- Only your private key can decrypt.

Next steps:
- Decrypt guide: {app_origin}/docs/decrypt
- Security model: {app_origin}/docs/security

Regards,
BLT-Zero Maintainers (OWASP BLT)
"""
