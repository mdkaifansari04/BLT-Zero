import layoutHtml from "./pages/layout.html";
import submitHtml from "./pages/submit.html";
import docsSecurityHtml from "./pages/docs-security.html";
import docsOrgOnboardingHtml from "./pages/docs-org-onboarding.html";
import docsDecryptHtml from "./pages/docs-decrypt.html";
import adminOnboardHtml from "./pages/admin-onboard.html";

function esc(s: string) {
  return s.replace(/[&<>"']/g, (c) =>
    ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[c] as string)
  );
}

function isTurnstileEnabled(siteKey: string | undefined | null): boolean {
  const v = (siteKey ?? "").trim().toLowerCase();
  if (!v) return false;
  if (v === "false" || v === "0" || v === "null" || v === "undefined") return false;
  return true;
}

function replaceTemplate(template: string, replacements: Record<string, string>): string {
  let result = template;
  for (const [key, value] of Object.entries(replacements)) {
    result = result.replace(new RegExp(`\\{\\{${key}\\}\\}`, 'g'), value);
  }
  return result;
}

export function layout(title: string, body: string, includeTurnstileScript: boolean) {
  const turnstileScript = includeTurnstileScript 
    ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
    : '';
  
  return replaceTemplate(layoutHtml, {
    TITLE: esc(title),
    BODY: body,
    TURNSTILE_SCRIPT: turnstileScript
  });
}

export function submitPage(opts: {
  domainPrefill?: string;
  turnstileSiteKey?: string;
  maxFiles: number;
  maxTotalBytes: number;
}) {
  const tsEnabled = isTurnstileEnabled(opts.turnstileSiteKey);

  const turnstileWidget = tsEnabled
    ? `<div class="cf-turnstile" data-sitekey="${esc(opts.turnstileSiteKey ?? "")}"></div>`
    : `<p class="text-sm text-muted-foreground">Turnstile disabled (local testing).</p>`;

  const body = replaceTemplate(submitHtml, {
    MAX_FILES: String(opts.maxFiles),
    MAX_MB: String(Math.floor(opts.maxTotalBytes / (1024 * 1024))),
    DOMAIN_PREFILL: esc(opts.domainPrefill || ""),
    TURNSTILE_WIDGET: turnstileWidget,
    MAX_TOTAL_BYTES: String(opts.maxTotalBytes),
    TURNSTILE_ENABLED: tsEnabled ? "true" : "false"
  });

  return layout("BLT-Zero — Submit Encrypted Report", body, tsEnabled);
}

export function docsSecurity() {
  return layout(
    "BLT-Zero — Security Model",
    docsSecurityHtml,
    false
  );
}

export function docsOrgOnboarding(appOrigin: string) {
  const body = replaceTemplate(docsOrgOnboardingHtml, {
    APP_ORIGIN: esc(appOrigin)
  });
  
  return layout(
    "BLT-Zero — Org Onboarding",
    body,
    false
  );
}

export function docsDecrypt() {
  return layout(
    "BLT-Zero — Decrypt Guide",
    docsDecryptHtml,
    false
  );
}

export function adminOnboardPage(turnstileSiteKey?: string) {
  const tsEnabled = isTurnstileEnabled(turnstileSiteKey);

  const turnstileWidget = tsEnabled
    ? `<div class="cf-turnstile" data-sitekey="${esc(turnstileSiteKey ?? "")}"></div>`
    : `<p class="text-sm text-muted-foreground">Turnstile disabled (local testing).</p>`;

  const turnstileStatus = tsEnabled ? "+ Turnstile" : "(Turnstile disabled)";

  const body = replaceTemplate(adminOnboardHtml, {
    TURNSTILE_WIDGET: turnstileWidget,
    TURNSTILE_STATUS: turnstileStatus,
    TURNSTILE_ENABLED: tsEnabled ? "true" : "false"
  });

  return layout(
    "BLT-Zero — Org Admin Onboarding",
    body,
    tsEnabled
  );
}

export function onboardingEmailBody(appOrigin: string, domain: string) {
  return `Hello Security Team,

You have been onboarded to BLT-Zero (zero.blt.owasp.org) for domain: ${domain}

How it works:
- Reporters encrypt in their browser using your public key.
- BLT-Zero receives only ciphertext and emails it to you.
- Only your private key can decrypt.

Next steps:
- Decrypt guide: ${appOrigin}/docs/decrypt
- Security model: ${appOrigin}/docs/security

Regards,
BLT-Zero Maintainers (OWASP BLT)
`;
}
