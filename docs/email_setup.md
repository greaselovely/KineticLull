# Email Setup for KineticLull (Resend)

KineticLull uses [Resend](https://resend.com) to send OTP emails for secure file downloads. This guide covers getting email deliverability set up properly.

## 1. Create a Resend Account

1. Sign up at https://resend.com
2. Go to **API Keys** and create a new key
3. Copy the API key — you'll add it to KineticLull's Settings page

## 2. Add Your Sending Domain

In Resend dashboard:

1. Go to **Domains** > **Add Domain**
2. Enter the domain you want to send from (e.g., `kineticlull.yourdomain.com` or `yourdomain.com`)
3. Resend will give you DNS records to add

## 3. Configure DNS Records

You'll need to add the following DNS records at your domain registrar or DNS provider. Resend provides the exact values — these are the types you'll see:

### SPF (Sender Policy Framework)

SPF tells receiving mail servers which services are allowed to send email on behalf of your domain.

| Type | Host | Value |
|------|------|-------|
| TXT | `@` or subdomain | Resend provides this — typically includes `include:resend.com` |

**If you already have an SPF record**, don't create a second one. Merge the `include:resend.com` into your existing record:

```
v=spf1 include:_spf.google.com include:resend.com ~all
```

**Important**: Only one SPF TXT record per domain. Multiple SPF records will cause failures.

### DKIM (DomainKeys Identified Mail)

DKIM cryptographically signs outgoing emails so recipients can verify they haven't been tampered with. Resend handles the signing — you just publish the public key in DNS.

Resend will give you one or more CNAME records:

| Type | Host | Value |
|------|------|-------|
| CNAME | `resend._domainkey.yourdomain.com` | provided by Resend |

Add all the CNAME records Resend provides. There may be multiple.

### DMARC (Domain-based Message Authentication, Reporting & Conformance)

DMARC ties SPF and DKIM together and tells receiving servers what to do when authentication fails. It also provides reporting so you can see who's sending email as your domain.

Add this TXT record:

| Type | Host | Value |
|------|------|-------|
| TXT | `_dmarc` | `v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com; pct=100` |

**DMARC policy options:**
- `p=none` — monitor only, don't take action on failures (good for initial setup)
- `p=quarantine` — send failures to spam (recommended)
- `p=reject` — reject failures outright (strictest, use after monitoring)

**Recommended approach:**
1. Start with `p=none` to monitor for a week
2. Move to `p=quarantine` once you confirm legitimate email is passing
3. Optionally move to `p=reject` after you're confident

### Return Path / Bounce Handling

Resend may also ask for a CNAME for bounce handling:

| Type | Host | Value |
|------|------|-------|
| CNAME | `bounces.yourdomain.com` | provided by Resend |

## 4. Verify in Resend

After adding all DNS records:

1. Go back to Resend **Domains** page
2. Click **Verify** on your domain
3. DNS propagation can take 5 minutes to 48 hours (usually under 30 minutes)
4. All records should show green checkmarks

## 5. Configure KineticLull

In KineticLull's **Settings** page (once the email feature is deployed):

1. Enter your Resend API key
2. Set the "From" email address (must match your verified domain, e.g., `noreply@yourdomain.com`)
3. Save

## Troubleshooting

### Emails going to spam
- Verify all three records (SPF, DKIM, DMARC) are in place
- Check Resend dashboard for delivery status
- Make sure you're not sending from a free email domain (gmail.com, etc.)

### DNS records not verifying
- Use [MXToolbox](https://mxtoolbox.com/SuperTool.aspx) to check your records
- SPF: `mxtoolbox.com/spf.aspx` — enter your domain
- DKIM: `mxtoolbox.com/dkim.aspx` — enter `resend._domainkey.yourdomain.com`
- DMARC: `mxtoolbox.com/dmarc.aspx` — enter your domain
- If using Cloudflare, make sure DNS-only mode (grey cloud) is on for CNAME records

### "No SPF record found"
- You may have added the TXT record to the wrong host. For root domain, use `@`. For subdomain, use the subdomain.
- Check for duplicate SPF records — only one is allowed per domain.

## DNS Propagation Check

After adding records, verify everything is in place:

```bash
# Check SPF
dig TXT yourdomain.com | grep spf

# Check DKIM
dig CNAME resend._domainkey.yourdomain.com

# Check DMARC
dig TXT _dmarc.yourdomain.com
```

## Notes

- Resend free tier: 100 emails/day, 3,000/month — plenty for OTP use
- Emails are transactional only (OTP codes), not marketing — deliverability should be high
- The sending domain does not need to match the KineticLull server domain
