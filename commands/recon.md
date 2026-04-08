---
description: Run full recon pipeline on a target — subdomain enum (Chaos API + subfinder), live host discovery (dnsx + httpx), URL crawl (katana + waybackurls + gau), gf pattern classification, nuclei scan. Outputs to recon/<target>/ directory. Usage: /recon target.com
---

# /recon

Run the full recon pipeline on a target and produce a prioritized attack surface.

> Ref: `agents/recon-agent.md` (agent-based recon), `agents/recon-ranker.md` (ranking after recon)

## Usage

```
/recon target.com
/recon target.com --focus api
/recon target.com --focus auth
/recon target.com --fast     (skip historical URLs)
```

## Pipeline (5 steps)

**Step 1: Subdomain Enumeration**
```bash
mkdir -p recon/$TARGET
curl -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" -H "Authorization: $CHAOS_API_KEY" | jq -r '.[]' > recon/$TARGET/subdomains.txt
subfinder -d $TARGET -silent | anew recon/$TARGET/subdomains.txt
assetfinder --subs-only $TARGET | anew recon/$TARGET/subdomains.txt
```

**Step 2: Live Host Discovery**
```bash
cat recon/$TARGET/subdomains.txt | dnsx -silent | httpx -silent -status-code -title -tech-detect | tee recon/$TARGET/live-hosts.txt
```

**Step 3: URL Crawl**
```bash
cat recon/$TARGET/live-hosts.txt | awk '{print $1}' | katana -d 3 -jc -kf all -silent | anew recon/$TARGET/urls.txt
echo $TARGET | waybackurls | anew recon/$TARGET/urls.txt
gau $TARGET --subs | anew recon/$TARGET/urls.txt
```

**Step 4: Classify URLs**
```bash
cat recon/$TARGET/urls.txt | gf xss > recon/$TARGET/xss-candidates.txt
cat recon/$TARGET/urls.txt | gf ssrf > recon/$TARGET/ssrf-candidates.txt
cat recon/$TARGET/urls.txt | gf idor > recon/$TARGET/idor-candidates.txt
cat recon/$TARGET/urls.txt | gf sqli > recon/$TARGET/sqli-candidates.txt
cat recon/$TARGET/urls.txt | grep -E "/api/|/v1/|/v2/|/graphql|/rest/" > recon/$TARGET/api-endpoints.txt
```

**Step 5: Nuclei**
```bash
nuclei -l recon/$TARGET/live-hosts.txt -t ~/nuclei-templates/ -severity critical,high,medium -o recon/$TARGET/nuclei.txt
```

## What to Do Next

1. Review `live-hosts.txt` — open interesting ones in browser
2. Check `nuclei.txt` — any high/critical findings?
3. Review `api-endpoints.txt` — start IDOR testing
4. Run `/hunt target.com` to start active testing

## 5-Minute Rule

If all hosts return 403 or static pages, no API endpoints, no nuclei medium/high → move on to a different target.
