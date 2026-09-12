# Publishing research and bulletins

Copy `templates/research.md` to `_posts/Threat Research/YYYY-MM-DD-slug.md`, or
`templates/bulletin.md` to `_posts/Bulletins/YYYY-MM-DD-slug.md`. Use the actual
publication date. Existing filenames, URLs and redirects have been preserved;
some legacy filenames contain placeholder dates, which must be confirmed by an editor
before changing them. Set `published: false` for a draft. Future-dated posts and
drafts are excluded by Jekyll, including from the public IOC index.

Every publication needs `title`, `description`, `content_type`, `categories` and
a nonempty `tags` list. Use `research` or `bulletin` as the content type.
Bulletins have no `header.teaser`, logo or image card. Both formats use the same
article layout, tag links and IOC schema. Narrative section titles can vary to
fit the research; use H2 for main sections and H3–H6 for subsections. The layout
supplies the only H1. Existing analysis and source qualifications are preserved.

## Tags

Choose a small set of relevant topics from `_data/tags.yml`. Add a new tag to that
file when needed. Tags are topics, not additional attribution claims: a country
can describe victim geography, an assessed actor connection, or the subject of
OSINT research. Consult the article for its attribution and confidence.
Use the same spelling everywhere (for example `C2`, `APT`, `MaaS`, `RaaS`,
`PhaaS`, `WordPress`, `China`, `Russia`, `DPRK`). Do not tag a post simply because
a country or malware appears in a passing reference. Research and Bulletin
filters combine selected tags with AND and the text query; filter URLs can be shared.

## IOC standard

Every publication has exactly one `## IOCs` section. Use one table with these
exact columns and one observation per row:

```markdown
## IOCs

| Indicator | Type | Context | Confidence | Classification |
|---|---|---|---|---|
| `192.0.2[.]1` | IPv4 | Example only: replace with a supported observation and its role. | Not stated | reference-only |
```

If no IOC section existed in a legacy article, it now explicitly says that no
individual indicators were listed. Add indicators only after reviewing evidence;
do not collect arbitrary addresses from screenshots, exploit examples or victim lists.

Use `IPv4`, `IPv6`, `Domain`, `Onion`, `URL`, `URL pattern`, `IP:port`, `SHA256`,
`SHA1`, `MD5`, `Filename`, `File path`, `URI path`, `Email`, `Wallet`, `String`,
`Scheduled task`, `Service`, `Extension`, `HTTP header`, `Auth token`,
`Bot username`, `Process name`, `Workflow name`, `Firewall rule`, `Snapshot` or
`Command pattern` as appropriate. `Hash fragment` and `IP pattern` preserve
incomplete historical values as `reference-only`; never reconstruct missing data.

Confidence is `High`, `Medium`, `Low` or `Not stated`. It belongs to the individual
observation, not the article's overall attribution. Classification is one of:

- `reported`: listed by the source without an explicit classification;
- `confirmed-attacker`: the source explicitly establishes attacker control;
- `victim-owned`: victim systems or internal scoping indicators;
- `unverified`: the source expressly qualifies the observation;
- `shared-service`: a specific resource on shared hosting or a legitimate service;
- `researcher-controlled`: sinkholed or researcher-owned infrastructure;
- `reference-only`: incomplete values, generic patterns or artefacts provided for pivoting.

Put the role, associated file, known observation dates and any source qualifications
in Context. Do not substitute publication dates for first/last-seen times.
Keep source links, YARA rules and command examples in subsections below the table.
Escape literal pipes as `\|`. Values may be defanged with `[.]`, `[:]`, `[@]`
or `hxxp(s)`. The index retains their original display and normalizes exported values.

## Build and check

```text
python -m pip install -r scripts/requirements.txt
python -m unittest discover -s tests
python scripts/build_iocs.py
bundle exec jekyll build
python scripts/check_site.py _site
```

Commit the refreshed `_data/iocs.json` alongside content edits. Run
`python scripts/build_iocs.py --check` to detect a stale index. The Pages workflow
also validates and regenerates it before every Jekyll build. Normal builds are
offline with respect to IOC sources: imported external lists are snapshots in the
Markdown, with their original source links retained.

The `/iocs.json` endpoint joins the extracted data to Jekyll's published posts.
The IOC viewer groups identical type/value pairs and preserves all distinct
source observations. Filters and exports operate on matching observations across
all result pages. CSV and JSON include context, classification, confidence, tags
and source links; TXT is a unique list of refanged values. CSV formula-leading
cells are escaped for spreadsheet import. IP lookup menus support VirusTotal,
Hunt.io and AbuseIPDB; domain menus support VirusTotal and Hunt.io. URL menus
look up the hostname. Hashes link to VirusTotal. The site does not contact IOC hosts.

The lookup menus use locally stored service favicons in `assets/images/services/`:
VirusTotal's `/gui/images/favicon.svg`, Hunt.io's favicon linked from its homepage,
and AbuseIPDB's `/favicon-32x32.png`. These are the respective services' brand assets.
