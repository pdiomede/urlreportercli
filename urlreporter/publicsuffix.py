"""Where a hostname stops belonging to its owner and starts belonging to a registry.

Three call sites need the same boundary and each used to guess at it with
"take the last two labels": `caa` and `email_auth` walk a host's parents
looking for inherited records, and `registration` needs the registrable domain
for its RDAP query. Under a multi-label public suffix that guess is wrong in a
way that is not merely useless but actively misleading — the walk climbs *into*
the suffix and reads the registry's own DNS.

That is a live false positive, not a theoretical one. At the time of writing
`co.za` publishes both MX and SPF records, and `com.mx` publishes SPF. So
`example.co.za`, with no email authentication of its own, inherited `co.za`'s
SPF and scored for it — on a scanner weighted 2.0 — while `co.za`'s MX
suppressed the "not a mail-sending host" link-out that should have applied.
The same walk in `caa` would credit a domain with a registry's CAA policy.

This module carries a **curated** list of multi-label suffixes rather than the
full Public Suffix List. The trade-off is deliberate: the full PSL means either
a new dependency whose bundled data ages inside our pinned version, or a
runtime download, and this project deliberately avoids both (it does its own
DNS over DoH rather than depend on a system resolver). The list below covers
the suffixes real traffic actually uses. A suffix that is missing simply
behaves as everything did before this module existed — the failure mode is
unchanged, not newly introduced — so being incomplete costs nothing relative
to the status quo while the listed ones become correct.
"""

from __future__ import annotations

# Multi-label public suffixes: names under which the public registers, so
# nothing at or above them belongs to the scanned domain's owner. Grouped by
# ccTLD for auditability. Single-label suffixes (`com`, `it`, `de`, …) need no
# listing — they are the default assumption.
_MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset({
    # United Kingdom
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    "ac.uk", "gov.uk", "nhs.uk", "police.uk", "mod.uk",
    # Australia
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    # New Zealand
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz", "geek.nz",
    "kiwi.nz", "maori.nz", "health.nz", "iwi.nz", "parliament.nz",
    # South Africa
    "co.za", "org.za", "net.za", "gov.za", "ac.za", "web.za", "edu.za",
    # Brazil
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "art.br", "blog.br",
    # Japan
    "co.jp", "or.jp", "ne.jp", "ac.jp", "ad.jp", "ed.jp", "go.jp", "gr.jp",
    "lg.jp",
    # China / Hong Kong / Taiwan
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "com.hk", "net.hk", "org.hk", "edu.hk", "gov.hk", "idv.hk",
    "com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw", "idv.tw",
    # Korea
    "co.kr", "ne.kr", "or.kr", "re.kr", "pe.kr", "go.kr", "ac.kr",
    # India
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "ac.in",
    "edu.in", "gov.in", "res.in",
    # Mexico / Latin America
    "com.mx", "org.mx", "net.mx", "edu.mx", "gob.mx",
    "com.ar", "net.ar", "org.ar", "gob.ar", "edu.ar",
    "com.co", "net.co", "org.co", "edu.co", "gov.co", "nom.co",
    "com.pe", "net.pe", "org.pe", "edu.pe", "gob.pe", "nom.pe",
    "com.uy", "net.uy", "org.uy", "edu.uy", "gub.uy", "mil.uy",
    "com.ve", "net.ve", "org.ve", "edu.ve", "gob.ve", "web.ve",
    "com.ec", "net.ec", "org.ec", "edu.ec", "gob.ec", "fin.ec", "med.ec",
    "co.cr", "ac.cr", "go.cr", "or.cr", "sa.cr", "fi.cr", "ed.cr",
    # Turkey
    "com.tr", "net.tr", "org.tr", "gen.tr", "biz.tr", "info.tr", "av.tr",
    "bel.tr", "gov.tr", "edu.tr", "k12.tr",
    # Israel
    "co.il", "org.il", "net.il", "ac.il", "gov.il", "k12.il", "muni.il",
    # Middle East / North Africa
    "com.sa", "net.sa", "org.sa", "edu.sa", "gov.sa", "med.sa", "pub.sa",
    "co.ae", "net.ae", "org.ae", "ac.ae", "gov.ae", "sch.ae", "mil.ae",
    "com.eg", "net.eg", "org.eg", "edu.eg", "gov.eg", "sci.eg",
    # Sub-Saharan Africa
    "com.ng", "net.ng", "org.ng", "edu.ng", "gov.ng", "sch.ng",
    "co.ke", "or.ke", "ne.ke", "go.ke", "ac.ke", "sc.ke", "me.ke",
    # South & Southeast Asia
    "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg", "per.sg",
    "com.my", "net.my", "org.my", "edu.my", "gov.my", "mil.my", "name.my",
    "co.th", "in.th", "ac.th", "go.th", "mi.th", "or.th", "net.th",
    "co.id", "or.id", "ac.id", "go.id", "net.id", "web.id", "sch.id",
    "my.id", "biz.id", "desa.id",
    "com.ph", "net.ph", "org.ph", "edu.ph", "gov.ph",
    "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn",
    "com.pk", "net.pk", "org.pk", "edu.pk", "gov.pk", "biz.pk", "web.pk",
    "com.bd", "net.bd", "org.bd", "edu.bd", "gov.bd", "ac.bd",
    # Europe (the flat ccTLDs are omitted on purpose)
    "com.pl", "net.pl", "org.pl", "edu.pl", "gov.pl", "info.pl", "waw.pl",
    "com.ua", "net.ua", "org.ua", "in.ua", "kiev.ua",
    "com.es", "org.es", "gob.es", "edu.es", "nom.es",
    "com.pt", "edu.pt", "gov.pt", "org.pt", "net.pt",
    "com.gr", "edu.gr", "net.gr", "org.gr", "gov.gr",
    "gov.it", "edu.it",
    "asso.fr", "com.fr", "gouv.fr", "nom.fr", "prd.fr", "tm.fr",
    "co.at", "or.at", "ac.at", "gv.at", "priv.at",
    "gov.ie",
    # Canada / US second levels in common use
    "gc.ca", "qc.ca", "on.ca", "ab.ca", "bc.ca",
    "k12.us", "state.us", "lib.us",

    # --- PSL "private section": platforms that hand out subdomains ---
    # Not registry suffixes, but the same boundary for our purposes — whoever
    # owns `myapp.vercel.app` does not control `vercel.app`'s DNS. Omitting
    # these was the more damaging half of the bug, because these hosts are far
    # likelier to be scanned than a ccTLD second-level. Verified live over DoH:
    # `vercel.app` and `netlify.app` publish SPF *and* DMARC, `github.io`
    # publishes SPF and six CAA records, `amazonaws.com` publishes MX, SPF and
    # DMARC. A scan of `myapp.vercel.app` scored A+/100 on both CAA and email
    # auth on records belonging entirely to Vercel.
    "github.io", "githubusercontent.com",
    "vercel.app", "netlify.app", "netlify.live",
    "pages.dev", "workers.dev",
    "herokuapp.com", "herokudns.com",
    "web.app", "firebaseapp.com", "appspot.com",
    "azurewebsites.net", "azurestaticapps.net", "cloudapp.net",
    "amazonaws.com", "s3.amazonaws.com", "elasticbeanstalk.com",
    "cloudfront.net",
    "onrender.com", "fly.dev", "railway.app", "surge.sh", "glitch.me",
    "repl.co", "ngrok.io", "translate.goog",
    "blogspot.com", "wordpress.com", "myshopify.com", "wixsite.com",
})


# Longest entry in the table, so the match below knows how far back to look.
_MAX_SUFFIX_LABELS = max(entry.count(".") + 1 for entry in _MULTI_LABEL_SUFFIXES)


def public_suffix(host: str) -> str:
    """The suffix portion of `host` — the part registered *under*, not *by*.

    Longest match wins. The first version of this compared only the last two
    labels, which meant an entry like `s3.amazonaws.com` could sit in the table
    and never be consulted: `bucket.s3.amazonaws.com` matched `amazonaws.com`
    and stopped there, so the walk still entered `s3.amazonaws.com` — itself a
    suffix. Three-label suffixes were unrepresentable rather than merely
    absent, which is the sort of gap that looks fixed from the table alone.
    """
    labels = host.lower().strip(".").split(".")
    for size in range(min(_MAX_SUFFIX_LABELS, len(labels)), 1, -1):
        candidate = ".".join(labels[-size:])
        if candidate in _MULTI_LABEL_SUFFIXES:
            return candidate
    return labels[-1]


def registrable_domain(host: str) -> str | None:
    """The apex a person or company actually owns: one label below the suffix.

    ``www.example.co.uk`` -> ``example.co.uk``, not the ``co.uk`` the old
    last-two-labels rule produced. Returns None when there is no such thing to
    extract: an IP literal, or a bare public suffix like ``co.uk`` itself.
    """
    cleaned = host.lower().strip(".")
    if not cleaned or ":" in cleaned:
        return None
    labels = cleaned.split(".")
    if all(label.isdigit() for label in labels):
        return None  # IPv4 literal, or something pretending to be one
    suffix_len = public_suffix(cleaned).count(".") + 1
    if len(labels) <= suffix_len:
        return None
    return ".".join(labels[-(suffix_len + 1):])


def parent_domains(host: str) -> list[str]:
    """`host` and each ancestor down to the registrable domain, closest first.

    The walk **stops at the apex** and never enters the public suffix, which is
    the whole point: CAA, SPF and DMARC are inherited from ancestors the owner
    controls, and a registry's zone is not one of them.
    """
    cleaned = host.lower().strip(".")
    apex = registrable_domain(cleaned)
    if apex is None:
        # A bare public suffix has nothing beneath it worth walking. A
        # single-label name ("localhost") is not a suffix at all, so it stays
        # its own leaf — which is what the previous implementations did.
        return [] if "." in cleaned else ([cleaned] if cleaned else [])
    labels = cleaned.split(".")
    depth = len(labels) - len(apex.split("."))
    return [".".join(labels[i:]) for i in range(depth + 1)]

def is_ip_literal(host: str) -> bool:
    """True when `host` is an IP address rather than a DNS name.

    Several scanners check properties that are defined *against a name* — CAA,
    SPF/DMARC/DKIM, HSTS preload, DNSSEC. None of them can exist for an IP
    literal, so grading one produces a number about a question that was never
    asked.
    """
    import ipaddress

    cleaned = host.strip().strip(".")
    if not cleaned:
        return False
    try:
        ipaddress.ip_address(cleaned)
    except ValueError:
        return False
    return True


def ancestor_domains(host: str) -> list[str]:
    """`host` and every parent down to the two-label boundary, closest first.

    This is **not** `parent_domains`, and the difference is deliberate — the
    three protocols that climb the DNS tree do not climb the same distance:

      * **SPF** (RFC 7208) does not climb at all.
      * **DMARC** (RFC 7489 §6.6.3) falls back to the Organizational Domain,
        which is defined *using a public suffix list*. It stops at the apex.
      * **CAA** (RFC 8659 §3) climbs `domain -> Parent(domain)` toward the root
        and does **not** exclude public suffixes.

    So a CAA record on `vercel.app` genuinely constrains issuance for
    `myapp.vercel.app`, and one on `co.uk` genuinely constrains issuance for
    `example.co.uk`. Applying the DMARC boundary to CAA makes the scanner
    report "no CAA records on this domain or any ancestor" about a host whose
    issuance *is* restricted — false, and in the reassuring direction.
    """
    if is_ip_literal(host):
        return []
    labels = host.lower().strip(".").split(".")
    return [".".join(labels[i:]) for i in range(max(len(labels) - 1, 1))]
