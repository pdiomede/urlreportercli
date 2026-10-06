# Security policy

Url Reporter is a free, passive website security scanner, run by Paolo Diomede. It lives at
[urlreporter.com](https://urlreporter.com), with its source in
[pdiomede/urlreporter](https://github.com/pdiomede/urlreporter) (the web app) and
[pdiomede/urlreportercli](https://github.com/pdiomede/urlreportercli) (the command-line tool).

If you have found a security problem in any of them, thank you. Please report it privately, as
described below, rather than in a public GitHub issue.

## Reporting a vulnerability

Email **security@pdiomede.com** with:

- what is affected: a URL, a file in one of the repositories, or a command;
- the steps to reproduce it, and what you expected to happen instead;
- the impact you think it has.

English or Italian is fine.

## Scope

In scope:

- urlreporter.com and its subdomains
- github.com/pdiomede/urlreporter
- github.com/pdiomede/urlreportercli

Out of scope:

- the third-party scanners Url Reporter queries (SSL Labs, Mozilla Observatory,
  securityheaders.com, hstspreload.org, crt.sh, CertSpotter, RIPEstat, Cloudflare DNS and others)
  and the results they return; please report those to their operators;
- denial-of-service or load testing of urlreporter.com;
- social engineering, phishing, or physical attacks;
- reports produced only by an automated tool, without a demonstrated impact.

## What to expect

- An acknowledgement within **5 working days**.
- Updates while the report is investigated, until it is fixed or closed.
- Credit in the release notes once it is fixed, if you would like it.

There is no bug bounty.

Fixes go into the current version of urlreporter.com and the latest release of the CLI; older
releases are not patched.

## Safe harbour

Research done in good faith and within this policy will not be pursued legally. Good faith here
means that you:

- test without degrading the service for others: no denial-of-service, and no bulk scanning
  beyond what you need to show the problem;
- do not access, change or delete data that isn't yours, such as the scan reports of other
  visitors, and stop as soon as you reach any;
- give a reasonable time for a fix before disclosing the problem publicly.
