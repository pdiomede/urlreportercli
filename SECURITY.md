# Security policy

Found a security problem in Url Reporter? Please report it privately. Thank you.

## How to report

Email **security@pdiomede.com**, in English or Italian, with:

- what is affected: a URL, a file, or a command
- how to reproduce it
- the impact you think it has

Please don't open a public GitHub issue.

## In scope

- [urlreporter.com](https://urlreporter.com) and its subdomains
- the urlreporter.com web app (its source is private)
- [pdiomede/urlreportercli](https://github.com/pdiomede/urlreportercli), the command-line tool

## Out of scope

- The third-party scanners Url Reporter queries (SSL Labs, Mozilla Observatory, crt.sh, RIPEstat
  and the rest) and their results. Please report those to their operators.
- Denial-of-service or load testing
- Social engineering, phishing or physical attacks
- Output from automated tools without a demonstrated impact

## What to expect

- An acknowledgement within **5 working days**
- Updates until the report is fixed or closed
- Credit in the release notes, if you want it
- No bug bounty
- Fixes go into the live site and the latest CLI release only

## Safe harbour

Good-faith research that follows this policy won't be pursued legally. Good faith means:

- No harm to the service: no denial-of-service, and no more scanning than the report needs.
- No access to data that isn't yours, such as other visitors' scan reports. Stop if you reach any.
- A reasonable time to fix before you disclose publicly.
