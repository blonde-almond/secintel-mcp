# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
(the **Report a vulnerability** button under this repository's **Security** tab)
rather than opening a public issue.

Include what you found, how to reproduce it, and the version or commit you
tested. You can expect an acknowledgement within a week.

## Scope

Things that are in scope:

- Any way to make the server send a request to a host other than the four
  documented data sources.
- Inputs that crash the server or make it consume unbounded time or memory.
- Leakage of the `NVD_API_KEY` to anything other than the NVD.

Known and accepted:

- The HTTP transport has no authentication. It binds to loopback by default and
  is meant to sit behind a reverse proxy.
- Text from upstream databases is passed to the calling model. It is trimmed and
  flagged as data, but a model may still be influenced by it.
