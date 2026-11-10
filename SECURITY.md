# Security policy

## Reporting a vulnerability

Please report security issues privately, not in a public issue.

Use GitHub's private vulnerability reporting: open the **Security** tab of this repository and choose **Report a vulnerability**. Include the version, the command you ran, and what you observed.

We will acknowledge your report and keep you informed while we work on a fix.

## Scope

This tool only sends read requests to Microsoft Graph and the Microsoft sign-in service. Issues of particular interest:

- Credentials or tokens written to output, logs or disk.
- Requests sent to any host other than Microsoft Graph or the Microsoft sign-in service.
- Findings that are wrong in a way that hides a real risk.
