# azure-iam-sec-checker

Read-only security checks for Microsoft Entra ID (Azure AD). It answers questions such as:

- Which service principals were granted high-risk Microsoft Graph permissions?
- Who holds a privileged directory role?
- Where are the gaps in our conditional access policies?

It only reads from Microsoft Graph, prints JSON, and needs nothing beyond Python and a sign-in.

## Install

Requires Python 3.10 or later.

```bash
pipx install git+https://github.com/BlueLanternSecurity/azure-iam-sec-checker
```

`uv tool install` and `pip install` accept the same URL.

## Quick start

```bash
az login
azure-iam-sec-checker find-risky-service-principals
```

```json
[
  {
    "app_name": "Vendor Backup",
    "app_id": "0c1f4b1e-0000-0000-0000-000000000000",
    "service_principal_id": "5d2a9c33-0000-0000-0000-000000000000",
    "service_principal_type": "Application",
    "account_enabled": true,
    "owner_tenant_id": "99999999-9999-9999-9999-999999999999",
    "external_owner": true,
    "permission": "RoleManagement.ReadWrite.Directory",
    "granted_on": "2025-02-03T00:00:00Z",
    "risk": "privesc",
    "reason": "Grants the ability to elevate privileges to the Global Administrator role or manage other directory roles, a significant security risk."
  }
]
```

## Commands

| Command | What it reports |
| --- | --- |
| `find-risky-service-principals` | Service principals granted any permission on the bundled high-risk list. `--list-permissions` prints the list. |
| `find-service-principals-with-permission --permission NAME` | Service principals granted one Microsoft Graph application permission, e.g. `Directory.Read.All`. |
| `find-role-members --role NAME` | Principals assigned to an Entra role, e.g. `"Global Administrator"`. |
| `find-entra-roles-with-action --action NAME` | Roles that allow a directory action. `*` is a wildcard. |
| `find-privileged-users` | Principals assigned any role that contains an action Microsoft marks as privileged. |
| `evaluate-conditional-access-policies` | Thirteen checks for conditional access gaps. `--threshold high`, `medium` or `info` sets the lowest severity reported. |

Run any command with `--help` for its options.

### Service principal checks

The two service principal commands report permissions that were **granted**: app role assignments on the Microsoft Graph service principal. An app that lists a permission in its manifest but never received admin consent is not reported. Enterprise apps that live in another tenant are reported, with `external_owner: true`.

The bundled high-risk list is in [`src/azure_iam/data/risky_permissions.json`](src/azure_iam/data/risky_permissions.json). Each entry carries the reason it is on the list and a risk category: `privesc`, `persistence`, `defense evasion`, `impersonation`, `exposure` or `data integrity`.

## Signing in

### Azure CLI (default)

With no credentials configured, the tool uses your `az login` session. Add `--azure-tenant-id` to pick a tenant other than your default.

If your account has no Azure subscription, sign in with `az login --allow-no-subscriptions`. If the session has expired or Microsoft Graph requires MFA, the error shows the `az login` command to run.

Every command works with an `az login` session; no app registration is needed. What you can read depends on your directory role, so sign in with an account that can read the data, such as a Global Reader. If Microsoft Graph refuses a request, the error names the permission the command needs and the permissions your token holds.

### App registration

For automation, where nobody is there to run `az login`, use an app registration with a client secret.

1. In the Microsoft Entra admin center, open **App registrations** and create a new registration.
2. Under **API permissions**, add Microsoft Graph **application** permissions from the table below, then grant admin consent.
3. Under **Certificates & secrets**, create a client secret.

| Command | Microsoft Graph application permissions |
| --- | --- |
| `find-risky-service-principals`, `find-service-principals-with-permission` | `Application.Read.All` |
| `find-role-members`, `find-entra-roles-with-action`, `find-privileged-users` | `RoleManagement.Read.Directory`, plus `Directory.Read.All` to show member names |
| `evaluate-conditional-access-policies` | `Policy.Read.All`, plus `User.Read.All` to show the names of excluded users |

Provide the credentials as environment variables:

```bash
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
azure-iam-sec-checker evaluate-conditional-access-policies --threshold medium
```

Or put the same three lines in a dotenv file and pass `--credential-file path/to/azure.env`. The flags `--azure-tenant-id`, `--azure-client-id` and `--azure-client-secret` also work, but a secret passed on the command line ends up in shell history.

When app credentials are present they are used; otherwise the Azure CLI session is. `--auth cli` or `--auth app` forces one or the other.

## Output and exit codes

- Results are JSON on stdout. An empty list means the check ran and found nothing.
- Errors and warnings go to stderr.
- Exit code 0 means the command completed; 1 means sign-in or a Microsoft Graph request failed, or a named role or permission does not exist; 2 means invalid usage.

A command never prints partial results. If any page of a Microsoft Graph response fails, the command fails.

```bash
azure-iam-sec-checker find-risky-service-principals | jq -r '.[] | select(.external_owner) | .app_name'
```

## Limitations

- Service principal checks cover application permissions on Microsoft Graph. They do not cover delegated permission grants or permissions on other APIs.
- Role commands report active role assignments. They do not include eligible assignments in Privileged Identity Management, and they list a group as a member without expanding it.
- Role actions written as `allProperties/allTasks` are matched literally, not expanded to the actions they cover.
- `find-privileged-users` reads the list of privileged actions from a Microsoft Graph beta endpoint, which may change.
- Only the global Azure cloud is supported.

## Development

```bash
pip install -e ".[dev]"
pytest
```

The tests run against a fake Microsoft Graph client and need no tenant.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## License

Apache-2.0. See [LICENSE](LICENSE).

Built and maintained by Blue Lantern Security. To find out more about the company, visit [bluelanternsecurity.com](https://bluelanternsecurity.com).
