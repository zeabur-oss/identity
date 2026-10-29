# Security policy

Report vulnerabilities privately through GitHub's "Report a vulnerability" (private
vulnerability reporting) on this repository. Do not open public issues for security problems.

## Alpha support

Zeabur Identity v0.1.1 is an alpha intended for evaluation on disposable, self-managed clusters.
Only the latest published alpha is eligible for security fixes. Fixes are delivered in a new
release; older alpha versions are not backported. There is no guaranteed response or patch
timeline. Upgrade to the latest alpha when a fix is published.

Breaking changes, including changes to Kubernetes resources, can occur between alpha releases.
There are no schema-migration, upgrade or rollback guarantees. Keep an independent cluster-admin
credential and a tested backup; see [operations](docs/operations/emergency-access.mdx).

Maintainers must enable GitHub private vulnerability reporting and confirm that the reporting
link is available before making an alpha release public.
