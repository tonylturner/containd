# Reserved management smoke

From the repository root:

```sh
bash scripts/smoke-mgmt-reservation.sh
```

Needs Go, Docker Compose, jq and Docker network access for Alpine/curl images.
Builds the local Go binary into a test-specific minimal runtime image (no UI
build), starts eight private zone networks, one fresh data volume, two exact
reserved-source clients and one non-source client. Publishes **no host ports**.
All API traffic originates inside those clients. It never connects to or changes
any `rangerdanger-*` container.

Checks health/login, an all-access-off commit, exact-source-only reachability,
substrate rejection, and deterministic NIC-renumber restart with no fault. The
fixture entrypoint renames only its own container NICs before starting containd.
The script then injects a legacy custom-row/listener conflict directly into its
private config DB (the API correctly refuses such edits), restarts, and requires
reserved health/login, one boot-fault event and an applied minimal recovery
ruleset. Two additional isolated transit peers route through the appliance:
a narrow normal-mode allow proves new TCP works, fault-mode restart must drop
new TCP, and a safe commit must restore it. A second recovery check after replay
intervals requires the same applied timestamp (no apply spam). Engine status and
the operator API must confirm the actual recovery ruleset. Factory reset also
clears recovery and leaves one unaddressed reserved binding. Finally a stored,
valid but unbindable HTTPS address must produce a visible optional-listener boot
fault without removing reserved HTTP access. The fixture uses SSH port 18222
inside its namespace; it publishes no ports. Unsafe address changes are rejected
at candidate staging, before an invalid commit can exist; store tests separately
prove legacy unsafe candidates cannot be promoted.

The unique project is torn down (including its own volume/networks) and its
Docker image is removed on exit; scratch files and diagnostic logs remain
under the repository's ignored `build/mgmt-reservation.*` directory. See
[Reserved Management Path](../../docs/mkdocs/management-reservation.md) for
operator configuration.
Default subnets are `10.217.0.0/24` through `10.217.7.0/24`; set
`MGMT_SMOKE_PREFIX=10.218` if those are already allocated. Never reuse the
RangerDanger subnets or ports. A subnet collision is an error, not permission to
remove an existing network.

The two transit bridges disable masquerading rather than using Docker's
`internal` host filter, which drops routed cross-subnet frames even when the
appliance allows them. The fixture removes default routes in the appliance and
both transit peers, and installs only explicit peer routes via the appliance;
there is no outside route or direct cross-network peer attachment. The other
six bridges remain Docker-internal.
