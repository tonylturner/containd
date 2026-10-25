# Reserved management smoke

From the worktree root:

```sh
bash scripts/smoke-mgmt-reservation.sh
```

Needs Go, Docker Compose, jq and Docker network access for Alpine/curl images.
Builds the current Go binary into a lane-specific minimal runtime image (no UI
build), starts eight private zone networks, one fresh data volume, two exact
reserved-source clients and one non-source client. Publishes **no host ports**.
All API traffic originates inside those clients. It never connects to or changes
any `rangerdanger-*` container.

Checks health/login, an all-access-off commit, exact-source-only reachability,
substrate rejection, and deterministic NIC-renumber restart with no fault. The
fixture entrypoint renames only its own container NICs before starting containd.
The script then injects a legacy custom-row/listener conflict directly into its
private config DB (the API correctly refuses such edits), restarts, and requires
reserved health/login, one boot-fault event and no engine ruleset apply, including
a second check after several replay intervals. It records the absent containd
firewall table (Docker DNS NAT chains remain); fault mode is not fail-closed
enforcement. Finally, safe commit and factory reset must each clear the fault; reset leaves exactly one unaddressed
reserved binding. Unsafe address changes are rejected
at candidate staging, before an invalid commit can exist; store tests separately
prove legacy unsafe candidates cannot be promoted.

The unique project is torn down (including its own volume/networks) on exit;
scratch, image and diagnostic logs stay under the lane's ignored `build/`.
Default subnets are `10.217.0.0/24` through `10.217.7.0/24`; set
`MGMT_SMOKE_PREFIX=10.218` if those are already allocated. Never reuse the
RangerDanger subnets or ports. A subnet collision is an error, not permission to
remove an existing network.
