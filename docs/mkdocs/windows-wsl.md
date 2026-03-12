# Windows / WSL Notes

containd is not a native Windows firewall. For classroom and lab use on Windows, run it inside Docker Desktop with the WSL2 backend so the segmented traffic stays inside Docker's Linux VM.

## Recommended Setup

1. Install Docker Desktop.
2. Enable the WSL2 backend in Docker Desktop settings.
3. Open your WSL shell (`Ubuntu`, `Debian`, etc.), not PowerShell, for the starter scripts below.
4. Run the starter from that WSL shell:

```bash
curl -fsSLO https://raw.githubusercontent.com/tonylturner/containd/main/scripts/quickstart.sh
sh quickstart.sh
```

If you want a lab directory you can edit before first boot:

```bash
curl -fsSLO https://raw.githubusercontent.com/tonylturner/containd/main/scripts/bootstrap-starter.sh
sh bootstrap-starter.sh --dir containd-lab --no-start
```

## Important Notes

- Keep your lab files in the Linux filesystem when possible, for example under `~/labs/containd`, instead of `/mnt/c/...`. Docker and bind mounts are usually faster and more reliable there.
- Access the UI from Windows at `http://localhost:8080` after the stack starts.
- The starter compose runs the appliance as `root` inside the container because nftables, routing, and TUN operations require that across Docker runtimes.
- Docker defines the lab networks and interface attachments. containd enforces segmentation only for traffic that actually routes through the appliance.

## What To Do If Something Fails

- Confirm Docker Desktop is running and the WSL2 backend is enabled.
- Run `docker compose logs -f containd` from the same WSL shell you used to start the stack.
- If the quick-start ports are already in use, rerun `bootstrap-starter.sh` with custom port overrides such as:

```bash
sh bootstrap-starter.sh --dir containd-lab --no-start \
  --http-port 18080 \
  --https-port 18443 \
  --ssh-port 12222
```
