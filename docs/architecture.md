# containd Architecture

This document tracks the high-level architecture for containd as it evolves. It mirrors the agent spec and will be expanded as components land.

- Planes: data plane (`ngfw-engine`), control plane (`pkg/cp`), management plane (`ngfw-mgmt` + UI + CLI).
- Packaging targets: containers for lab, host systemd services, future Kubernetes workloads.

Further details will be refined as we implement each phase.
