#!/usr/bin/env bash
# Create .env from .env.example with random, policy-compliant secrets.
source "$(dirname "$0")/lib.sh"
ctl init-env
ctl validate
ok "Review .env (versions, ports, integrations) before running scripts/setup.sh"
