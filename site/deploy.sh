#!/usr/bin/env bash
# Deploys this static site to Cloudflare Pages with wrangler.
#
# Requirements: Node.js (for npx) and Cloudflare credentials, either
#   npx wrangler login                                  (interactive), or
#   CLOUDFLARE_API_TOKEN=... CLOUDFLARE_ACCOUNT_ID=...  (CI / non-interactive).
# The Pages project is created on first deploy if it does not exist.
#
# Usage:  site/deploy.sh               # project "the-river", branch main (production)
#         PROJECT=my-river site/deploy.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
npx wrangler pages deploy . --project-name "${PROJECT:-the-river}" --branch main
