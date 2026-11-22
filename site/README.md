# The River — project website

Static site for The River (plain HTML + CSS + a little vanilla JS). No build
step, no external fonts, CDNs, trackers or analytics.

```
site/
  index.html      landing page: animated illustration of the client + "Demo real" videos
  download.html   per-platform download and install steps (Windows, Linux, Termux)
  security.html   security model and protocol v2 summary
  guide.html      client/admin commands, environment variables, server setup
  assets/
    style.css     shared styles (BBS palette: black, #0000A8 blue, magenta, lime, white)
    site.js       ES/EN toggle (saved in localStorage), terminal animation, footer clock
    favicon.svg
  media/          real screen recordings of the client (mp4 + webm + jpg poster)
  robots.txt      crawler policy and sitemap location
  sitemap.xml     public page URLs at theriver.soryntel.com
  _headers        Cloudflare Pages headers (CSP, nosniff, referrer, cache)
  deploy.sh       Cloudflare Pages deploy with wrangler
```

## Preview locally

```bash
python3 -m http.server -d site 8099
# open http://localhost:8099/
```

Any static file server works; the pages use relative links only, so opening
`site/index.html` directly from disk also works.

## Content rules

- Spanish is the primary language. Every translatable block exists twice, as
  `lang="es"` and `lang="en"` siblings; CSS hides the one that does not match
  `<html lang>`, and `site.js` switches it. Without JavaScript the site shows
  Spanish. Page titles live in `data-title-es` / `data-title-en` on `<html>`.
- Never put a real `.onion` address, key, password or any other secret on the
  site. Use placeholders such as `<tu-direccion>.onion`.
- Clients only need `THE_RIVER_ONION` (protocol v2). Do not document
  `THE_RIVER_AES_KEY` as a client setting: it is server-only.
- Keep the client's visual identity: hard edges, monospace, blue header/footer
  bars, magenta for "me", lime for peers, `user-->` prompt. Don't use magenta
  for small text on the blue background (contrast is only ~4.2:1).
- Animations must stay disabled under `prefers-reduced-motion: reduce`.
- No inline `<script>`, `<style>` or `style="..."` attributes and no third-party
  URLs for scripts, styles, images or media: the CSP in `_headers` only allows
  `'self'`.

## Demo videos (`media/`)

The clips in the "Demo real" section of `index.html` (and the one in
`guide.html`) are real screen recordings of `the_river_server`,
`the_river_admin` and two `the_river_client` windows. They are produced by
`the_river_cpp/scripts/demo/record_demo.sh` (Xvfb + xdotool + ffmpeg; Tor is
replaced by a local SOCKS5 shim) — see `the_river_cpp/scripts/demo/README.md`.
Never replace them with mock-ups or edited composites.

| File | What it shows |
| --- | --- |
| `admin.*` | admin console: login, `/newuser` (one-time key), `/accounts` |
| `login.*` | client start, ES button, login with the one-time key, mandatory first-access change |
| `chat.*` | alice and bob in the room, `Tab` nickname completion, `↑` history |
| `private.*` | `/fingerprint` on both sides, `/msg` and `/r` (E2E `[PM]` lines) |
| `attachment.*` | Attach → zenity picker → `[IMG]` offer → bob previews the image |

To refresh them: `the_river_cpp/scripts/demo/record_demo.sh --build` (writes
straight into `site/media/`). Videos are `<video muted loop playsinline
preload="metadata">` with an mp4 (H.264) source first and webm (VP9) second;
`site.js` plays them only while at least half visible and never under
`prefers-reduced-motion` (then they show the poster and native controls).
Keep each clip short (10–30 s) and the folder small (currently ~2.4 MB).

## Deployment

### Release links

The download buttons use GitHub's `/releases/latest/download/<asset>` URLs.
They follow the newest published release automatically when it contains assets
with the same filenames. Creating a release does not change the site's HTML or
redeploy GitHub Pages. The current site describes the protocol 2 prototype, so
keep the compatibility note visible until that protocol has a published release.

### Cloudflare Pages

```bash
npx wrangler login            # or export CLOUDFLARE_API_TOKEN + CLOUDFLARE_ACCOUNT_ID
site/deploy.sh                # = npx wrangler pages deploy . --project-name the-river --branch main
PROJECT=other-name site/deploy.sh
```

`deploy.sh` uploads the whole `site/` folder (including this README and the
script itself, which are harmless). `_headers` is applied by Cloudflare Pages:
a `'self'`-only Content-Security-Policy, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, a minimal
`Permissions-Policy`, and cache lifetimes for `/media/*` (30 days) and
`/assets/*` (7 days). Files are not fingerprinted, so rename a clip when you
re-record it, or lower those values.

### GitHub Pages

`.github/workflows/pages.yml` publishes this directory to GitHub Pages on every
push to `main` that touches `site/**` (or on manual dispatch). In the
repository settings, *Pages → Build and deployment → Source* must be set to
**GitHub Actions**.
