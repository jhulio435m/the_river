# The River — project website

Static site for The River (plain HTML + CSS + a little vanilla JS). No build
step, no external fonts, CDNs, trackers or analytics.

```
site/
  index.html      landing page with a mock of the client chat screen
  download.html   per-platform download and install steps (Windows, Linux, Termux)
  security.html   security model and protocol v2 summary
  guide.html      client/admin commands, environment variables, server setup
  assets/
    style.css     shared styles (BBS palette: black, #0000A8 blue, magenta, lime, white)
    site.js       ES/EN toggle (saved in localStorage), terminal animation, footer clock
    favicon.svg
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

## Deployment

`.github/workflows/pages.yml` publishes this directory to GitHub Pages on every
push to `main` that touches `site/**` (or on manual dispatch). In the
repository settings, *Pages → Build and deployment → Source* must be set to
**GitHub Actions**.
