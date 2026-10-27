# sms-otp-inbox

A tiny self-hosted inbox for one-time codes. My SIM lives in another phone, so
the OTPs my bank and accounts send end up there. That phone runs
[Incoming SMS to URL forwarder](https://github.com/bogkonstantin/android_income_sms_gateway_webhook),
which POSTs each OTP SMS here. A page behind a login shows the latest code in
large type (tap to copy), refreshing every few seconds, plus whether the phone
is still alive.

**Demo:** https://otp-demo.anishsheela.com. It shows made-up messages, with a
new code every few minutes, and accepts nothing.

- **`app.py`**: Python standard library only, SQLite storage. Messages are
  deleted after 7 days.
- **`index.html`**: the page, styled like my other personal apps.

## Endpoints

| Path | Who | Auth |
|---|---|---|
| `POST /hook` | the phone, one SMS per request | HMAC-SHA256 of the raw body in `X-Signature` (the app's "Sign with HMAC-SHA-256" option) |
| `POST /heartbeat/<token>` | the phone's heartbeat ping | the token in the path. The ping is an empty, unsigned POST, so the URL is the only place a credential can go. A leaked token can only fake "phone alive" |
| `GET /`, `GET /api/messages` | you | **none in the app.** Put it behind a login at the reverse proxy. I use nginx `auth_request` with oauth2-proxy and Kanidm |

The OTP is pulled out of the message text. A message only counts as containing
a code when it also contains a keyword such as OTP, code or verification. That
rule exists so a balance or an order number isn't shown as a code. Amounts and
card or account suffixes are skipped even when they appear next to the keyword.

The page loads fonts from `/fonts/` (Archivo, IBM Plex Mono). Serve them there
or the page falls back to system fonts.

## Running it

```bash
SMS_HMAC_SECRET=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n') \
SMS_HEARTBEAT_TOKEN=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n') \
SMS_DB=./sms.db python3 app.py      # listens on 127.0.0.1:8776
```

| Variable | Default | |
|---|---|---|
| `SMS_HMAC_SECRET` | required | Shared with the phone app. The server refuses to start without it |
| `SMS_HEARTBEAT_TOKEN` | required, 16+ chars | Last part of the heartbeat URL |
| `SMS_HEARTBEAT_MINUTES` | `5` | Must match the app's heartbeat interval. The page shows the phone as late after 2 missed pings and not reporting after 6 |
| `SMS_DB` | `/var/lib/sms-inbox/sms.db` | |
| `SMS_PORT` | `8776` | |
| `SMS_KEEP_DAYS` | `7` | |
| `SMS_DEMO` | unset | `1` runs the public demo: no secrets and no database are needed, `/api/messages` returns a made-up inbox generated from the clock, and every POST is refused |

Tests: `python3 -m unittest test_app`. Deploy: copy `.deploy.env.example` to
`.deploy.env`, fill it in, and run `./deploy.sh` (rsync plus a systemd restart;
the unit and vhost are defined elsewhere).

## Phone setup

Forwarding rule:

- **Sender:** `*`
- **SIM slot:** the SIM whose messages you want, so the phone owner's own SMS
  never leave their phone
- **Text filter:** `(?i)otp|code|verification|password|pin`
- **URL:** `https://<your host>/hook`
- **Sign with HMAC-SHA256:** on, using `SMS_HMAC_SECRET`
- **Template:**

```json
{
  "from": "%from%",
  "text": "%text%",
  "sentStamp": %sentStamp%,
  "receivedStamp": %receivedStamp%,
  "sim": "%sim%",
  "battery": %battery%,
  "power": "%power%",
  "network": "%network%",
  "version": "%version%"
}
```

In the app's Settings, turn on Heartbeat with
`https://<your host>/heartbeat/<SMS_HEARTBEAT_TOKEN>`. Turn off RCS in Google
Messages, because RCS messages never reach SMS forwarders.
