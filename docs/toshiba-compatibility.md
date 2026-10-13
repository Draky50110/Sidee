# Toshiba VIDAA authentication compatibility

Reported target, 13 October 2026: Toshiba Z670, firmware
`V0000.09.60N.Q0615`, extended version `X0003.W01.Y01.J01`, minor version
`N.Q0615.9.61.00-a20260727u`. The reporter confirms that the official VIDAA app
pairs and controls the TV. Sidee reports MQTT `rc=5` before displaying its PIN.
No local pairing or installation on this model has been verified yet.

Firmware version alone does not identify the required authentication algorithm.
MQTT 3.1.1 code 5 is an authorization refusal after the connection reaches the
TV. Discovery and official remote control are useful evidence, but neither
confirms that this model accepts Sidee's app-install action.

## Implemented behavior

- Keep modern authentication first for existing Hisense compatibility. After
  an explicit authentication refusal (4 or 5), try static, middle, and RemoteNOW
  profiles once each. Close each rejected connection before opening another.
  Stop on TLS, network, timeout, or other broker errors.
- Use the saved profile first when pairing the same TV again. Reuse its client
  identity; do not reuse a different TV's saved pairing identity.
- On static firmware, request TV state to trigger the PIN. If no PIN notification
  arrives, try the documented VIDAA app-connect request. PIN acceptance remains
  mandatory for saving a new pairing.
- Request tokens after PIN acceptance. Only a static profile with no token
  response can proceed without tokens, and it must answer a fresh app-list
  request. Invalid or incomplete token responses remain errors.
- Preserve the accepted profile, client ID, and username on reconnection and
  token refresh. Static pairings have no token expiry or automatic refresh.
- If a saved static pairing is rejected, ask for a new PIN. Do not change
  authentication profiles while running an installation.
- Accept VIDAA identifiers in a Toshiba UPnP descriptor without requiring the
  manufacturer to be Hisense. Toshiba branding alone does not identify VIDAA.

## Trial on the reported TV

Extract the experimental Windows ZIP in a new folder, open `start-windows.bat`,
find the TV, and request a code. Enter only the PIN displayed on that TV. If
pairing succeeds, install one app and check the returned app list and launcher.
Close and reopen Sidee to check that the saved pairing reconnects without a new
PIN. Firmware updates and TV restarts should be checked separately.

If connection still fails, collect the authentication profile/result lines
printed by Sidee, the exact dashboard error, and whether a PIN appeared. Do not
share `session.json`, PINs, tokens, or dashboard access links. Successful pairing
alone should not be reported as confirmed tile-install support.

## Protocol references

- [hisense_vidaa credential profiles](https://github.com/stevene1919/hisense_vidaa/blob/main/custom_components/hisense_vidaa/crypto.py)
- [vidaa-control Toshiba static fallback](https://github.com/Lucent-/vidaa-control/blob/main/vidaa/client.py)
- [pyvidaa static PIN and tokenless pairing](https://github.com/warrenrees/pyvidaa/blob/master/pyvidaa/client.py)
- [pyvidaa documented MQTT topics](https://github.com/warrenrees/pyvidaa/blob/master/pyvidaa/topics.py)

Offline tests use simulated TV responses and independent credential vectors.
They validate fallback, PIN confirmation, session persistence, refresh behavior,
and the browser flow; they cannot establish compatibility with this firmware.
