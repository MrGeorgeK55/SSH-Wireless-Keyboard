# SSHWK - Secure SHell Wireless Keyboard

This project targets the `ESP32-S3 SuperMini` and turns it into a Wi-Fi managed
USB HID keyboard:

1. The board powers on.
2. If no saved config exists, it starts an AP named `SSHWK` at `10.10.10.1`.
3. You open the setup page, enter Wi-Fi and SSH credentials, and save.
4. The board reboots, joins your Wi-Fi, starts an SSH server, and enumerates as
   a USB keyboard on the host computer connected to its USB-C port.
5. Bytes received over SSH are translated into USB HID keyboard events.

Current firmware version: `v1.1`

## Features

- Provisioning AP:
  - SSID: `SSHWK`
  - IP: `10.10.10.1`
  - captive-portal style redirects for common probe URLs
- SSH keyboard bridge:
  - password authentication
  - stable SSH host key persisted in NVS
  - live SSH MOTD with firmware version and active layout
- USB HID keyboard output over the board's native USB-C port
- Runtime layout toggle:
  - default layout: `US`
  - alternate layout: `ES-MX/LATAM`
  - toggle with `Ctrl+A` inside the SSH session
- Session exit with `Ctrl+D`
- Readable terminal echo for special keys:
  - arrows, function keys, Home/End, Insert/Delete, Page Up/Page Down
- Factory reset button:
  - external button on `GPIO1` to `GND`
  - hold for at least 5 seconds
  - LED blinks red before wiping config and rebooting
 
> [!NOTE] 
> Some keys as CTRL, SHIFT or ALT cant be sent via SSH and other keys like F11 could not be sent due to limitations of the SSH you are using (PuTTY for example)

## Board Notes

The target board is the `ESP32-S3 SuperMini`.

References:

- Board page:
  https://www.espboards.dev/esp32/esp32-s3-super-mini/
- ESP32-S3 built-in USB / USB-Serial-JTAG:
  https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-guides/jtag-debugging/configure-builtin-jtag.html
- Arduino ESP32 USB API:
  https://docs.espressif.com/projects/arduino-esp32/en/latest/api/usb.html

Important hardware points:

- The USB keyboard data goes through the onboard USB-C connector.
- On ESP32-S3, the native USB data lines are:
  - `GPIO19` = `D-`
  - `GPIO20` = `D+`
- On this board those lines are already wired internally to the USB-C port, so
  you normally do not connect them manually.

## RGB LED Status

The onboard WS2812 LED on `GPIO48` is used as the primary status indicator.

- `white`: provisioning AP active
- `blue`: Wi-Fi connected
- `yellow`: Wi-Fi connected with weak signal
- `cyan`: SSH session active
- `blinking red`: factory reset in progress
- `pulsing blue`: booting
- `red`: error state

Hardware caveat from the board docs:

- the discrete red LED and the WS2812 share `GPIO48`
- they cannot be controlled independently

## Keyboard Behavior

The firmware uses Arduino ESP32 `USBHIDKeyboard`.

Handled input includes:

- printable characters
- Enter, Tab, Backspace
- `Ctrl+B` through `Ctrl+Z`
- arrows
- Home / End
- Insert / Delete
- Page Up / Page Down
- function keys supported by the terminal escape decoder

Inside the SSH session:

- `Ctrl+A` toggles the keyboard layout between `US` and `ES-MX/LATAM`
- `Ctrl+D` closes the SSH session

(Setting configurable)

## Security Notes

- The SSH password is stored as a SHA-256 hash in NVS.
- The SSH host key is persisted in NVS, so the host fingerprint remains stable
  across reboots.
- Authentication is password-only.

## Build Configuration

PlatformIO environment:

- environment: `esp32-s3-supermini`
- framework: `arduino`
- board: custom profile in `boards/esp32-s3-supermini-custom.json`
- upload protocol: `esptool`
- USB mode:
  - `ARDUINO_USB_MODE=0`
  - `ARDUINO_USB_CDC_ON_BOOT=0`

This project uses:

- `LibSSH-ESP32`
- Arduino `USBHIDKeyboard`
- Arduino `DNSServer`
- Arduino `WebServer`

## Flashing

Use the provided script:

```bash
cd /scripts/sshwk
./flash_sshwk.sh
```

What it does:

- builds the current firmware
- probes `/dev/ttyACM*` and `/dev/ttyUSB*`
- requires exactly one ESP32-S3 in ROM bootloader mode
- flashes that board

Useful options:

```bash
./flash_sshwk.sh --no-build
```

That skips the compile step and uploads the already built binary.

The script fails clearly if:

- no device is found
- more than one ESP32-S3 in bootloader mode is found
- the board is connected but not actually in bootloader mode

## Bootloader Mode

If flashing fails because the board is not in ROM download mode:

1. Hold `BOOT`
2. Tap `RST`
3. Keep holding `BOOT` for about 2 seconds
4. Release `BOOT`
5. Run `./flash_sshwk.sh`

## Provisioning Flow

If no valid config is stored, the board starts provisioning mode:

- connect to Wi-Fi SSID `SSHWK`
- open `http://10.10.10.1/`
- enter:
  - Wi-Fi SSID
  - Wi-Fi password
  - SSH username
  - SSH password

The board validates Wi-Fi before saving, then reboots into normal mode.

## Factory Reset Wiring

Wire a momentary pushbutton like this:

- one side to `GPIO1`
- one side to `GND`

The firmware uses `INPUT_PULLUP`, so pressed = logic low.
