#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIO_BIN="$ROOT_DIR/.venv/bin/pio"
PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
PIO_CORE_DIR="$ROOT_DIR/.pio-core"
ESPTOOL_PY="$PIO_CORE_DIR/packages/tool-esptoolpy/esptool.py"
ENV_NAME="esp32-s3-supermini"
BUILD_DIR="$ROOT_DIR/.pio/build/$ENV_NAME"
FIRMWARE_BIN="$BUILD_DIR/firmware.bin"

usage() {
  cat <<'EOF'
Usage: ./flash_sshwk.sh [--no-build|-uo]

Builds the SSHWK firmware and flashes exactly one ESP32-S3 that is already in
ROM download mode.

Behavior:
  - Fails if no ESP32-S3 in bootloader mode is found
  - Fails if more than one ESP32-S3 in bootloader mode is found
  - Prints a hint if a board seems connected but is not in bootloader mode

Options:
  --no-build   Skip the PlatformIO build step and use the existing firmware.bin
  -uo          Alias for --no-build
  -h, --help   Show this help
EOF
}

log() {
  printf '[flash_sshwk] %s\n' "$*"
}

die() {
  printf '[flash_sshwk] ERROR: %s\n' "$*" >&2
  exit 1
}

list_candidate_ports() {
  all_ports=()
  shopt -s nullglob
  for port in /dev/ttyACM* /dev/ttyUSB*; do
    [[ -e "$port" ]] || continue
    all_ports+=("$port")
  done
  shopt -u nullglob
}

print_port_snapshot() {
  if ((${#all_ports[@]} == 0)); then
    printf '[flash_sshwk] Serial ports: none\n' >&2
    return
  fi

  printf '[flash_sshwk] Serial ports:\n' >&2
  for port in "${all_ports[@]}"; do
    [[ -e "$port" ]] || continue
    printf '  - %s\n' "$port" >&2
  done
}

build_firmware=true
while (($#)); do
  case "$1" in
    --no-build|-uo)
      build_firmware=false
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ -x "$PIO_BIN" ]] || die "PlatformIO not found at $PIO_BIN"
[[ -x "$PYTHON_BIN" ]] || die "Python not found at $PYTHON_BIN"
[[ -f "$ESPTOOL_PY" ]] || die "esptool.py not found at $ESPTOOL_PY"

if [[ "$build_firmware" == true ]]; then
  log "Building firmware for $ENV_NAME"
  PLATFORMIO_CORE_DIR="$PIO_CORE_DIR" "$PIO_BIN" run -e "$ENV_NAME"
else
  [[ -f "$FIRMWARE_BIN" ]] || die "firmware not found at $FIRMWARE_BIN; run without --no-build first"
fi

list_candidate_ports

declare -a esp_ports=()

probe_port() {
  local port="$1"
  local output
  if output="$("$PYTHON_BIN" "$ESPTOOL_PY" --chip esp32s3 --port "$port" --baud 115200 chip_id 2>&1)"; then
    if grep -q 'Chip is ESP32-S3' <<<"$output"; then
      esp_ports+=("$port")
    fi
  fi
}

if ((${#all_ports[@]} > 0)); then
  log "Probing serial ports for ESP32-S3 bootloader"
  for port in "${all_ports[@]}"; do
    [[ -e "$port" ]] || continue
    probe_port "$port"
  done
fi

if ((${#esp_ports[@]} == 0)); then
  if lsusb 2>/dev/null | grep -qi '303a:1001'; then
    print_port_snapshot
    die "an Espressif USB device is visible, but it is running normal firmware mode ('USB JTAG/serial debug unit'), not the ROM bootloader. Hold BOOT, tap RST, keep BOOT held for about 2 seconds, release BOOT, then run this script again."
  fi
  if lsusb 2>/dev/null | grep -qi '303a:'; then
    print_port_snapshot
    die "an Espressif USB device is visible, but no ESP32-S3 ROM bootloader responded on the available serial ports. Re-enter download mode and retry."
  fi
  print_port_snapshot
  die "no ESP32-S3 device was found. Reconnect the board and put it into ROM download mode before retrying."
fi

if ((${#esp_ports[@]} > 1)); then
  printf '[flash_sshwk] ERROR: more than one ESP32-S3 in bootloader mode was found:\n' >&2
  for port in "${esp_ports[@]}"; do
    printf '  - %s\n' "$port" >&2
  done
  printf '[flash_sshwk] Disconnect extra boards and retry.\n' >&2
  exit 1
fi

selected_port="${esp_ports[0]}"
log "Found exactly one ESP32-S3 bootloader on $selected_port"

log "Flashing firmware"
PLATFORMIO_CORE_DIR="$PIO_CORE_DIR" "$PIO_BIN" run -e "$ENV_NAME" -t upload --upload-port "$selected_port"

log "Flash completed successfully"
