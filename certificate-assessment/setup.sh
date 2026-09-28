#!/bin/sh
# This shell entrypoint requires PowerShell 7.2+ (pwsh).
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CONFIG=
MODE=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --config)
            [ "$#" -ge 2 ] && [ -n "$2" ] || { echo 'A config path is required.' >&2; exit 2; }
            [ -z "$CONFIG" ] || { echo 'Use --config once.' >&2; exit 2; }
            CONFIG=$2
            shift 2
            ;;
        --preview|--apply)
            [ -z "$MODE" ] || { echo 'Choose one of --preview or --apply.' >&2; exit 2; }
            case "$1" in --preview) MODE=-Preview ;; --apply) MODE=-Apply ;; esac
            shift
            ;;
        --help|-h)
            echo 'Usage: setup.sh --config PATH [--preview | --apply]'
            echo 'Requires PowerShell 7.2+ (pwsh). Default: local plan, no sign-in.'
            exit 0
            ;;
        *) echo 'Unknown argument. Use --help.' >&2; exit 2 ;;
    esac
done
[ -n "$CONFIG" ] || { echo 'Use --config PATH.' >&2; exit 2; }
command -v pwsh >/dev/null 2>&1 || { echo 'Install PowerShell 7.2+ (pwsh) before setup.' >&2; exit 127; }
if [ -n "$MODE" ]; then
    exec pwsh -NoProfile -File "$SCRIPT_DIR/Sync-AssessmentApp.ps1" -Config "$CONFIG" "$MODE"
fi
exec pwsh -NoProfile -File "$SCRIPT_DIR/Sync-AssessmentApp.ps1" -Config "$CONFIG"
