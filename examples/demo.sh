#!/usr/bin/env bash
#
# scrubline demo — pipe a messy log through scrubline and watch secrets vanish
# while UUIDs, commit SHAs, and pod names are left alone.
#
# Record it with:  asciinema rec -c ./examples/demo.sh scrubline.cast
# Override the binary with:  SCRUBLINE=./target/release/scrubline ./examples/demo.sh

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
LOG="$DIR/messy.log"
SCRUB="${SCRUBLINE:-scrubline}"

say() { printf '\n\033[1;36m# %s\033[0m\n' "$1"; }

say "the raw log — secrets in plain sight"
cat "$LOG"

say "piped through scrubline — secrets gone, noise untouched"
"$SCRUB" <"$LOG"

say "what got redacted (summary on stderr)"
"$SCRUB" --stats <"$LOG" >/dev/null
