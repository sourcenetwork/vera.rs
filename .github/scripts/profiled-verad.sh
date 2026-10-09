#!/usr/bin/env bash
set -euo pipefail
umask 077
: "${VERA_PROFILE_BINARY:?}" "${VERA_PROFILE_ROOT:?}" "${VERA_PROFILE_LIBRARY?}"

selected=false
previous=
for argument in "$@"; do
    if [[ "$previous" == --data-dir && "${argument##*/}" == node3 ]]; then
        selected=true
    fi
    previous=$argument
done

# Keep the original child PID and inherited RPC descriptor; profile only its first boot.
if [[ "$selected" == true ]] && mkdir "$VERA_PROFILE_ROOT/claimed" 2>/dev/null; then
    printf '%s\n' "$$" > "$VERA_PROFILE_ROOT/pid"
    export LD_PRELOAD="$VERA_PROFILE_LIBRARY"
    export DUMP_HEAPTRACK_OUTPUT="$VERA_PROFILE_ROOT/heap.raw"
fi
exec "$VERA_PROFILE_BINARY" "$@"
