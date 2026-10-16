#!/bin/sh
# ar-sync.sh - Wazuh active response (Linux agent)
#
# Deploys *.move files from the agent's shared directory into
# active-response/bin, stripping the .move extension:
#
#   /var/ossec/etc/shared/test.sh.move  ->  /var/ossec/active-response/bin/test.sh
#
# A file is copied only when the target is missing or its SHA-256 differs.
# Copies go to a temporary file in bin first and are renamed into place,
# so a half-written script is never visible under its final name.
#
# Trigger from the manager API:
#   PUT /active-response?agents_list=<ids>   {"command": "!ar-sync.sh"}

# Extensions never deployed on Linux (Windows-only payloads in a mixed group).
SKIP_EXTENSIONS="exe cmd bat ps1 dll msi vbs"

# Seconds to wait for another ar-sync run to finish before giving up.
LOCK_WAIT=60

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

SELF=$(basename "$0")
BIN_DIR=$(cd "$(dirname "$0")" && pwd -P) || exit 1
WAZUH_HOME=$(cd "$BIN_DIR/../.." && pwd -P) || exit 1
SHARED_DIR="$WAZUH_HOME/etc/shared"
LOG_FILE="$WAZUH_HOME/logs/active-responses.log"
LOCK_DIR="$WAZUH_HOME/var/run/ar-sync.lock"
# Deployed files get the same group as bin (wazuh, or ossec on old installs).
BIN_GROUP=$(stat -c %G "$BIN_DIR" 2>/dev/null) || BIN_GROUP=wazuh

TMP_FILE=""
HAVE_LOCK=0

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') active-response/bin/$SELF: $*" >> "$LOG_FILE"
}

cleanup() {
    [ -n "$TMP_FILE" ] && rm -f "$TMP_FILE"
    [ "$HAVE_LOCK" -eq 1 ] && rm -rf "$LOCK_DIR"
}

# mkdir is atomic, so it works as a portable lock without flock.
try_lock() {
    if mkdir "$LOCK_DIR" 2>/dev/null; then
        echo $$ > "$LOCK_DIR/pid"
        HAVE_LOCK=1
        return 0
    fi
    pid=$(cat "$LOCK_DIR/pid" 2>/dev/null)
    if [ -n "$pid" ]; then
        kill -0 "$pid" 2>/dev/null && return 1
    elif [ -z "$(find "$LOCK_DIR" -maxdepth 0 -mmin +10 2>/dev/null)" ]; then
        # No pid yet: the owner may have just created the lock.
        return 1
    fi
    log "Removing stale lock $LOCK_DIR"
    rm -rf "$LOCK_DIR"
    return 1
}

acquire_lock() {
    waited=0
    while ! try_lock; do
        [ "$waited" -ge "$LOCK_WAIT" ] && return 1
        sleep 1
        waited=$((waited + 1))
    done
    return 0
}

sha256() {
    sha256sum < "$1" | cut -d' ' -f1
}

is_skipped_extension() {
    case "$1" in
        *.*) ext=$(echo "${1##*.}" | tr 'A-Z' 'a-z') ;;
        *) return 1 ;;
    esac
    for skip in $SKIP_EXTENSIONS; do
        [ "$ext" = "$skip" ] && return 0
    done
    return 1
}

# Sets RESULT to the outcome: deployed, updated, current, skipped or failed.
sync_file() {
    src=$1
    name=$(basename "$src")
    target_name=${name%.move}
    dst="$BIN_DIR/$target_name"

    case "$target_name" in
        ""|.*)
            log "SKIPPED $name: invalid target name"
            RESULT=skipped; return ;;
    esac
    if [ "$target_name" = "$SELF" ]; then
        log "SKIPPED $name: the mover does not replace itself"
        RESULT=skipped; return
    fi
    if is_skipped_extension "$target_name"; then
        RESULT=skipped; return
    fi
    if [ -L "$src" ] || [ ! -f "$src" ]; then
        log "SKIPPED $name: not a regular file"
        RESULT=skipped; return
    fi
    if [ -d "$dst" ]; then
        log "FAILED $name: $dst is a directory"
        RESULT=failed; return
    fi

    src_hash=$(sha256 "$src")
    if [ -f "$dst" ] && [ "$(sha256 "$dst")" = "$src_hash" ]; then
        # Keep permissions correct even when the content is current.
        chown "root:$BIN_GROUP" "$dst" 2>/dev/null
        chmod 750 "$dst" 2>/dev/null
        RESULT=current; return
    fi

    if [ -e "$dst" ]; then outcome=updated; else outcome=deployed; fi

    TMP_FILE=$(mktemp "$BIN_DIR/.ar-sync.XXXXXX") || {
        log "FAILED $name: cannot create temporary file in $BIN_DIR"
        TMP_FILE=""
        RESULT=failed; return
    }
    if ! cat "$src" > "$TMP_FILE"; then
        log "FAILED $name: copy error"
        rm -f "$TMP_FILE"; TMP_FILE=""
        RESULT=failed; return
    fi
    # A mismatch means the agent rewrote the file during the copy; the next run retries.
    if [ "$(sha256 "$TMP_FILE")" != "$src_hash" ]; then
        log "FAILED $name: file changed while copying, will retry on next run"
        rm -f "$TMP_FILE"; TMP_FILE=""
        RESULT=failed; return
    fi
    if ! chown "root:$BIN_GROUP" "$TMP_FILE" || ! chmod 750 "$TMP_FILE" \
        || ! mv -f "$TMP_FILE" "$dst"; then
        log "FAILED $name: cannot install $dst"
        rm -f "$TMP_FILE"; TMP_FILE=""
        RESULT=failed; return
    fi
    TMP_FILE=""

    log "$(echo "$outcome" | tr 'a-z' 'A-Z') $target_name sha256=$src_hash"
    RESULT=$outcome
}

trap cleanup EXIT
trap 'exit 1' INT TERM HUP

# wazuh-execd writes one JSON line to stdin; this mover does not need it.
if [ ! -t 0 ]; then
    read -r _input || :
fi

log "Starting"

if ! acquire_lock; then
    log "Another ar-sync run is still active after ${LOCK_WAIT}s, exiting"
    exit 0
fi

deployed=0 updated=0 current=0 skipped=0 failed=0
for src in "$SHARED_DIR"/*.move; do
    # An unmatched glob stays literal.
    [ -e "$src" ] || [ -L "$src" ] || continue
    sync_file "$src"
    case "$RESULT" in
        deployed) deployed=$((deployed + 1)) ;;
        updated)  updated=$((updated + 1)) ;;
        current)  current=$((current + 1)) ;;
        skipped)  skipped=$((skipped + 1)) ;;
        *)        failed=$((failed + 1)) ;;
    esac
done

log "Ended: deployed=$deployed updated=$updated current=$current skipped=$skipped failed=$failed"
exit 0
