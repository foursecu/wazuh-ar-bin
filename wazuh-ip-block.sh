#!/bin/sh
# wazuh-ip-block.sh - Linux counterpart of wazuh-ip-block.ps1
#
# Reads one line of Wazuh active-response JSON from STDIN and blocks or
# unblocks an IP address.
#
#   Manual API mode : parameters.extra_args = ["block"|"add"|"unblock"|"delete", "<ip>"]
#   Native AR mode  : command = add|delete, parameters.alert.data.srcip
#
# Portable POSIX sh. It needs only sed, grep, tr, head, id and date, plus one
# firewall tool.
#
# The script first finds out WHICH firewall this machine is really using (a
# tool that is installed but not running or not active is skipped), then uses
# the matching commands. Order of detection:
#   1. firewalld  - "firewall-cmd --state" says running   -> rich rule (inbound)
#   2. ufw        - "ufw status" says Status: active      -> deny in + deny out
#   3. iptables   - iptables/ip6tables answers a probe    -> INPUT + OUTPUT DROP
#   4. nftables   - nft answers a probe                   -> own table "inet wazuh_ar"
# Before it touches anything it checks that every command it needs exists and
# that it runs as root. After every change it reads the firewall back to
# confirm the result, and logs what the tool said when something goes wrong.


#PUT /active-response?agents_list=???
#{
#  "command": "!wazuh-ip-block.sh",
#  "arguments": ["block", "1.1.1.1"]
#}

#PUT /active-response?agents_list=???
#{
#  "command": "!wazuh-ip-block.sh",
#  "arguments": ["unblock", "1.1.1.1"]
#}



PATH="$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

SCRIPT_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd) || SCRIPT_DIR=/var/ossec/active-response/bin
LOG_FILE="$SCRIPT_DIR/wazuh-ip-block.log"

log() {
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" "$*" >> "$LOG_FILE" 2>/dev/null
    return 0
}

fail() {
    log "ERROR: $*"
    exit 1
}

have() {
    command -v "$1" >/dev/null 2>&1
}

first_line() {
    printf '%s\n' "$1" | head -n 1
}

# ---------------------------------------------------------------------------
# 1. Required commands exist, and we are root
# ---------------------------------------------------------------------------

for _cmd in sed grep tr head id date; do
    have "$_cmd" || fail "required command not found: $_cmd"
done

[ "$(id -u)" = "0" ] || fail "must run as root (uid $(id -u))"

# ---------------------------------------------------------------------------
# 2. Read the Wazuh message (one JSON line on STDIN)
# ---------------------------------------------------------------------------

IFS= read -r INPUT || true
[ -n "$INPUT" ] || fail "Empty input"
log "INPUT: $INPUT"

json_value() {
    printf '%s\n' "$INPUT" | grep -o "\"$1\" *: *\"[^\"]*\"" | head -n 1 | sed 's/.*: *"//; s/"$//'
}

COMMAND=$(json_value command)
[ -n "$COMMAND" ] || fail "Missing command"

# first two elements of extra_args, kept exactly as written (spaces included)
extra_arg() {
    printf '%s\n' "$INPUT" \
        | sed -n "s/^.*\"extra_args\" *: *\[ *\"\([^\"]*\)\" *, *\"\([^\"]*\)\".*\$/\\$1/p" \
        | head -n 1
}

ARG_OP=$(extra_arg 1)
ARG_IP=$(extra_arg 2)

if [ -n "$ARG_OP" ] && [ -n "$ARG_IP" ]; then
    case $(printf '%s' "$ARG_OP" | tr '[:upper:]' '[:lower:]') in
        add|block)      OPERATION=add ;;
        delete|unblock) OPERATION=delete ;;
        *) fail "Invalid extra_args operation: $ARG_OP" ;;
    esac
    RAW_IP=$ARG_IP
    log "Manual API mode: operation=$OPERATION IP=$RAW_IP"
else
    OPERATION=$(printf '%s' "$COMMAND" | tr '[:upper:]' '[:lower:]')
    RAW_IP=$(json_value srcip)
    [ -n "$RAW_IP" ] || fail "Missing parameters.alert.data.srcip"
    log "Native Wazuh AR mode: command=$OPERATION IP=$RAW_IP"
fi

case $OPERATION in
    add|delete) ;;
    *) fail "Unsupported command: $OPERATION" ;;
esac

# ---------------------------------------------------------------------------
# 3. Validate the IP (it can come from log data, so be strict)
# ---------------------------------------------------------------------------

valid_ipv4() {
    printf '%s\n' "$1" | grep -Eq '^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$' || return 1
    _oldifs=$IFS
    IFS=.
    set -f
    set -- $1
    set +f
    IFS=$_oldifs
    for _octet in "$@"; do
        [ "$_octet" -le 255 ] || return 1
    done
    return 0
}

valid_ipv6() {
    printf '%s\n' "$1" | grep -Eq '^[0-9A-Fa-f:.]{2,45}$' || return 1
    case $1 in
        *:*:*) return 0 ;;
    esac
    return 1
}

IP=$(printf '%s' "$RAW_IP" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | tr '[:upper:]' '[:lower:]')

# an IPv4-mapped IPv6 address (::ffff:1.2.3.4) is really an IPv4 client
case $IP in
    ::ffff:*.*.*.*) IP=${IP#::ffff:} ;;
esac

if valid_ipv4 "$IP"; then
    FAMILY=4
    case $IP in
        0.0.0.0|127.*) fail "Invalid or unsafe IP address: $RAW_IP" ;;
    esac
elif valid_ipv6 "$IP"; then
    FAMILY=6
    case $IP in
        ::|::1) fail "Invalid or unsafe IP address: $RAW_IP" ;;
    esac
else
    fail "Invalid or unsafe IP address: $RAW_IP"
fi

# ---------------------------------------------------------------------------
# 4. Detect which firewall this machine is using
#    (the command must exist AND the firewall must be running / answer a probe)
# ---------------------------------------------------------------------------

IPT=""
IPT_W=""
BACKEND=""

detect_backend() {
    # 1) firewalld: installed AND running
    if have firewall-cmd; then
        _out=$(firewall-cmd --state 2>&1)
        if [ "$_out" = "running" ]; then
            BACKEND=firewalld
            return 0
        fi
        log "firewall-cmd found but firewalld is not running ($(first_line "$_out"))"
    else
        log "firewall-cmd not found"
    fi

    # 2) ufw: installed AND active
    if have ufw; then
        _out=$(LC_ALL=C ufw status 2>&1)
        case $_out in
            "Status: active"*)
                BACKEND=ufw
                return 0
                ;;
        esac
        log "ufw found but it is not active ($(first_line "$_out"))"
    else
        log "ufw not found"
    fi

    # 3) iptables / ip6tables: installed AND answers a read-only probe
    if [ "$FAMILY" = 6 ]; then _tool=ip6tables; else _tool=iptables; fi
    if have "$_tool"; then
        if "$_tool" -w -L -n >/dev/null 2>&1; then
            IPT=$_tool
            IPT_W="-w"
            BACKEND=iptables
            return 0
        fi
        _out=$("$_tool" -L -n 2>&1) && { IPT=$_tool; BACKEND=iptables; return 0; }
        log "$_tool exists but its probe failed: $(first_line "$_out")"
    else
        log "$_tool not found"
    fi

    # 4) nftables: installed AND answers a read-only probe
    if have nft; then
        _out=$(nft list tables 2>&1) && { BACKEND=nft; return 0; }
        log "nft exists but its probe failed: $(first_line "$_out")"
    else
        log "nft not found"
    fi
    return 1
}

# --- firewalld (rich rule in the default zone, runtime only, inbound) --------

fwd_rule() {
    if [ "$FAMILY" = 6 ]; then _fam=ipv6; else _fam=ipv4; fi
    printf 'rule family="%s" source address="%s" drop' "$_fam" "$IP"
}

fwd_add() {
    _rule=$(fwd_rule)
    _out=$(firewall-cmd --add-rich-rule="$_rule" 2>&1) || {
        log "ERROR firewall-cmd --add-rich-rule failed: $(first_line "$_out")"
        return 1
    }
    firewall-cmd --query-rich-rule="$_rule" >/dev/null 2>&1 || {
        log "ERROR: rich rule for $IP not found after adding it"
        return 1
    }
    return 0
}

fwd_remove() {
    _rule=$(fwd_rule)
    _out=$(firewall-cmd --remove-rich-rule="$_rule" 2>&1) ||
        log "DELETE: firewall-cmd said: $(first_line "$_out")"
    if firewall-cmd --query-rich-rule="$_rule" >/dev/null 2>&1; then
        log "ERROR: rich rule for $IP is still present after removal"
        return 1
    fi
    return 0
}

# --- ufw (deny from IP, deny out to IP) ---------------------------------------

ufw_cmd() {
    LC_ALL=C ufw "$@"
}

ufw_remove_quiet() {
    ufw_cmd --force delete deny from "$IP" >/dev/null 2>&1
    ufw_cmd --force delete deny out to "$IP" >/dev/null 2>&1
    return 0
}

# does "ufw status" show a DENY line for this IP? (IPv4 only, IPv6 text can differ)
ufw_denied() {
    ufw_cmd status 2>/dev/null | grep -Fw -- "$IP" | grep -q DENY
}

ufw_add() {
    ufw_remove_quiet    # remove old copies first
    # insert at position 1 so an earlier "allow" rule cannot override the deny;
    # "insert" fails on an empty rule list, where a plain append is already first
    _out=$(ufw_cmd insert 1 deny from "$IP" 2>&1) || {
        _out=$(ufw_cmd deny from "$IP" 2>&1) || {
            log "ERROR ufw deny from $IP failed: $(first_line "$_out")"
            return 1
        }
    }
    _out=$(ufw_cmd insert 1 deny out to "$IP" 2>&1) || {
        _out=$(ufw_cmd deny out to "$IP" 2>&1) || {
            log "ERROR ufw deny out to $IP failed: $(first_line "$_out")"
            ufw_remove_quiet
            return 1
        }
    }
    if [ "$FAMILY" = 4 ] && ! ufw_denied; then
        log "ERROR: no DENY rule for $IP in 'ufw status' after adding it"
        ufw_remove_quiet
        return 1
    fi
    return 0
}

ufw_remove() {
    ufw_remove_quiet
    if [ "$FAMILY" = 4 ] && ufw_denied; then
        log "ERROR: a DENY rule for $IP is still in 'ufw status' after removal"
        return 1
    fi
    return 0
}

# --- iptables / ip6tables (INPUT + OUTPUT DROP) -------------------------------

ipt() {
    "$IPT" $IPT_W "$@"
}

ipt_remove_all() {
    _n=0
    while [ "$_n" -lt 50 ] && ipt -D INPUT -s "$IP" -j DROP >/dev/null 2>&1; do
        _n=$((_n + 1))
    done
    _n=0
    while [ "$_n" -lt 50 ] && ipt -D OUTPUT -d "$IP" -j DROP >/dev/null 2>&1; do
        _n=$((_n + 1))
    done
}

ipt_present() {
    ipt -C INPUT -s "$IP" -j DROP >/dev/null 2>&1 &&
        ipt -C OUTPUT -d "$IP" -j DROP >/dev/null 2>&1
}

ipt_leftover() {
    ipt -C INPUT -s "$IP" -j DROP >/dev/null 2>&1 ||
        ipt -C OUTPUT -d "$IP" -j DROP >/dev/null 2>&1
}

ipt_add() {
    ipt_remove_all    # remove old copies first
    _out=$(ipt -I INPUT -s "$IP" -j DROP 2>&1) || {
        log "ERROR adding INPUT rule for $IP : $_out"
        ipt_remove_all
        return 1
    }
    _out=$(ipt -I OUTPUT -d "$IP" -j DROP 2>&1) || {
        log "ERROR adding OUTPUT rule for $IP : $_out"
        ipt_remove_all
        return 1
    }
    if ! ipt_present; then
        log "ERROR: rules for $IP not found after adding them"
        ipt_remove_all
        return 1
    fi
    return 0
}

ipt_remove() {
    ipt_remove_all
    if ipt_leftover; then
        log "ERROR: a rule for $IP is still present after removal"
        return 1
    fi
    return 0
}

# --- nftables (own table, one set per address family) -------------------------

nft_set_name() {
    if [ "$FAMILY" = 6 ]; then echo blocked6; else echo blocked4; fi
}

nft_ensure_table() {
    nft list table inet wazuh_ar >/dev/null 2>&1 && return 0
    nft -f - >/dev/null 2>&1 <<'NFT'
add table inet wazuh_ar
add set inet wazuh_ar blocked4 { type ipv4_addr; }
add set inet wazuh_ar blocked6 { type ipv6_addr; }
add chain inet wazuh_ar input { type filter hook input priority -10; policy accept; }
add chain inet wazuh_ar output { type filter hook output priority -10; policy accept; }
add rule inet wazuh_ar input ip saddr @blocked4 drop
add rule inet wazuh_ar input ip6 saddr @blocked6 drop
add rule inet wazuh_ar output ip daddr @blocked4 drop
add rule inet wazuh_ar output ip6 daddr @blocked6 drop
NFT
}

nft_add() {
    nft_ensure_table || {
        log "ERROR: could not create nft table inet wazuh_ar"
        return 1
    }
    _set=$(nft_set_name)
    nft delete element inet wazuh_ar "$_set" "{ $IP }" >/dev/null 2>&1    # no duplicates
    _out=$(nft add element inet wazuh_ar "$_set" "{ $IP }" 2>&1) || {
        log "ERROR adding $IP to nft set $_set : $_out"
        return 1
    }
    return 0
}

nft_remove() {
    if nft list table inet wazuh_ar >/dev/null 2>&1; then
        _set=$(nft_set_name)
        _out=$(nft delete element inet wazuh_ar "$_set" "{ $IP }" 2>&1) ||
            log "DELETE: nothing to remove for $IP ($(first_line "$_out"))"
    else
        log "DELETE: table inet wazuh_ar does not exist, nothing to remove"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# 5. Block / unblock with the detected firewall
# ---------------------------------------------------------------------------

add_ip_block() {
    log "ADD requested: IP=$IP firewall=$BACKEND"
    case $BACKEND in
        firewalld) fwd_add || return 1 ;;
        ufw)       ufw_add || return 1 ;;
        iptables)  ipt_add || return 1 ;;
        nft)       nft_add || return 1 ;;
    esac
    log "SUCCESS: IP blocked: $IP firewall=$BACKEND"
    return 0
}

remove_ip_block() {
    log "DELETE requested: IP=$IP firewall=$BACKEND"
    case $BACKEND in
        firewalld) fwd_remove || return 1 ;;
        ufw)       ufw_remove || return 1 ;;
        iptables)  ipt_remove || return 1 ;;
        nft)       nft_remove || return 1 ;;
    esac
    log "DELETE done: IP=$IP"
    return 0
}

detect_backend || fail "no usable firewall found (need a running firewalld or an active ufw, or iptables/ip6tables or nft, and root)"
log "Firewall in use: $BACKEND"

if [ "$OPERATION" = add ]; then
    add_ip_block
else
    remove_ip_block
fi
exit $?
