#!/usr/bin/env bash
# GNU compatibility test suite for shadow-rs.
# Runs both GNU and shadow-rs tools, diffs output.
# Usage: docker compose run --rm debian bash tests/gnu-compat.sh

set -euo pipefail
PASS=0; FAIL=0; SKIP=0

cargo build --release --workspace 2>/dev/null
RS=./target/release

compare() {
    local name="$1" our_cmd="$2" gnu_cmd="$3"
    local our_out gnu_out
    our_out=$(eval "$our_cmd" 2>&1) || true
    gnu_out=$(eval "$gnu_cmd" 2>&1) || true
    if [ "$our_out" = "$gnu_out" ]; then
        echo "  PASS: $name"
        ((PASS++))
    else
        echo "  FAIL: $name"
        echo "    shadow-rs: ${our_out:0:80}"
        echo "    GNU:       ${gnu_out:0:80}"
        ((FAIL++))
    fi
}

compare_exit() {
    local name="$1" our_cmd="$2" gnu_cmd="$3"
    local our_rc gnu_rc
    our_rc=0; eval "$our_cmd" >/dev/null 2>&1 || our_rc=$?
    gnu_rc=0; eval "$gnu_cmd" >/dev/null 2>&1 || gnu_rc=$?
    if [ "$our_rc" = "$gnu_rc" ]; then
        echo "  PASS: $name (exit $our_rc)"
        ((PASS++))
    else
        echo "  FAIL: $name (shadow-rs=$our_rc, GNU=$gnu_rc)"
        ((FAIL++))
    fi
}

echo "=== passwd ==="
compare "passwd -S root" "$RS/passwd -S root" "/usr/bin/passwd -S root"
compare_exit "passwd --help" "$RS/passwd --help" "/usr/bin/passwd --help"
compare_exit "passwd --bogus" "$RS/passwd --bogus" "/usr/bin/passwd --bogus"

echo "=== pwck ==="
compare "pwck -r output" "$RS/pwck -r" "/usr/sbin/pwck -r"
compare_exit "pwck -r exit" "$RS/pwck -r" "/usr/sbin/pwck -r"
compare_exit "pwck -q -r" "$RS/pwck -q -r" "/usr/sbin/pwck -q -r"

echo "=== useradd ==="
compare_exit "useradd --help" "$RS/useradd --help" "/usr/sbin/useradd --help"

echo "=== userdel ==="
compare_exit "userdel --help" "$RS/userdel --help" "/usr/sbin/userdel --help"

echo "=== usermod ==="
compare_exit "usermod --help" "$RS/usermod --help" "/usr/sbin/usermod --help"

echo "=== groupadd ==="
compare_exit "groupadd --help" "$RS/groupadd --help" "/usr/sbin/groupadd --help"

echo "=== groupdel ==="
compare_exit "groupdel --help" "$RS/groupdel --help" "/usr/sbin/groupdel --help"

echo "=== groupmod ==="
compare_exit "groupmod --help" "$RS/groupmod --help" "/usr/sbin/groupmod --help"

echo "=== chage ==="
compare_exit "chage --help" "$RS/chage --help" "/usr/bin/chage --help"

echo "=== chpasswd ==="
compare_exit "chpasswd --help" "$RS/chpasswd --help" "/usr/sbin/chpasswd --help"

echo "=== chfn ==="
compare_exit "chfn --help" "$RS/chfn --help" "/usr/bin/chfn --help"

echo "=== chsh ==="
compare_exit "chsh --help" "$RS/chsh --help" "/usr/bin/chsh --help"

echo "=== grpck ==="
compare_exit "grpck --help" "$RS/grpck --help" "/usr/sbin/grpck --help"

echo "=== newgrp ==="
compare_exit "newgrp --help" "$RS/newgrp --help" "/usr/bin/newgrp --help"

echo ""
echo "=== Results ==="
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo "  SKIP: $SKIP"
