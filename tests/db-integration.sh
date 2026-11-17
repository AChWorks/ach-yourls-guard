#!/usr/bin/env bash
# Disposable database-backed YOURLS integration test. Never touches a configured site.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
upstream="${YOURLS_SOURCE:-"$repo/../upstream-yourls"}"
force="${FORCE_LOWERCASE_SOURCE:-"$repo/../upstream-force-lowercase"}"
if [[ ! -f "$upstream/includes/load-yourls.php" || ! -f "$force/plugin.php" ]]; then
  echo "Set YOURLS_SOURCE and FORCE_LOWERCASE_SOURCE to checkouts of the real plugins." >&2
  exit 2
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/ach-yourls-db-integration.XXXXXXXX")"
chmod 700 "$tmp"
server_pid=''
http_pid=''
lock_pid=''
database_created=0
ACH_IT_DB_NAME="ach_guard_it_$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
export ACH_IT_DB_NAME
export ACH_IT_SITE="$tmp/site"
export ACH_IT_DB_HOST="${ACH_IT_DB_HOST:-localhost}"
export ACH_IT_DB_USER="${ACH_IT_DB_USER:-root}"
export ACH_IT_DB_PASS="${ACH_IT_DB_PASS:-}"
export ACH_IT_DB_PORT="${ACH_IT_DB_PORT:-3306}"
export ACH_IT_DB_SOCKET="${ACH_IT_DB_SOCKET:-}"
ACH_IT_COOKIE_KEY="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
export ACH_IT_COOKIE_KEY
ACH_IT_ADMIN_PASS="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
export ACH_IT_ADMIN_PASS
# shellcheck disable=SC2016 # PHP variables must remain literal inside single quotes.
ACH_IT_HTTP_PORT="$(php -r '$s = stream_socket_server("tcp://127.0.0.1:0"); if (!$s) exit(1); echo (int) substr(strrchr(stream_socket_get_name($s, false), ":"), 1); fclose($s);')"
export ACH_IT_HTTP_PORT
cleanup() {
  local code=$?
  trap - EXIT
  if [[ -n "$lock_pid" ]]; then
    kill "$lock_pid" >/dev/null 2>&1 || true
    wait "$lock_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$http_pid" ]]; then
    kill "$http_pid" >/dev/null 2>&1 || true
    wait "$http_pid" >/dev/null 2>&1 || true
  fi
  if [[ "$database_created" == 1 ]]; then
    run_php "$repo/tests/db-phase.php" drop >/dev/null 2>&1 || echo 'WARNING: disposable DB cleanup failed' >&2
  fi
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$tmp"
  exit "$code"
}
trap cleanup EXIT
run_php() {
  if [[ -n "$ACH_IT_DB_SOCKET" ]]; then
    php -d "pdo_mysql.default_socket=$ACH_IT_DB_SOCKET" -d "mysqli.default_socket=$ACH_IT_DB_SOCKET" "$@"
  else
    php "$@"
  fi
}

# Locally, create a private, socket-only MariaDB instance in the test directory.
# CI instead supplies its own loopback MariaDB service.
if [[ -z "${ACH_IT_EXTERNAL_DB:-}" ]]; then
  if ! command -v mariadb-install-db >/dev/null || ! command -v mariadbd >/dev/null; then
    echo 'Local testing requires mariadb-install-db and mariadbd; CI may use ACH_IT_EXTERNAL_DB=1.' >&2
    exit 2
  fi
  mkdir "$tmp/data"
  mariadb-install-db --no-defaults --datadir="$tmp/data" --auth-root-authentication-method=normal --skip-test-db >"$tmp/init.log" 2>&1 || {
    tail -50 "$tmp/init.log" >&2
    exit 1
  }
  export ACH_IT_DB_SOCKET="$tmp/mariadb.sock"
  export ACH_IT_DB_HOST=localhost
  export ACH_IT_DB_USER=root
  export ACH_IT_DB_PASS=''
  mariadbd --no-defaults --datadir="$tmp/data" --socket="$ACH_IT_DB_SOCKET" \
    --pid-file="$tmp/mariadb.pid" --log-error="$tmp/mariadb.log" \
    --skip-networking --innodb-buffer-pool-size=32M --max-connections=20 \
    >"$tmp/server.out" 2>&1 &
  server_pid=$!
  ready=0
  for _ in {1..40}; do
    if [[ -S "$ACH_IT_DB_SOCKET" ]] && run_php "$repo/tests/db-phase.php" ping >/dev/null 2>&1; then
      ready=1
      break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      break
    fi
    sleep 0.25
  done
  if [[ "$ready" != 1 ]]; then
    tail -60 "$tmp/mariadb.log" >&2
    exit 1
  fi
fi

# All test file writes are confined to this fresh temporary site.
mkdir "$ACH_IT_SITE"
cp -a "$upstream/." "$ACH_IT_SITE/"
# Upstream YOURLS intentionally has no root index.php; the public front page
# is an optional sample. Install that sample only in this disposable fixture
# so public-mode reachability is exercised without a custom Production UI.
cp "$upstream/sample-public-front-page.txt" "$ACH_IT_SITE/index.php"
mkdir -p "$ACH_IT_SITE/user/plugins/force-lowercase" "$ACH_IT_SITE/user/plugins/ach-url-guard"
cp "$force/plugin.php" "$ACH_IT_SITE/user/plugins/force-lowercase/plugin.php"
cp "$repo/plugin.php" "$ACH_IT_SITE/user/plugins/ach-url-guard/plugin.php"
cp -R "$repo/bin" "$ACH_IT_SITE/user/plugins/ach-url-guard/bin"
cp -R "$repo/src" "$ACH_IT_SITE/user/plugins/ach-url-guard/src"
cat >"$ACH_IT_SITE/user/config.php" <<'CONFIG'
<?php
define('YOURLS_DB_USER', getenv('ACH_IT_DB_USER'));
define('YOURLS_DB_PASS', getenv('ACH_IT_DB_PASS'));
define('YOURLS_DB_NAME', getenv('ACH_IT_DB_NAME'));
define('YOURLS_DB_HOST', getenv('ACH_IT_DB_HOST') . (getenv('ACH_IT_DB_HOST') === 'localhost' ? '' : ':' . getenv('ACH_IT_DB_PORT')));
define('YOURLS_DB_PREFIX', 'yourls_');
define('YOURLS_SITE', 'http://127.0.0.1:' . getenv('ACH_IT_HTTP_PORT'));
define('YOURLS_COOKIEKEY', getenv('ACH_IT_COOKIE_KEY'));
define('YOURLS_PRIVATE', getenv('ACH_IT_PRIVATE') !== '0');
define('YOURLS_URL_CONVERT', 36);
// This isolated suite creates many links per second. Production retains native flood protection.
// Fixture normally disables flood for rapid link insertions; final native-flood probes opt back in.
define('YOURLS_FLOOD_DELAY_SECONDS', (int) (getenv('ACH_IT_FLOOD_DELAY') ?: '0'));
define('YOURLS_DEBUG', false);
$yourls_user_passwords = ['integration' => getenv('ACH_IT_ADMIN_PASS')];
CONFIG

run_php "$repo/tests/db-phase.php" create
database_created=1
run_php "$repo/tests/db-phase.php" install
run_php "$repo/tests/db-phase.php" verify

# Exercise a real background cron-style PHP process in the disposable site.
# Preview must stop at ready until a separate authorization is recorded.
export ACH_IT_BG_JOB_ID="$(run_php "$repo/tests/db-phase.php" background-seed)"
run_php "$ACH_IT_SITE/user/plugins/ach-url-guard/bin/bulk-worker.php" --site="$ACH_IT_SITE" --seconds=5
run_php "$repo/tests/db-phase.php" background-ready
run_php "$repo/tests/db-phase.php" background-approve
run_php "$ACH_IT_SITE/user/plugins/ach-url-guard/bin/bulk-worker.php" --site="$ACH_IT_SITE" --seconds=5
run_php "$repo/tests/db-phase.php" background-done
unset ACH_IT_BG_JOB_ID

# v0.2.2 serialized records omit new optional worker fields. The operator
# must be able to inspect legacy phases before installing a scheduler.
run_php "$repo/tests/db-phase.php" background-legacy-seed
inspection="$(run_php "$ACH_IT_SITE/user/plugins/ach-url-guard/bin/bulk-worker.php" --site="$ACH_IT_SITE" --inspect)"
for phase in scan ready delete; do
  grep -q "phase=$phase .*legacy=yes" <<<"$inspection" || {
    echo "Legacy scheduler preflight did not expose phase $phase" >&2; exit 1;
  }
done
# Deliberately execute the pre-approved *disposable* legacy delete job;
# ready jobs must remain inert, and scans must never gain delete permission.
run_php "$ACH_IT_SITE/user/plugins/ach-url-guard/bin/bulk-worker.php" --site="$ACH_IT_SITE" --seconds=5
run_php "$repo/tests/db-phase.php" background-legacy-verify
echo 'PASS legacy v0.2.2 preflight: all phases inspected, only already-approved fixture deleted.'

# Two independent site paths sharing the same MariaDB job namespace MUST
# contend on the identical server-side advisory lock. A separate process
# holds it while BOTH worker paths attempt to advance a saved scan.
export ACH_IT_LOCK_JOB_ID="$(run_php "$repo/tests/db-phase.php" background-lock-seed)"
cp -a "$ACH_IT_SITE" "$tmp/second-site"
ready_file="$tmp/lock-ready"
php "$repo/tests/worker-lock-holder.php" "$ready_file" >"$tmp/lock-holder.log" 2>&1 &
lock_pid=$!
for _ in {1..60}; do
  [[ -f "$ready_file" ]] && break
  kill -0 "$lock_pid" 2>/dev/null || break
  sleep .1
done
if [[ ! -f "$ready_file" ]]; then
  cat "$tmp/lock-holder.log" >&2
  echo 'Disposable advisory lock was never acquired.' >&2
  exit 1
fi
run_php "$ACH_IT_SITE/user/plugins/ach-url-guard/bin/bulk-worker.php" \
  --site="$ACH_IT_SITE" --seconds=5 >"$tmp/worker-a.log" 2>&1 &
worker_a=$!
run_php "$tmp/second-site/user/plugins/ach-url-guard/bin/bulk-worker.php" \
  --site="$tmp/second-site" --seconds=5 >"$tmp/worker-b.log" 2>&1 &
worker_b=$!
wait "$worker_a"
wait "$worker_b"
test ! -s "$tmp/worker-a.log" && test ! -s "$tmp/worker-b.log" || {
  echo 'Worker did not respect cross-path shared advisory lock.' >&2; exit 1;
}
ACH_IT_LOCK_PHASE=scan run_php "$repo/tests/db-phase.php" background-lock-check
kill "$lock_pid" >/dev/null 2>&1 || true
wait "$lock_pid" >/dev/null 2>&1 || true
lock_pid=''
run_php "$ACH_IT_SITE/user/plugins/ach-url-guard/bin/bulk-worker.php" \
  --site="$ACH_IT_SITE" --seconds=5 >"$tmp/worker-recovered.log" 2>&1 &
worker_a=$!
run_php "$tmp/second-site/user/plugins/ach-url-guard/bin/bulk-worker.php" \
  --site="$tmp/second-site" --seconds=5 >"$tmp/worker-repeated.log" 2>&1 &
worker_b=$!
wait "$worker_a"
wait "$worker_b"
printf 'RECOVERED_WORKER_LOGS\n'
cat "$tmp/worker-recovered.log" "$tmp/worker-repeated.log"
ACH_IT_LOCK_PHASE=ready run_php "$repo/tests/db-phase.php" background-lock-check
run_php "$tmp/second-site/user/plugins/ach-url-guard/bin/bulk-worker.php" \
  --site="$tmp/second-site" --seconds=5
ACH_IT_LOCK_PHASE=ready run_php "$repo/tests/db-phase.php" background-lock-check
unset ACH_IT_LOCK_JOB_ID
echo 'PASS cross-path MariaDB lock contention, worker crash recovery and repeated cron runs.'

# Prepare three separate real HTTP login/approval fixtures; the public and
# private server modes must use real browser-like cookies and POSTs.
export ACH_IT_HTTP_PRIVATE_ID="$(ACH_IT_HTTP_LABEL=private run_php "$repo/tests/db-phase.php" background-http-seed)"
export ACH_IT_HTTP_PUBLIC_ID="$(ACH_IT_HTTP_LABEL=public run_php "$repo/tests/db-phase.php" background-http-seed)"
export ACH_IT_HTTP_OTHER_ID="$(ACH_IT_HTTP_LABEL=other run_php "$repo/tests/db-phase.php" background-http-seed)"
export ACH_IT_HTTP_STALE_PRIVATE_ID="$(ACH_IT_HTTP_LABEL=stale-private run_php "$repo/tests/db-phase.php" background-http-seed)"
export ACH_IT_HTTP_STALE_PUBLIC_ID="$(ACH_IT_HTTP_LABEL=stale-public run_php "$repo/tests/db-phase.php" background-http-seed)"
export ACH_IT_LOGIN_NONCE="$(run_php "$repo/tests/db-phase.php" login-nonce)"

# The opt-in historical audit is required to be read-only, including options/events.
before="$(run_php "$repo/tests/db-phase.php" snapshot)"
run_php "$repo/bin/audit.php" --site="$ACH_IT_SITE" --limit=200 >"$tmp/audit.csv" 2>"$tmp/audit.log"
after="$(run_php "$repo/tests/db-phase.php" snapshot)"
if [[ "$before" != "$after" ]] || ! grep -q '^keyword,status,reason,destination' "$tmp/audit.csv" || ! grep -q 'monitor-root' "$tmp/audit.csv"; then
  echo 'Historical audit changed database state or failed to produce expected CSV.' >&2
  tail -20 "$tmp/audit.log" >&2
  exit 1
fi
echo 'PASS read-only historical audit: CSV and full database state unchanged.'

# Shared native YOURLS session is generated by private-mode HTTP login,
# then reused across the public-mode restart (no fake auth filters).
export ACH_IT_TEST_COOKIE_FILE="$tmp/yourls-auth-cookie"
# The native PHP HTTP entry points and actual redirects are checked over loopback.
cat >"$tmp/router.php" <<'ROUTER'
<?php
$site = getenv('ACH_IT_SITE');
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if (is_string($path) && $path !== '/' && is_file($site . $path)) {
    return false;
}
require $site . '/yourls-loader.php';
ROUTER
if [[ -n "$ACH_IT_DB_SOCKET" ]]; then
  php -d "pdo_mysql.default_socket=$ACH_IT_DB_SOCKET" -d "mysqli.default_socket=$ACH_IT_DB_SOCKET" \
    -S "127.0.0.1:$ACH_IT_HTTP_PORT" -t "$ACH_IT_SITE" "$tmp/router.php" >"$tmp/http.log" 2>&1 &
else
  php -S "127.0.0.1:$ACH_IT_HTTP_PORT" -t "$ACH_IT_SITE" "$tmp/router.php" >"$tmp/http.log" 2>&1 &
fi
http_pid=$!
ready=0
for _ in {1..40}; do
  if run_php "$repo/tests/http-integration.php" ping >/dev/null 2>&1; then ready=1; break; fi
  if ! kill -0 "$http_pid" 2>/dev/null; then break; fi
  sleep 0.25
done
if [[ "$ready" != 1 ]]; then tail -50 "$tmp/http.log" >&2; exit 1; fi
if ! run_php "$repo/tests/http-integration.php" verify; then
  tail -65 "$tmp/http.log" >&2
  exit 1
fi

# Restart only the disposable local HTTP server with YOURLS in public mode.
# In public mode the native YOURLS admin router itself does not require login;
# the plugin must protect its sensitive pages independently.
kill "$http_pid" >/dev/null 2>&1 || true
wait "$http_pid" >/dev/null 2>&1 || true
http_pid=''
if [[ -n "$ACH_IT_DB_SOCKET" ]]; then
  ACH_IT_PRIVATE=0 php -d "pdo_mysql.default_socket=$ACH_IT_DB_SOCKET" \
    -d "mysqli.default_socket=$ACH_IT_DB_SOCKET" \
    -S "127.0.0.1:$ACH_IT_HTTP_PORT" -t "$ACH_IT_SITE" "$tmp/router.php" \
    >"$tmp/public-http.log" 2>&1 &
else
  ACH_IT_PRIVATE=0 php -S "127.0.0.1:$ACH_IT_HTTP_PORT" -t "$ACH_IT_SITE" \
    "$tmp/router.php" >"$tmp/public-http.log" 2>&1 &
fi
http_pid=$!
ready=0
for _ in {1..40}; do
  if run_php "$repo/tests/http-integration.php" ping >/dev/null 2>&1; then ready=1; break; fi
  if ! kill -0 "$http_pid" 2>/dev/null; then break; fi
  sleep 0.25
done
if [[ "$ready" != 1 ]]; then tail -50 "$tmp/public-http.log" >&2; exit 1; fi
if ! run_php "$repo/tests/http-integration.php" verify-public; then
  tail -65 "$tmp/public-http.log" >&2
  exit 1
fi

run_php "$repo/tests/db-phase.php" background-http-check
# Prove admission works across distinct PHP processes with the real YOURLS
# native flood policy enabled. Never call external HTTP/provider services.
gate_before="$(run_php "$repo/tests/db-phase.php" snapshot)"
for phase in first repeat different; do
  ACH_IT_FLOOD_DELAY=15 ACH_IT_GATE_CASE="$phase" run_php "$repo/tests/db-phase.php" gate
done
gate_after="$(run_php "$repo/tests/db-phase.php" snapshot)"
if [[ "$gate_before" != "$gate_after" ]]; then
  echo 'Work admission changed YOURLS database state.' >&2
  exit 1
fi
echo 'PASS native-delay admission: coalesced repeated rejected checks, deferred alternate URL, DB unchanged.'

echo 'PASS isolated real YOURLS + MariaDB + HTTP integration (site and database removed)'
