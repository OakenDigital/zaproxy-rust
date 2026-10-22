#!/bin/sh
# PHASE-11 entrypoint. Installed as /zap/zap-x.sh.
# Accepts the flags the packaged-scan scripts pass and execs zapd.
# The automation framework (-autorun) is not in this image.
# -config, including spider.maxDuration, is ignored. The crawl uses
# spider 0.18.0 defaults (max depth 5).

set -eu

host=0.0.0.0
port=8080
session="${ZAP_SESSION:-}"
bin="${ZAPD_BIN:-/zap/zapd}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    -port|--port)
      port="$2"
      shift 2
      ;;
    -host|--host)
      host="$2"
      shift 2
      ;;
    -session|--session)
      session="$2"
      shift 2
      ;;
    -config|-addoninstall)
      shift 2
      ;;
    -addonupdate|-daemon|-cmd|-silent)
      shift
      ;;
    -autorun|--autorun)
      echo "zapd: the automation framework is not in this image" >&2
      exit 3
      ;;
    *)
      shift
      ;;
  esac
done

if [ -n "$session" ]; then
  exec "$bin" --host "$host" --port "$port" --session "$session"
fi
exec "$bin" --host "$host" --port "$port"
