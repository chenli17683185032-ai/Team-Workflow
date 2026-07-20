#!/bin/zsh

set -u

ROOT=${0:A:h}
PYTHON='/Library/Frameworks/Python.framework/Versions/3.13/Resources/Python.app/Contents/MacOS/Python'

cd "$ROOT" || exit 1

if [[ ! -x "$PYTHON" ]]; then
  PYTHON=$(command -v python3)
fi

"$PYTHON" -B -m team_protocol push-sub2api --latest
status=$?

echo
read -r '?按回车键关闭窗口。'
exit "$status"
