#!/usr/bin/env bash
# Flow – הפעלה ב-Mac / Linux
cd "$(dirname "$0")"
if [ ! -d .venv ]; then
  echo "מתקינה בפעם הראשונה..."
  python3 -m venv .venv || exit 1
  ./.venv/bin/pip install -q -r requirements.txt || exit 1
fi
( sleep 2; (command -v open >/dev/null && open http://127.0.0.1:5000) || (command -v xdg-open >/dev/null && xdg-open http://127.0.0.1:5000) ) >/dev/null 2>&1 &
./.venv/bin/python app.py "$@"
