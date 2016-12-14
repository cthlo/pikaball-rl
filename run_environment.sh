#!/usr/bin/env bash

pid=`ps x | grep '[P]ikaBall.exe' | awk '{print $1}'`

if [[ -z $pid ]]; then
  echo "PikaBall not running?"
else
  DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
  gdb -q -p $pid -x "$DIR/interface/pikaball.py"
fi
