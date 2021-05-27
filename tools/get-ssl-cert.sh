#!/bin/bash

#
# Copyright (C) 2015 - 2021 Eaton
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

PEM_KEY="/etc/tntnet/bios.key"
PEM_CRT="/etc/tntnet/bios.crt"
PEM_FINAL_CERT="/etc/tntnet/bios.pem"

for F in "$PEM_FINAL_CERT" "$PEM_KEY" "$PEM_CRT" ; do
    D="`dirname "$F"`"
    if [ ! -d "$D/" ]; then
        echo "FATAL: Directory '$D' to hold the PEM files does not exist!" >&2
        exit 1
    fi
done

### discard multiple new lines at the end of the stream
KEY=$(certcmd https server getkey | sed -E ':a;N;$!ba;s/[\n]+$//g')
CRT=$(certcmd https server getcert | sed -E ':a;N;$!ba;s/[\n]+$//g')

UPDATE_CERT=no
if [ -f "$PEM_KEY" ]; then
    DIFF=$(diff -q <(echo "$KEY") <(cat "$PEM_KEY" | sed -E ':a;N;$!ba;s/[\n]+$//g') | grep differ)
    if [ -n "$DIFF" ]; then
        UPDATE_CERT=yes
    fi
else
    UPDATE_CERT=yes
fi

if [ -f $PEM_CRT ]; then
    DIFF=$(diff -q <(echo "$CRT") <(cat "$PEM_CRT" | sed -E ':a;N;$!ba;s/[\n]+$//g') | grep differ)
    if [ -n "$DIFF" ]; then
        UPDATE_CERT=yes
    fi
else
    UPDATE_CERT=yes
fi

if [ "$UPDATE_CERT" = yes ]; then
    echo "$KEY" > "$PEM_KEY"
    echo "$CRT" > "$PEM_CRT"
    cat "$PEM_KEY" "$PEM_CRT" > "$PEM_FINAL_CERT"
fi

exit 0