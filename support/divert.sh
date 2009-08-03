#!/bin/sh

ipfw add 410 divert 1337 ip4 from any to any
./FreeIPS -i iwn0 -I -P 1337 -c config/config.xml

ipfw delete 410
