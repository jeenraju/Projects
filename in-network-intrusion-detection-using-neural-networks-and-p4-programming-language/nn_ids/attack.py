#!/usr/bin/env python3
import os

# Attack traffic: TCP with sport 80 (like HTTP)
os.system("python3 send.py 10.0.2.2 --proto tcp --sport 80 --ttl 254 --payload ATTACK")