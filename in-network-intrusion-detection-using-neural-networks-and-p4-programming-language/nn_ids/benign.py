#!/usr/bin/env python3
import os

# Benign traffic: UDP with sport 53 (DNS)
os.system("python3 send.py 10.0.2.2 --proto udp --sport 53 --ttl 64 --payload BENIGN")