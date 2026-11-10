### Send Logs Script Test
```python
import socket

with open("monFichier.txt", "r") as f:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for line in f:
        sock.sendto(line.encode(), ("127.0.0.1", 514))
    sock.close()
```
