import os
import sys

from dosp.server.base import ServerConfig

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dosp.server import DoSP

if __name__ == "__main__":
    server = DoSP(ServerConfig(
        port=7744,
        ip_template="7.34.43.x"
    ))
    try:
        server.start()
        # server.add_peer_server("10.0.0.50", ip_template="7.10.0.{x}")
    except KeyboardInterrupt:
        server.stop()
        exit(0)
