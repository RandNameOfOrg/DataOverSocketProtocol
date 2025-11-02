import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dosp.server import DoSP

if __name__ == "__main__":
    server = DoSP()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
