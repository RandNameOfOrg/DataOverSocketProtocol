from dosp.server import DoSP

if __name__ == "__main__":
    server = DoSP()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
