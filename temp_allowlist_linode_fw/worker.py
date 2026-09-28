from gunicorn.workers.gthread import ThreadWorker

from temp_allowlist_linode_fw.config import Config


class ReadTimeoutThreadWorker(ThreadWorker):
    """gthread worker that bounds how long a client may stall mid-request.

    Stock gthread only defers connections that send nothing. Once any byte
    arrives, a pool thread reads the request from a blocking socket with no
    timeout, so a client that sends a partial request line and goes quiet
    (e.g. a scanner sending a TLS ClientHello to this plain-HTTP port) pins
    that thread forever. With every pool thread pinned, the app hangs.
    """

    def handle(self, conn):
        if not getattr(conn, "_read_timeout_applied", False):
            init = conn.init

            # handle() resets the socket to fully blocking and then calls
            # conn.init() on every request (including keepalive), so apply
            # the timeout right after init to cover request parsing.
            def init_with_read_timeout():
                init()
                conn.sock.settimeout(Config.CLIENT_READ_TIMEOUT_SECONDS)

            conn.init = init_with_read_timeout
            conn._read_timeout_applied = True
        return super().handle(conn)
