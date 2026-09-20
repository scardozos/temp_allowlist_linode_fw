import logging
import sys
import time
from contextlib import contextmanager

from flask import g, has_request_context
from gunicorn.glogging import Logger
from pythonjsonlogger import jsonlogger

from temp_allowlist_linode_fw.config import Config


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter producing structured log entries."""

    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        log_record["logLevel"] = record.levelname
        if "asctime" in log_record:
            log_record["timestamp"] = log_record.pop("asctime")
        for k in ["levelname", "lineno", "funcName", "filename", "module"]:
            log_record.pop(k, None)


class GunicornJsonLogger(Logger):
    """Custom Gunicorn logger that ensures all server/worker logs use JSON."""

    def setup(self, cfg):
        super().setup(cfg)
        log_level_name = Config.LOG_LEVEL
        log_level = getattr(logging, log_level_name, logging.INFO)

        formatter = CustomJsonFormatter(
            fmt="%(asctime)s %(levelname)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
        self.error_log.setLevel(log_level)
        self.error_log.propagate = False
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(formatter)
        self.error_log.handlers = [handler]


def setup_logging(log_level_name: str | None = None):
    """Configure root, Flask, and Gunicorn loggers with CustomJsonFormatter."""
    if log_level_name is None:
        log_level_name = Config.LOG_LEVEL
    log_level = getattr(logging, log_level_name, logging.INFO)

    formatter = CustomJsonFormatter(
        fmt="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers.clear()
    root_logger.addHandler(handler)

    # Silence noisy 3rd party loggers unless at DEBUG level
    if log_level > logging.DEBUG:
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("werkzeug").setLevel(logging.WARNING)
    else:
        logging.getLogger("werkzeug").setLevel(logging.INFO)

    # Disable gunicorn default access log propagation if present
    gunicorn_access = logging.getLogger("gunicorn.access")
    gunicorn_access.handlers.clear()
    gunicorn_access.propagate = False

    # Configure gunicorn.error logger to ensure structured JSON logging
    gunicorn_error = logging.getLogger("gunicorn.error")
    gunicorn_error.setLevel(log_level)
    gunicorn_error.propagate = False
    if gunicorn_error.handlers:
        for h in gunicorn_error.handlers:
            h.setFormatter(formatter)
            if hasattr(h, "setStream"):
                h.setStream(sys.stdout)
    else:
        gunicorn_error.addHandler(handler)

    return logging.getLogger("temp_allowlist_linode")


logger = setup_logging()


def record_timing(op_name: str, duration_ms: float):
    """Record operation timing into Flask request context if available."""
    if has_request_context() and hasattr(g, "timings") and isinstance(g.timings, dict):
        g.timings[op_name] = round(duration_ms, 2)


@contextmanager
def measure_operation(op_name: str, threshold_ms: float | None = None):
    """Context manager measuring execution time and logging warnings for slow ops."""
    if threshold_ms is None:
        threshold_ms = Config.SLOW_OP_THRESHOLD_MS

    start = time.perf_counter()
    try:
        yield
    finally:
        elapsed = (time.perf_counter() - start) * 1000
        record_timing(op_name, elapsed)
        if elapsed > threshold_ms:
            logger.warning(
                f"Slow operation detected: {op_name} took {elapsed:.2f} ms "
                "(possible upstream rate limiting or API latency)",
                extra={"operation": op_name, "duration_ms": round(elapsed, 2)},
            )
