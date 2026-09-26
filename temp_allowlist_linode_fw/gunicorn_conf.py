from temp_allowlist_linode_fw.config import Config
from temp_allowlist_linode_fw.logging import GunicornJsonLogger

# Bind address and port
bind = f"0.0.0.0:{Config.SERVER_PORT}"

# Threaded workers to avoid blocking on slow clients or API calls
worker_class = "gthread"
threads = 4

# Structured JSON logging for Gunicorn
logger_class = GunicornJsonLogger
loglevel = Config.LOG_LEVEL.lower()

# Access logging is handled in structured JSON by Flask's @app.after_request
accesslog = None
