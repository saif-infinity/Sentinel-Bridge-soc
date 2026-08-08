import ssl

from ...core.config import settings

ssl_verify = settings.ENVIRONMENT == "production"
if ssl_verify:
    ssl_ctx = ssl.create_default_context()
else:
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
