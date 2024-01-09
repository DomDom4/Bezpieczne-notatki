
class Config():
    SECRET_KEY = '69718f415bb2f267271e9351af67b1a57fc2a6590534395175004643f0170f36'
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    DB_NAME = "users.db"
    TOTP_ENCRYPTION_PASSWORD = b'DpA_5UJOsBDK6rXtkztAilKU1LlxZfTE40GcJzqxUHc='

class ProductionConfig(Config):
    pass

class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False