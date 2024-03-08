import sys
from django.apps import AppConfig
from django.core.checks import Tags, run_checks

import sys
from django.apps import AppConfig

class TelegramAuthConfig(AppConfig):
    name = 'telegram_auth'

    def ready(self):
        if 'runserver' in sys.argv:
            from .views import set_webhook
            set_webhook()