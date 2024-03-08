from django.db import models
from django.contrib.auth.models import User

class TelegramProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='telegram_profile')
    chat_id = models.CharField(max_length=255, unique=True)
    token = models.CharField(max_length=64, blank=True, null=True)  # Добавляем поле для токена

    def __str__(self):
        return f"{self.user.username} - {self.chat_id}"

class UserLogin(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} logged in at {self.timestamp}"

class ParserSetting(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='parser_settings')
    group_tag = models.CharField(max_length=100, help_text="Telegram group tag to monitor, e.g., @rgb_rostov_events")
    keywords = models.CharField(max_length=255, help_text="Keywords to search for, separated by commas")