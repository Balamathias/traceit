import uuid
from django.conf import settings
from django.core.validators import FileExtensionValidator
from django.db import models


class Item(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="items",
        db_index=True
    )
    name = models.CharField(max_length=255)
    serial_number = models.CharField(max_length=255, unique=True, db_index=True)
    description = models.TextField(blank=True)
    is_stolen = models.BooleanField(default=False, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return self.name


class ItemMedia(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    IMAGE_EXTS = ("png", "jpg", "jpeg", "gif")
    VIDEO_EXTS = ("mp4", "mov", "avi")

    item = models.ForeignKey(
        Item,
        on_delete=models.CASCADE,
        related_name="media",
    )
    media_url = models.FileField(
        upload_to="item_media/",
        validators=[FileExtensionValidator(IMAGE_EXTS + VIDEO_EXTS)],
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-uploaded_at",)

    def __str__(self):
        return f"Media for {self.item.name} ({self.media_type})"

    @property
    def media_type(self):
        ext = self.media_url.name.rsplit(".", 1)[-1].lower()
        if ext in self.IMAGE_EXTS:
            return "image"
        if ext in self.VIDEO_EXTS:
            return "video"
        return "unknown"


class StolenReport(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    item = models.ForeignKey(
        Item,
        related_name="reports",
        on_delete=models.CASCADE,
        db_index=True
    )
    report_date = models.DateTimeField(auto_now_add=True, db_index=True)
    resolved = models.BooleanField(default=False, db_index=True)

    class Meta:
        ordering = ("-report_date",)

    def __str__(self):
        return f"Report for {self.item.name} on {self.report_date:%Y-%m-%d %H:%M}"
