from django.contrib import admin
from django.utils.html import format_html

from .models import Item, ItemMedia, StolenReport


class ItemMediaInline(admin.TabularInline):
    model = ItemMedia
    extra = 1
    readonly_fields = ("media_type", "preview")
    fields = ("media_url", "media_type", "preview",)

    def preview(self, obj):
        if obj.media_type == "image":
            return format_html('<img src="{}" style="max-height:150px;"/>', obj.media_url.url)
        return "-"
    preview.short_description = "Preview"


class StolenReportInline(admin.TabularInline):
    model = StolenReport
    extra = 0
    readonly_fields = ("report_date",)
    fields = ("report_date", "resolved",)


@admin.register(Item)
class ItemAdmin(admin.ModelAdmin):
    list_display = ("name", "owner", "serial_number", "is_stolen", "created_at")
    list_filter = ("is_stolen", "owner", "created_at")
    search_fields = ("name", "serial_number", "description", "owner__username")
    date_hierarchy = "created_at"
    raw_id_fields = ("owner",)
    ordering = ("-created_at",)
    inlines = (ItemMediaInline, StolenReportInline,)


@admin.register(ItemMedia)
class ItemMediaAdmin(admin.ModelAdmin):
    list_display = ("item", "media_type", "uploaded_at", "preview")
    list_filter = ("uploaded_at", "item__owner")
    search_fields = ("item__name", "item__serial_number")
    readonly_fields = ("preview",)
    date_hierarchy = "uploaded_at"

    def preview(self, obj):
        if obj.media_type == "image":
            return format_html(
                '<img src="{}" style="max-height:150px;"/>', obj.media_url.url
            )
        return "-"
    preview.short_description = "Preview"


@admin.register(StolenReport)
class StolenReportAdmin(admin.ModelAdmin):
    list_display = ("item", "report_date", "resolved")
    list_filter = ("resolved", "report_date", "item__owner")
    search_fields = ("item__name", "item__serial_number")
    date_hierarchy = "report_date"
