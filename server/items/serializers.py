from rest_framework import serializers
from .models import Item, ItemMedia, StolenReport


class ItemMediaSerializer(serializers.ModelSerializer):
    media_type = serializers.CharField(read_only=True)

    class Meta:
        model = ItemMedia
        fields = ['id', 'item', 'media_url', 'media_type', 'uploaded_at']
        read_only_fields = ['id', 'media_type', 'uploaded_at']


class StolenReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = StolenReport
        fields = ['id', 'item', 'report_date', 'resolved']
        read_only_fields = ['id', 'report_date']


class ItemSerializer(serializers.ModelSerializer):
    media = ItemMediaSerializer(many=True, read_only=True)
    reports = StolenReportSerializer(many=True, read_only=True)
    owner = serializers.ReadOnlyField(source='owner.id')

    class Meta:
        model = Item
        fields = ['id', 'owner', 'name', 'serial_number', 'description', 'is_stolen', 'created_at', 'media', 'reports']
        read_only_fields = ['id', 'owner', 'created_at', 'media', 'reports']