from django.shortcuts import render
from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter

from utils.response import ResponseMixin
from utils.pagination import StackPagination
from users.permissions import IsOwnerOrReadOnly

from .models import Item, ItemMedia, StolenReport
from .serializers import ItemSerializer, ItemMediaSerializer, StolenReportSerializer


class ItemViewSet(ResponseMixin, viewsets.ModelViewSet):
    queryset = Item.objects.all().prefetch_related('media', 'reports')
    serializer_class = ItemSerializer
    permission_classes = [IsAuthenticated, IsOwnerOrReadOnly]
    pagination_class = StackPagination
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['owner', 'is_stolen']
    search_fields = ['name', 'serial_number', 'description']
    ordering_fields = ['created_at', 'name', 'serial_number']
    lookup_field = 'id'

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        serializer = self.get_serializer(page, many=True)
        return self.response(
            data=serializer.data,
            message="Items retrieved successfully",
            count=self.paginator.page.paginator.count,
            next=self.paginator.get_next_link(),
            previous=self.paginator.get_previous_link()
        )

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return self.response(data=serializer.data, message="Item retrieved successfully")

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(owner=request.user)
        return self.response(
            data=serializer.data,
            message="Item created successfully",
            status_code=status.HTTP_201_CREATED
        )

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return self.response(data=serializer.data, message="Item updated successfully")

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return self.response(
            data=None,
            message="Item deleted successfully",
            status_code=status.HTTP_204_NO_CONTENT
        )


class ItemMediaViewSet(ResponseMixin, viewsets.ModelViewSet):
    queryset = ItemMedia.objects.all()
    serializer_class = ItemMediaSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['item', 'media_type']
    ordering_fields = ['uploaded_at']
    pagination_class = StackPagination
    lookup_field = 'id'

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        serializer = self.get_serializer(page, many=True)
        return self.response(
            data=serializer.data,
            message="Item media list retrieved successfully",
            count=self.paginator.page.paginator.count,
            next=self.paginator.get_next_link(),
            previous=self.paginator.get_previous_link()
        )

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return self.response(data=serializer.data, message="Item media retrieved successfully")

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return self.response(
            data=serializer.data,
            message="Item media uploaded successfully",
            status_code=status.HTTP_201_CREATED
        )

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return self.response(
            data=None,
            message="Item media deleted successfully",
            status_code=status.HTTP_204_NO_CONTENT
        )


class StolenReportViewSet(ResponseMixin, viewsets.ModelViewSet):
    queryset = StolenReport.objects.all()
    serializer_class = StolenReportSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['item', 'resolved']
    ordering_fields = ['report_date']
    pagination_class = StackPagination
    lookup_field = 'id'

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        serializer = self.get_serializer(page, many=True)
        return self.response(
            data=serializer.data,
            message="Stolen reports retrieved successfully",
            count=self.paginator.page.paginator.count,
            next=self.paginator.get_next_link(),
            previous=self.paginator.get_previous_link()
        )

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return self.response(data=serializer.data, message="Stolen report retrieved successfully")

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return self.response(
            data=serializer.data,
            message="Stolen report created successfully",
            status_code=status.HTTP_201_CREATED
        )

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=kwargs.get('partial', False))
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return self.response(data=serializer.data, message="Stolen report updated successfully")

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return self.response(
            data=None,
            message="Stolen report deleted successfully",
            status_code=status.HTTP_204_NO_CONTENT
        )
