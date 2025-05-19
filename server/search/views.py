from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.db.models import Q

from utils.response import ResponseMixin
from utils.pagination import StackPagination
from items.models import Item
from items.serializers import ItemSerializer


class SearchView(ResponseMixin, APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        q = request.query_params.get('q', '').strip()
        if not q:
            return self.response(
                data=[],
                message="Query parameter 'q' is required",
                status_code=status.HTTP_400_BAD_REQUEST,
                error="Missing 'q' parameter"
            )
        queryset = Item.objects.filter(
            Q(name__icontains=q) |
            Q(serial_number__icontains=q) |
            Q(description__icontains=q)
        ).prefetch_related('media', 'reports')
        paginator = StackPagination()
        page = paginator.paginate_queryset(queryset, request)
        serializer = ItemSerializer(page, many=True)
        return self.response(
            data=serializer.data,
            message="Search results retrieved successfully",
            count=paginator.page.paginator.count,
            next=paginator.get_next_link(),
            previous=paginator.get_previous_link()
        )

# Create your views here.
