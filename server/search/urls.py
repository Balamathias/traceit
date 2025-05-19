from django.urls import path
from .views import SearchView

urlpatterns = [
    path('items/search/', SearchView.as_view(), name='search-items'),
]
