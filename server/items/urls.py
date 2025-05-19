from rest_framework.routers import DefaultRouter
from .views import ItemViewSet, ItemMediaViewSet, StolenReportViewSet

router = DefaultRouter()
router.register(r'items', ItemViewSet, basename='item')
router.register(r'media', ItemMediaViewSet, basename='itemmedia')
router.register(r'reports', StolenReportViewSet, basename='stolenreport')

urlpatterns = router.urls
