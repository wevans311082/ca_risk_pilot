from django.urls import path
from .views import (
    asset_list, asset_detail, asset_edit, asset_delete
)

app_name = 'assets'

urlpatterns = [
    path('', asset_list, name='asset_list'),
    path('add/', asset_edit, name='asset_add'),
    path('<int:asset_id>/', asset_detail, name='asset_detail'),
    path('<int:asset_id>/edit/', asset_edit, name='asset_edit'),
    path('<int:asset_id>/delete/', asset_delete, name='asset_delete'),
]
