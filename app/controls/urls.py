from django.urls import path
from .views import (
    control_list, control_detail, control_edit, control_delete
)

app_name = 'controls'

urlpatterns = [
    path('', control_list, name='control_list'),
    path('add/', control_edit, name='control_add'),
    path('<int:control_id>/', control_detail, name='control_detail'),
    path('<int:control_id>/edit/', control_edit, name='control_edit'),
    path('<int:control_id>/delete/', control_delete, name='control_delete'),
]
