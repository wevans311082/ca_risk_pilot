from django.urls import path
from .views import finding_list, finding_edit, finding_delete

urlpatterns = [
    path('', finding_list, name='finding_list'),
    path('create/', finding_edit, name='finding_create'),
    path('<int:finding_id>/edit/', finding_edit, name='finding_edit'),
    path('<int:finding_id>/delete/', finding_delete, name='finding_delete'),
]
