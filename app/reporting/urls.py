from django.urls import path
from .views import reporting_center, generate_report, download_report, delete_report

urlpatterns = [
    path('', reporting_center, name='reporting_center'),
    path('generate/', generate_report, name='generate_report'),
    path('download/<int:version_id>/', download_report, name='download_report'),
    path('delete/<int:doc_id>/', delete_report, name='delete_report'),
]
