from django.urls import path
from .views import document_library, upload_new_version, download_file, delete_document

urlpatterns = [
    path('', document_library, name='document_library'),
    path('upload-version/<int:doc_id>/', upload_new_version, name='upload_new_version'),
    path('download/<int:version_id>/', download_file, name='download_file'),
    path('delete/<int:doc_id>/', delete_document, name='delete_document'),
]
