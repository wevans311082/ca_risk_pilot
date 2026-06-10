from django.urls import path
from .views import (
    add_comment,
    notifications_list,
    api_unread_notifications,
    mark_notification_read,
    mark_all_notifications_read,
    evidence_requests_list,
    submit_evidence_response,
    approve_reject_evidence_request
)

urlpatterns = [
    path('comment/add/', add_comment, name='add_comment'),
    path('notifications/', notifications_list, name='notifications_list'),
    path('api/notifications/', api_unread_notifications, name='api_unread_notifications'),
    path('api/notifications/<int:notif_id>/read/', mark_notification_read, name='mark_notification_read'),
    path('api/notifications/read-all/', mark_all_notifications_read, name='mark_all_notifications_read'),
    path('requests/', evidence_requests_list, name='evidence_requests_list'),
    path('requests/<int:request_id>/submit/', submit_evidence_response, name='submit_evidence_response'),
    path('requests/<int:request_id>/review/', approve_reject_evidence_request, name='approve_reject_evidence_request'),
]
