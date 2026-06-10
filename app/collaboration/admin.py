from django.contrib import admin
from .models import Comment, EvidenceRequest, Notification, CollaborationActivity

@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    list_display = ('user', 'tenant', 'created_at', 'text_preview')
    list_filter = ('tenant', 'created_at')
    search_fields = ('text', 'user__email')

    def text_preview(self, obj):
        return obj.text[:55] + '...' if len(obj.text) > 55 else obj.text

@admin.register(EvidenceRequest)
class EvidenceRequestAdmin(admin.ModelAdmin):
    list_display = ('title', 'client', 'tenant', 'status', 'requested_by', 'created_at')
    list_filter = ('status', 'tenant', 'client')
    search_fields = ('title', 'description', 'client__name')

@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('recipient', 'tenant', 'title', 'is_read', 'created_at')
    list_filter = ('is_read', 'tenant', 'recipient')
    search_fields = ('title', 'message', 'recipient__email')

@admin.register(CollaborationActivity)
class CollaborationActivityAdmin(admin.ModelAdmin):
    list_display = ('user', 'tenant', 'action_type', 'created_at')
    list_filter = ('action_type', 'tenant', 'created_at')
    search_fields = ('description', 'user__email')
