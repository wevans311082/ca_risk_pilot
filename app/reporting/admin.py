from django.contrib import admin
from .models import ReportDocument, ReportVersion, ReportDownloadHistory

class ReportVersionInline(admin.TabularInline):
    model = ReportVersion
    extra = 0
    readonly_fields = ('version_number', 'file', 'status', 'error_message', 'generated_by', 'created_at')
    show_change_link = True

@admin.register(ReportDocument)
class ReportDocumentAdmin(admin.ModelAdmin):
    list_display = ('id', 'assessment', 'report_type', 'file_format', 'tenant', 'created_by', 'created_at', 'is_deleted')
    list_filter = ('tenant', 'report_type', 'file_format', 'is_deleted')
    search_fields = ('assessment__name', 'report_type')
    inlines = [ReportVersionInline]

@admin.register(ReportVersion)
class ReportVersionAdmin(admin.ModelAdmin):
    list_display = ('id', 'document', 'version_number', 'status', 'generated_by', 'created_at')
    list_filter = ('status', 'created_at')
    search_fields = ('document__assessment__name', 'error_message')

@admin.register(ReportDownloadHistory)
class ReportDownloadHistoryAdmin(admin.ModelAdmin):
    list_display = ('id', 'version', 'downloaded_by', 'downloaded_at')
    list_filter = ('downloaded_at',)
    search_fields = ('downloaded_by__email', 'version__document__assessment__name')
