from django.contrib import admin
from .models import EvidenceDocument, EvidenceVersion

class EvidenceVersionInline(admin.TabularInline):
    model = EvidenceVersion
    extra = 1
    readonly_fields = ('version_number', 'file_name', 'content_type', 'file_size', 'sha256_hash', 'status', 'scan_results')
    show_change_link = True

@admin.register(EvidenceDocument)
class EvidenceDocumentAdmin(admin.ModelAdmin):
    list_display = ('name', 'tenant', 'assessment', 'risk_item', 'finding', 'treatment', 'created_by', 'created_at')
    list_filter = ('tenant', 'created_at')
    search_fields = ('name', 'assessment__name', 'risk_item__asset_name', 'finding__title')
    inlines = [EvidenceVersionInline]

@admin.register(EvidenceVersion)
class EvidenceVersionAdmin(admin.ModelAdmin):
    list_display = ('file_name', 'document', 'version_number', 'file_size', 'status', 'uploaded_by', 'created_at')
    list_filter = ('status', 'created_at')
    search_fields = ('file_name', 'document__name')
    ordering = ('-created_at',)
