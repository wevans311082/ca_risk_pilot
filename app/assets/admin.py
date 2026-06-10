from django.contrib import admin
from .models import Asset

@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ('name', 'asset_type', 'client', 'owner', 'classification', 'criticality', 'location')
    list_filter = ('asset_type', 'classification', 'criticality', 'tenant', 'client')
    search_fields = ('name', 'supplier', 'business_function', 'location')
    filter_horizontal = ('central_risks', 'assessment_risks', 'assessments', 'evidence_documents')
