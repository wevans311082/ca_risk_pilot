from django.contrib import admin
from .models import Control

@admin.register(Control)
class ControlAdmin(admin.ModelAdmin):
    list_display = ('name', 'control_type', 'client', 'effectiveness', 'maturity', 'last_tested_at', 'next_test_date')
    list_filter = ('control_type', 'effectiveness', 'maturity', 'tenant', 'client')
    search_fields = ('name', 'description')
    filter_horizontal = ('central_risks', 'assessment_risks', 'assessments', 'findings', 'recommendations')
