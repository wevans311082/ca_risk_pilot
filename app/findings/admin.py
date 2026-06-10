from django.contrib import admin
from .models import Finding, Recommendation

class RecommendationInline(admin.TabularInline):
    model = Recommendation
    extra = 1
    show_change_link = True

@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ('title', 'assessment', 'risk_item', 'tenant', 'status', 'assignee', 'due_date', 'is_deleted')
    list_filter = ('tenant', 'status', 'is_deleted')
    search_fields = ('title', 'description', 'assessment__name')
    ordering = ('-created_at',)
    inlines = [RecommendationInline]

@admin.register(Recommendation)
class RecommendationAdmin(admin.ModelAdmin):
    list_display = ('text_preview', 'finding', 'tenant', 'priority', 'is_deleted')
    list_filter = ('tenant', 'priority', 'is_deleted')
    ordering = ('finding', 'priority')

    def text_preview(self, obj):
        return obj.text[:60] + "..." if len(obj.text) > 60 else obj.text
