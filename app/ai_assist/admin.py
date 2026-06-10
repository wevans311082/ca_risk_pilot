from django.contrib import admin
from .models import AISuggestion, AISettings, AIInteraction

@admin.register(AISuggestion)
class AISuggestionAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'tenant', 'risk_item', 'finding', 'created_at', 'is_deleted')
    list_filter = ('tenant', 'is_deleted')
    search_fields = ('prompt', 'suggestion_text')
    ordering = ('-created_at',)


@admin.register(AISettings)
class AISettingsAdmin(admin.ModelAdmin):
    list_display = ('tenant', 'provider', 'model_name', 'is_deleted')
    list_filter = ('tenant', 'provider', 'is_deleted')
    search_fields = ('model_name',)


@admin.register(AIInteraction)
class AIInteractionAdmin(admin.ModelAdmin):
    list_display = ('feature', 'tenant', 'user', 'model_used', 'created_at')
    list_filter = ('tenant', 'feature', 'model_used')
    search_fields = ('prompt', 'response')
