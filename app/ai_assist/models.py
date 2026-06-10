from django.db import models
from tenants.models import TenantOwnedSoftDeleteModel

class AISuggestion(TenantOwnedSoftDeleteModel):
    """
    AI-generated risk response and mitigation suggestion.
    """
    risk_item = models.ForeignKey('assessments.RiskItem', on_delete=models.CASCADE, related_name='ai_suggestions', null=True, blank=True)
    finding = models.ForeignKey('findings.Finding', on_delete=models.CASCADE, related_name='ai_suggestions', null=True, blank=True)
    
    prompt = models.TextField(help_text="The prompt template submitted to the LLM.")
    suggestion_text = models.TextField(help_text="The raw structured suggestion output returned by the LLM.")
    status = models.CharField(
        max_length=50, 
        default='Pending', 
        choices=[('Pending', 'Pending Review'), ('Applied', 'Applied'), ('Rejected', 'Rejected')]
    )

    class Meta:
        indexes = [
            models.Index(fields=['tenant', 'risk_item']),
            models.Index(fields=['tenant', 'finding']),
        ]

    def __str__(self):
        target = f"Finding {self.finding_id}" if self.finding_id else f"RiskItem {self.risk_item_id}"
        return f"AI Suggestion for {target}"


class AISettings(TenantOwnedSoftDeleteModel):
    PROVIDER_CHOICES = [
        ('Gemini', 'Gemini'),
        ('OpenAI', 'OpenAI'),
        ('Ollama', 'Ollama'),
    ]
    provider = models.CharField(max_length=50, choices=PROVIDER_CHOICES, default='Gemini')
    api_key = models.CharField(max_length=255, blank=True, help_text="API key for Gemini/OpenAI")
    api_url = models.CharField(max_length=255, blank=True, help_text="Base URL/host configuration (e.g. http://localhost:11434 for Ollama)")
    model_name = models.CharField(max_length=100, default='gemini-1.5-flash', help_text="Model name identifier (e.g. gpt-4o, llama3)")

    class Meta:
        indexes = [
            models.Index(fields=['tenant']),
        ]

    def __str__(self):
        return f"AI Settings for {self.tenant.name} ({self.provider})"


class AIInteraction(TenantOwnedSoftDeleteModel):
    user = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='ai_interactions')
    feature = models.CharField(max_length=100, help_text="The AI feature helper identifier.")
    prompt = models.TextField(help_text="The prompt template submitted to the LLM.")
    response = models.TextField(help_text="The suggestion output returned by the LLM.")
    model_used = models.CharField(max_length=100, help_text="Model used during completion.")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['tenant', 'feature']),
            models.Index(fields=['tenant', 'created_at']),
        ]

    def __str__(self):
        return f"AI Log ({self.feature}) - {self.created_at}"
