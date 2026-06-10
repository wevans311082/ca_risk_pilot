from django.urls import path
from .views import ai_settings, ai_history, generate_ai_suggestion, ai_suggestion_review

urlpatterns = [
    path('settings/', ai_settings, name='ai_settings'),
    path('history/', ai_history, name='ai_history'),
    path('generate/', generate_ai_suggestion, name='generate_ai_suggestion'),
    path('suggestion/<int:suggestion_id>/review/', ai_suggestion_review, name='ai_suggestion_review'),
]
