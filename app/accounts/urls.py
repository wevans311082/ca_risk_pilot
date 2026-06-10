from django.urls import path
from .views import RiskPilotLoginView, logout_view, mfa_verify_view, mfa_setup_view

urlpatterns = [
    path('login/', RiskPilotLoginView.as_view(), name='login'),
    path('logout/', logout_view, name='logout'),
    path('mfa/verify/', mfa_verify_view, name='mfa_verify'),
    path('mfa/setup/', mfa_setup_view, name='mfa_setup'),
]
