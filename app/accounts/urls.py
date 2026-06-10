from django.urls import path

from .admin_views import (
    admin_dashboard,
    m365_login_callback,
    m365_login_start,
    sso_settings,
    user_create,
    user_edit,
    user_list,
    user_reset_mfa,
    user_toggle_active,
)
from .views import RiskPilotLoginView, logout_view, mfa_setup_view, mfa_verify_view

urlpatterns = [
    path('login/', RiskPilotLoginView.as_view(), name='login'),
    path('logout/', logout_view, name='logout'),
    path('mfa/verify/', mfa_verify_view, name='mfa_verify'),
    path('mfa/setup/', mfa_setup_view, name='mfa_setup'),
    path('sso/microsoft/start/', m365_login_start, name='m365_sso_start'),
    path('sso/microsoft/callback/', m365_login_callback, name='m365_sso_callback'),
    path('admin/', admin_dashboard, name='admin_dashboard'),
    path('admin/users/', user_list, name='admin_user_list'),
    path('admin/users/new/', user_create, name='admin_user_create'),
    path('admin/users/<int:user_id>/edit/', user_edit, name='admin_user_edit'),
    path('admin/users/<int:user_id>/toggle-active/', user_toggle_active, name='admin_user_toggle_active'),
    path('admin/users/<int:user_id>/reset-mfa/', user_reset_mfa, name='admin_user_reset_mfa'),
    path('admin/sso/', sso_settings, name='admin_sso_settings'),
]
