"""
URL configuration for config project.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.http import JsonResponse
from django.db import connections
from django.db.utils import OperationalError

def health_check(request):
    # Verify default database connection is healthy
    try:
        db_conn = connections['default']
        db_conn.cursor()
    except OperationalError:
        return JsonResponse({"status": "unhealthy", "database": "unavailable"}, status=503)
    
    return JsonResponse({"status": "healthy", "database": "ok"})

urlpatterns = [
    path('admin/', admin.site.urls),
    path('health/', health_check, name='health_check'),
    path('accounts/', include('accounts.urls')),
    path('clients/', include('tenants.urls')),
    path('evidence/', include('evidence.urls')),
    path('findings/', include('findings.urls')),
    path('reports/', include('reporting.urls')),
    path('ai/', include('ai_assist.urls')),
    path('collaboration/', include('collaboration.urls')),
    path('assets/', include('assets.urls')),
    path('controls/', include('controls.urls')),
    path('', include('assessments.urls')),
]

# Include Django Debug Toolbar URL pattern in development
if settings.DEBUG:
    try:
        import debug_toolbar
        urlpatterns += [
            path('__debug__/', include(debug_toolbar.urls)),
        ]
    except ImportError:
        pass
