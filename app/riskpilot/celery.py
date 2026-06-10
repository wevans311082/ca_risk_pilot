import os
from celery import Celery

# Set default Django settings module for celery command-line tool.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'riskpilot.settings')

app = Celery('riskpilot')

# Load celery settings prefixed with CELERY_ from Django settings
app.config_from_object('django.conf:settings', namespace='CELERY')

# Discover tasks inside registered applications (tasks.py)
app.autodiscover_tasks()

@app.task(bind=True, ignore_result=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
