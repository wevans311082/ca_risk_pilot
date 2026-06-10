from django import template
from auditlog.signing import generate_signed_url

register = template.Library()

@register.simple_tag
def secure_url(url_name, *args, **kwargs):
    """
    Template tag to generate secure, signed URLs with a cryptographic signature.
    Usage: {% secure_url 'download_file' version.id %}
    """
    return generate_signed_url(url_name, args=args, kwargs=kwargs)
