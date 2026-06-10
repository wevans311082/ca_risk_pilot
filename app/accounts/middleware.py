from django.contrib.auth import logout
from django.contrib import messages
from django.shortcuts import redirect

class SessionConcurrencyMiddleware:
    """
    Middleware that enforces a single-active-session limit.
    If request.user's last_session_key does not match the active session key,
    it automatically logs out the user and redirects them to the login page.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            # Skip checking for superusers to avoid admin lockouts during developer tasks
            if not request.user.is_superuser:
                last_key = getattr(request.user, 'last_session_key', None)
                if last_key and request.session.session_key and request.session.session_key != last_key:
                    # Invalidate session
                    logout(request)
                    messages.warning(
                        request, 
                        "Your session has been terminated because your account was logged in from another device or window."
                    )
                    # Redirect to login page
                    if not request.path.startswith('/accounts/login/'):
                        return redirect('login')
                        
        response = self.get_response(request)
        return response
