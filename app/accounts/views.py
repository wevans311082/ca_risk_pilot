from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import logout, login as auth_login
from django.contrib.auth.views import LoginView
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth import get_user_model
from auditlog.utils import log_audit_event
from .mfa import verify_totp, generate_mfa_secret
from .models import UserProfile
import urllib.parse

User = get_user_model()

class RiskPilotLoginView(LoginView):
    """
    Custom login view that handles logging failed attempts and redirects
    to MFA verification if MFA is enabled on the user's profile.
    """
    template_name = 'accounts/login.html'
    
    def form_valid(self, form):
        user = form.get_user()
        
        # Ensure profile exists
        profile, _ = UserProfile.objects.get_or_create(user=user)
        
        if profile.mfa_enabled:
            # Keep user unauthenticated, save target user ID in session
            self.request.session['mfa_user_id'] = user.id
            
            # Log pending MFA audit event
            log_audit_event(
                tenant=self.request.tenant,
                user=user,
                event_type='AUTHENTICATION',
                action='MFA_PENDING',
                payload={'email': user.email},
                ip_address=self.request.META.get('REMOTE_ADDR')
            )
            return redirect('mfa_verify')
        
        # No MFA: complete django login
        response = super().form_valid(form)
        
        # Record session key and update concurrency tracking
        user.last_session_key = self.request.session.session_key
        user.save()
        
        # Log successful login
        log_audit_event(
            tenant=self.request.tenant,
            user=user,
            event_type='AUTHENTICATION',
            action='LOGIN',
            payload={'email': user.email},
            ip_address=self.request.META.get('REMOTE_ADDR')
        )
        return response

    def form_invalid(self, form):
        email = form.data.get('username')
        
        # Log failed login attempt
        log_audit_event(
            tenant=self.request.tenant,
            user=None,
            event_type='AUTHENTICATION',
            action='LOGIN_FAILED',
            payload={'email': email},
            ip_address=self.request.META.get('REMOTE_ADDR')
        )
        return super().form_invalid(form)


def logout_view(request):
    """
    Logs out the user and logs the logout event.
    """
    user = request.user
    if user.is_authenticated:
        log_audit_event(
            tenant=request.tenant,
            user=user,
            event_type='AUTHENTICATION',
            action='LOGOUT',
            payload={'email': user.email},
            ip_address=request.META.get('REMOTE_ADDR')
        )
    logout(request)
    return redirect('login')


def mfa_verify_view(request):
    """
    Verifies the 6-digit TOTP code during authentication flow.
    """
    user_id = request.session.get('mfa_user_id')
    if not user_id:
        return redirect('login')
        
    user = get_object_or_404(User, id=user_id)
    profile, _ = UserProfile.objects.get_or_create(user=user)
    
    if request.method == 'POST':
        code = request.POST.get('code', '').strip()
        if verify_totp(profile.mfa_secret, code):
            # Complete login
            auth_login(request, user)
            
            # Record session key
            user.last_session_key = request.session.session_key
            user.save()
            
            # Clean up temp session key
            del request.session['mfa_user_id']
            
            # Log verification success and login
            log_audit_event(
                tenant=request.tenant,
                user=user,
                event_type='AUTHENTICATION',
                action='MFA_VERIFIED',
                payload={'email': user.email},
                ip_address=request.META.get('REMOTE_ADDR')
            )
            log_audit_event(
                tenant=request.tenant,
                user=user,
                event_type='AUTHENTICATION',
                action='LOGIN',
                payload={'email': user.email},
                ip_address=request.META.get('REMOTE_ADDR')
            )
            return redirect('dashboard')
        else:
            # Log verification failure
            log_audit_event(
                tenant=request.tenant,
                user=user,
                event_type='AUTHENTICATION',
                action='MFA_VERIFIED_FAILED',
                payload={'email': user.email},
                ip_address=request.META.get('REMOTE_ADDR')
            )
            messages.error(request, "Invalid 6-digit MFA code.")
            
    return render(request, 'accounts/mfa_verify.html')


@login_required
def mfa_setup_view(request):
    """
    Enables users to activate or deactivate MFA on their profile.
    """
    tenant = request.tenant
    user = request.user
    profile, _ = UserProfile.objects.get_or_create(user=user)
    
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'enable':
            secret = request.POST.get('secret')
            code = request.POST.get('code', '').strip()
            if verify_totp(secret, code):
                profile.mfa_enabled = True
                profile.mfa_secret = secret
                profile.save()
                
                log_audit_event(
                    tenant=tenant,
                    user=user,
                    event_type='AUTHENTICATION',
                    action='MFA_ENABLED',
                    payload={'email': user.email},
                    ip_address=request.META.get('REMOTE_ADDR')
                )
                messages.success(request, "Multi-Factor Authentication (MFA) enabled successfully.")
                return redirect('mfa_setup')
            else:
                messages.error(request, "Invalid verification code. Please scan the QR code and try again.")
        elif action == 'disable':
            profile.mfa_enabled = False
            profile.mfa_secret = ''
            profile.save()
            
            log_audit_event(
                tenant=tenant,
                user=user,
                event_type='AUTHENTICATION',
                action='MFA_DISABLED',
                payload={'email': user.email},
                ip_address=request.META.get('REMOTE_ADDR')
            )
            messages.success(request, "Multi-Factor Authentication (MFA) disabled.")
            return redirect('mfa_setup')
            
    # GET: generate a temporary secret if not already set
    temp_secret = profile.mfa_secret if profile.mfa_enabled else generate_mfa_secret()
    
    # Generate TOTP key URI and format QR code using Google Charts
    qr_data = f"otpauth://totp/RiskPilot:{user.email}?secret={temp_secret}&issuer=RiskPilot"
    qr_url = f"https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl={urllib.parse.quote(qr_data)}"
    
    return render(request, 'accounts/mfa_setup.html', {
        'profile': profile,
        'temp_secret': temp_secret,
        'qr_url': qr_url
    })
