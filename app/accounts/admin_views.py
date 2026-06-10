import json
import secrets
import urllib.parse
import urllib.request
import uuid
from functools import wraps

from django.contrib import messages
from django.contrib.auth import get_user_model, login as auth_login
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone

from auditlog.utils import log_audit_event
from tenants.models import Client, Tenant, UserTenantMembership

from .forms import TenantSsoSettingsForm, TenantUserForm
from .models import UserProfile


User = get_user_model()
MICROSOFT_AUTHORIZE_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
MICROSOFT_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
MICROSOFT_JWKS_URL = "https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"


def tenant_admin_required(view_func):
    @wraps(view_func)
    @login_required
    def wrapper(request, *args, **kwargs):
        tenant = getattr(request, "tenant", None)
        if not tenant:
            messages.error(request, "No active tenant association found for your account.")
            return redirect("dashboard")
        if request.user.is_superuser or request.user.is_tenant_admin(tenant):
            return view_func(request, *args, **kwargs)
        messages.error(request, "Permission denied. Administrator access is required.")
        return redirect("dashboard")

    return wrapper


@tenant_admin_required
def admin_dashboard(request):
    tenant = request.tenant
    memberships = UserTenantMembership.objects.filter(tenant=tenant).select_related("user", "client")
    users = User.objects.filter(memberships__tenant=tenant).distinct()
    mfa_enabled_count = UserProfile.objects.filter(user__in=users, mfa_enabled=True).count()

    return render(
        request,
        "accounts/admin/dashboard.html",
        {
            "active_tenant": tenant,
            "user_count": users.count(),
            "active_user_count": users.filter(is_active=True).count(),
            "client_count": Client.objects.filter(tenant=tenant).count(),
            "mfa_enabled_count": mfa_enabled_count,
            "sso_configured": bool(tenant.m365_sso_enabled and tenant.m365_client_id),
            "recent_memberships": memberships.order_by("-created_at")[:8],
        },
    )


@tenant_admin_required
def user_list(request):
    memberships = (
        UserTenantMembership.objects.filter(tenant=request.tenant)
        .select_related("user", "client")
        .order_by("user__email")
    )
    return render(
        request,
        "accounts/admin/user_list.html",
        {"active_tenant": request.tenant, "memberships": memberships},
    )


@tenant_admin_required
def user_create(request):
    form = TenantUserForm(request.POST or None, tenant=request.tenant)
    if request.method == "POST" and form.is_valid():
        user = form.save()
        messages.success(request, f"{user.email} was added to {request.tenant.name}.")
        log_audit_event(
            tenant=request.tenant,
            user=request.user,
            event_type="USER_MANAGEMENT",
            action="USER_CREATED",
            payload={"target_user": user.email},
            ip_address=request.META.get("REMOTE_ADDR"),
        )
        return redirect("admin_user_list")
    return render(
        request,
        "accounts/admin/user_form.html",
        {"form": form, "active_tenant": request.tenant, "mode": "create"},
    )


@tenant_admin_required
def user_edit(request, user_id):
    user = get_object_or_404(User, pk=user_id, memberships__tenant=request.tenant)
    membership = get_object_or_404(UserTenantMembership, user=user, tenant=request.tenant)
    form = TenantUserForm(request.POST or None, instance=user, tenant=request.tenant, membership=membership)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, f"{user.email} was updated.")
        log_audit_event(
            tenant=request.tenant,
            user=request.user,
            event_type="USER_MANAGEMENT",
            action="USER_UPDATED",
            payload={"target_user": user.email},
            ip_address=request.META.get("REMOTE_ADDR"),
        )
        return redirect("admin_user_list")
    return render(
        request,
        "accounts/admin/user_form.html",
        {"form": form, "active_tenant": request.tenant, "target_user": user, "mode": "edit"},
    )


@tenant_admin_required
def user_toggle_active(request, user_id):
    if request.method != "POST":
        return redirect("admin_user_list")
    user = get_object_or_404(User, pk=user_id, memberships__tenant=request.tenant)
    if user == request.user:
        messages.error(request, "You cannot deactivate your own account.")
        return redirect("admin_user_list")
    user.is_active = not user.is_active
    user.save(update_fields=["is_active"])
    messages.success(request, f"{user.email} is now {'active' if user.is_active else 'inactive'}.")
    return redirect("admin_user_list")


@tenant_admin_required
def user_reset_mfa(request, user_id):
    if request.method != "POST":
        return redirect("admin_user_list")
    user = get_object_or_404(User, pk=user_id, memberships__tenant=request.tenant)
    profile, _ = UserProfile.objects.get_or_create(user=user)
    profile.mfa_enabled = False
    profile.mfa_secret = ""
    profile.save(update_fields=["mfa_enabled", "mfa_secret", "updated_at"])
    messages.success(request, f"MFA was reset for {user.email}.")
    log_audit_event(
        tenant=request.tenant,
        user=request.user,
        event_type="USER_MANAGEMENT",
        action="MFA_RESET",
        payload={"target_user": user.email},
        ip_address=request.META.get("REMOTE_ADDR"),
    )
    return redirect("admin_user_list")


@tenant_admin_required
def sso_settings(request):
    form = TenantSsoSettingsForm(request.POST or None, instance=request.tenant)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Microsoft sign-in settings were updated.")
        log_audit_event(
            tenant=request.tenant,
            user=request.user,
            event_type="CONFIGURATION",
            action="M365_SSO_UPDATED",
            payload={"enabled": request.tenant.m365_sso_enabled},
            ip_address=request.META.get("REMOTE_ADDR"),
        )
        return redirect("admin_sso_settings")
    return render(
        request,
        "accounts/admin/sso_settings.html",
        {
            "form": form,
            "active_tenant": request.tenant,
            "redirect_uri": request.build_absolute_uri(reverse("m365_sso_callback")),
        },
    )


def _resolve_sso_tenant(request):
    tenant_ref = request.GET.get("tenant", "").strip()
    if tenant_ref:
        tenant = Tenant.objects.filter(domain__iexact=tenant_ref, status="active", is_deleted=False).first()
        if tenant:
            return tenant
        return Tenant.objects.filter(pk=tenant_ref, status="active", is_deleted=False).first()
    tenant = getattr(request, "tenant", None)
    if tenant and tenant.m365_sso_enabled:
        return tenant
    return Tenant.objects.filter(status="active", is_deleted=False, m365_sso_enabled=True).first()


def m365_login_start(request):
    tenant = _resolve_sso_tenant(request)
    if not tenant or not tenant.m365_sso_enabled or not tenant.m365_client_id or not tenant.m365_client_secret:
        messages.error(request, "Microsoft sign-in is not configured for this tenant.")
        return redirect("login")

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    request.session["m365_sso"] = {
        "state": state,
        "nonce": nonce,
        "tenant_id": tenant.pk,
        "next": request.GET.get("next") or request.GET.get("next_url") or reverse("dashboard"),
        "created_at": timezone.now().isoformat(),
    }
    authority = tenant.microsoft_tenant_id or "organizations"
    params = {
        "client_id": tenant.m365_client_id,
        "response_type": "code",
        "redirect_uri": request.build_absolute_uri(reverse("m365_sso_callback")),
        "response_mode": "query",
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
    }
    return redirect(f"{MICROSOFT_AUTHORIZE_URL.format(tenant=authority)}?{urllib.parse.urlencode(params)}")


def m365_login_callback(request):
    session_state = request.session.get("m365_sso") or {}
    if request.GET.get("error"):
        messages.error(request, request.GET.get("error_description") or "Microsoft sign-in was cancelled.")
        return redirect("login")
    if not session_state or request.GET.get("state") != session_state.get("state"):
        messages.error(request, "Microsoft sign-in state validation failed. Please try again.")
        return redirect("login")

    tenant = get_object_or_404(Tenant, pk=session_state.get("tenant_id"), status="active", is_deleted=False)
    code = request.GET.get("code")
    if not code:
        messages.error(request, "Microsoft sign-in did not return an authorization code.")
        return redirect("login")

    try:
        token_payload = _exchange_m365_code(request, tenant, code)
        claims = _verify_m365_id_token(tenant, token_payload["id_token"], session_state.get("nonce"))
        user = _get_or_create_sso_user(tenant, claims)
    except Exception as exc:
        messages.error(request, f"Microsoft sign-in failed: {exc}")
        return redirect("login")

    request.session.pop("m365_sso", None)
    profile, _ = UserProfile.objects.get_or_create(user=user)
    if profile.mfa_enabled:
        request.session["mfa_user_id"] = user.id
        return redirect("mfa_verify")

    auth_login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    user.last_session_key = request.session.session_key
    user.save(update_fields=["last_session_key"])
    log_audit_event(
        tenant=tenant,
        user=user,
        event_type="AUTHENTICATION",
        action="M365_LOGIN",
        payload={"email": user.email},
        ip_address=request.META.get("REMOTE_ADDR"),
    )
    return redirect(session_state.get("next") or "dashboard")


def _exchange_m365_code(request, tenant, code):
    authority = tenant.microsoft_tenant_id or "organizations"
    data = urllib.parse.urlencode(
        {
            "client_id": tenant.m365_client_id,
            "client_secret": tenant.m365_client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": request.build_absolute_uri(reverse("m365_sso_callback")),
            "scope": "openid email profile",
        }
    ).encode()
    req = urllib.request.Request(
        MICROSOFT_TOKEN_URL.format(tenant=authority),
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=15) as response:
        payload = json.loads(response.read().decode())
    if "id_token" not in payload:
        raise ValueError("Microsoft did not return an ID token.")
    return payload


def _verify_m365_id_token(tenant, id_token, expected_nonce):
    try:
        import jwt
    except ImportError as exc:
        raise ValueError("PyJWT is not installed. Reinstall dependencies before enabling Microsoft sign-in.") from exc

    unverified = jwt.decode(id_token, options={"verify_signature": False})
    token_tenant_id = unverified.get("tid")
    configured_tenant_id = tenant.microsoft_tenant_id or ""
    configured_is_guid = _is_guid(configured_tenant_id)
    if configured_is_guid and token_tenant_id and configured_tenant_id.lower() != token_tenant_id.lower():
        raise ValueError("The Microsoft tenant in the token does not match this workspace.")

    jwks_tenant = token_tenant_id or tenant.microsoft_tenant_id or "organizations"
    jwk_client = jwt.PyJWKClient(MICROSOFT_JWKS_URL.format(tenant=jwks_tenant))
    signing_key = jwk_client.get_signing_key_from_jwt(id_token)
    issuer = unverified.get("iss")
    claims = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=tenant.m365_client_id,
        issuer=issuer,
    )
    if claims.get("nonce") != expected_nonce:
        raise ValueError("Microsoft sign-in nonce validation failed.")
    return claims


def _get_or_create_sso_user(tenant, claims):
    email = (claims.get("preferred_username") or claims.get("email") or claims.get("upn") or "").strip().lower()
    if not email:
        raise ValueError("Microsoft did not provide an email address.")

    user = User.objects.filter(email__iexact=email).first()
    if not user:
        if not tenant.m365_auto_create_users:
            raise ValueError("Your account has not been provisioned in this workspace.")
        user = User(email=email, username=email, first_name=claims.get("given_name", ""), last_name=claims.get("family_name", ""))
        user.set_unusable_password()
        user.save()
        UserProfile.objects.get_or_create(user=user)

    if not user.is_active:
        raise ValueError("Your RiskPilot account is inactive.")

    UserTenantMembership.objects.get_or_create(
        user=user,
        tenant=tenant,
        defaults={"role": tenant.m365_default_role},
    )
    return user


def _is_guid(value):
    try:
        uuid.UUID(str(value))
    except (TypeError, ValueError):
        return False
    return True
