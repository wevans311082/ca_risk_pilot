from django import forms
from django.contrib.auth import get_user_model

from .models import UserProfile
from tenants.models import Client, Tenant, UserTenantMembership


User = get_user_model()


class TenantUserForm(forms.ModelForm):
    role = forms.ChoiceField(choices=UserTenantMembership.ROLE_CHOICES)
    client = forms.ModelChoiceField(queryset=Client.objects.none(), required=False)
    password = forms.CharField(
        required=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        help_text="Leave blank to keep the existing password. Required for new local users unless they use SSO.",
    )
    title = forms.CharField(required=False, max_length=100)
    department = forms.CharField(required=False, max_length=100)
    phone_number = forms.CharField(required=False, max_length=50, label="Phone")

    class Meta:
        model = User
        fields = ["email", "first_name", "last_name", "is_active"]

    def __init__(self, *args, tenant=None, membership=None, **kwargs):
        self.tenant = tenant
        self.membership = membership
        super().__init__(*args, **kwargs)
        self.fields["client"].queryset = Client.objects.filter(tenant=tenant) if tenant else Client.objects.none()

        if membership:
            self.fields["role"].initial = membership.role
            self.fields["client"].initial = membership.client

        profile = getattr(self.instance, "profile", None)
        if profile:
            self.fields["title"].initial = profile.title
            self.fields["department"].initial = profile.department
            self.fields["phone_number"].initial = profile.phone_number

        for field in self.fields.values():
            css_class = "form-select" if isinstance(field.widget, forms.Select) else "form-control"
            if isinstance(field.widget, forms.CheckboxInput):
                css_class = "form-check-input"
            field.widget.attrs.setdefault("class", css_class)

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        exists = User.objects.filter(email__iexact=email)
        if self.instance.pk:
            exists = exists.exclude(pk=self.instance.pk)
        if exists.exists():
            raise forms.ValidationError("A user with this email already exists.")
        return email

    def clean(self):
        cleaned = super().clean()
        if not self.instance.pk and not cleaned.get("password"):
            raise forms.ValidationError("Set a password for local users. SSO-created users are created automatically at first sign-in.")
        if cleaned.get("role") == "client" and not cleaned.get("client"):
            self.add_error("client", "Client users must be linked to a client.")
        return cleaned

    def save(self, commit=True):
        user = super().save(commit=False)
        user.username = user.email
        password = self.cleaned_data.get("password")
        if password:
            user.set_password(password)
        if commit:
            user.save()
            profile, _ = UserProfile.objects.get_or_create(user=user)
            profile.title = self.cleaned_data.get("title", "")
            profile.department = self.cleaned_data.get("department", "")
            profile.phone_number = self.cleaned_data.get("phone_number", "")
            profile.save()
            UserTenantMembership.objects.update_or_create(
                user=user,
                tenant=self.tenant,
                defaults={
                    "role": self.cleaned_data["role"],
                    "client": self.cleaned_data.get("client"),
                },
            )
        return user


class TenantSsoSettingsForm(forms.ModelForm):
    m365_client_secret = forms.CharField(
        required=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        help_text="Leave blank to keep the existing secret.",
    )

    class Meta:
        model = Tenant
        fields = [
            "microsoft_tenant_id",
            "m365_sso_enabled",
            "m365_client_id",
            "m365_client_secret",
            "m365_auto_create_users",
            "m365_default_role",
        ]
        labels = {
            "microsoft_tenant_id": "Microsoft tenant ID",
            "m365_sso_enabled": "Enable Microsoft sign-in",
            "m365_client_id": "Application client ID",
            "m365_client_secret": "Application client secret",
            "m365_auto_create_users": "Create users on first SSO sign-in",
            "m365_default_role": "Default role for new SSO users",
        }

    def __init__(self, *args, **kwargs):
        self._existing_secret = kwargs.get("instance").m365_client_secret if kwargs.get("instance") else ""
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            css_class = "form-select" if isinstance(field.widget, forms.Select) else "form-control"
            if isinstance(field.widget, forms.CheckboxInput):
                css_class = "form-check-input"
            field.widget.attrs.setdefault("class", css_class)

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("m365_sso_enabled"):
            for field in ["microsoft_tenant_id", "m365_client_id"]:
                if not cleaned.get(field):
                    self.add_error(field, "This field is required when Microsoft sign-in is enabled.")
            if not cleaned.get("m365_client_secret") and not self._existing_secret:
                self.add_error("m365_client_secret", "This field is required when Microsoft sign-in is enabled.")
        return cleaned

    def save(self, commit=True):
        tenant = super().save(commit=False)
        if not self.cleaned_data.get("m365_client_secret"):
            tenant.m365_client_secret = self._existing_secret
        if commit:
            tenant.save()
        return tenant
