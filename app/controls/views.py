from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db import transaction
from django.http import HttpResponseForbidden
from auditlog.utils import log_audit_event
from collaboration.views import create_activity_feed_entry
from tenants.models import Client
from accounts.models import User
from assessments.models import CentralRisk, RiskItem, Assessment
from findings.models import Finding, Recommendation
from .models import Control

@login_required
def control_list(request):
    tenant = getattr(request, 'tenant', None)
    if not tenant:
        messages.error(request, "No active tenant association found.")
        return redirect('login')

    user_role = getattr(request, 'user_role', None)
    user_client = getattr(request, 'user_client', None)

    # Base query
    controls = Control.objects.filter(tenant=tenant).select_related('client')

    # Client isolation
    if user_role == 'client':
        controls = controls.filter(client=user_client)

    # Filtering parameters
    client_id = request.GET.get('client')
    control_type = request.GET.get('control_type')
    effectiveness = request.GET.get('effectiveness')
    maturity = request.GET.get('maturity')

    if user_role != 'client' and client_id:
        controls = controls.filter(client_id=client_id)
    if control_type:
        controls = controls.filter(control_type=control_type)
    if effectiveness:
        controls = controls.filter(effectiveness=effectiveness)
    if maturity:
        controls = controls.filter(maturity=maturity)

    controls_list = list(controls)

    # Metrics
    total_count = len(controls_list)
    admin_count = sum(1 for c in controls_list if c.control_type == 'Administrative')
    tech_count = sum(1 for c in controls_list if c.control_type == 'Technical')
    physical_count = sum(1 for c in controls_list if c.control_type == 'Physical')
    ineffective_count = sum(1 for c in controls_list if c.effectiveness == 'Ineffective')

    filter_clients = Client.objects.filter(tenant=tenant)

    context = {
        'controls': controls_list,
        'active_tenant': tenant,
        'user_role': user_role,
        'filter_clients': filter_clients,
        'selected_client_id': client_id,
        'selected_type': control_type,
        'selected_effectiveness': effectiveness,
        'selected_maturity': maturity,
        
        'total_count': total_count,
        'admin_count': admin_count,
        'tech_count': tech_count,
        'physical_count': physical_count,
        'ineffective_count': ineffective_count,
        
        'type_choices': Control.CONTROL_TYPE_CHOICES,
        'effectiveness_choices': Control.EFFECTIVENESS_CHOICES,
        'maturity_choices': Control.MATURITY_CHOICES,
    }

    return render(request, 'controls/control_list.html', context)

@login_required
def control_detail(request, control_id):
    tenant = request.tenant
    user_role = getattr(request, 'user_role', None)
    user_client = getattr(request, 'user_client', None)

    if user_role == 'client':
        control = get_object_or_404(Control, id=control_id, tenant=tenant, client=user_client)
    else:
        control = get_object_or_404(Control, id=control_id, tenant=tenant)

    linked_risks = control.central_risks.all().prefetch_related('threat')
    linked_assessment_risks = control.assessment_risks.all().prefetch_related('threat', 'assessment')
    linked_assessments = control.assessments.all()
    linked_findings = control.findings.all().prefetch_related('assessment')
    linked_recommendations = control.recommendations.all().prefetch_related('finding')

    return render(request, 'controls/control_detail.html', {
        'control': control,
        'linked_risks': linked_risks,
        'linked_assessment_risks': linked_assessment_risks,
        'linked_assessments': linked_assessments,
        'linked_findings': linked_findings,
        'linked_recommendations': linked_recommendations,
        'active_tenant': tenant,
        'user_role': user_role
    })

@login_required
@transaction.atomic
def control_edit(request, control_id=None):
    tenant = request.tenant
    user_role = getattr(request, 'user_role', None)
    if user_role == 'client':
        return HttpResponseForbidden("Permission denied. Clients cannot edit controls.")

    control = None
    if control_id:
        control = get_object_or_404(Control, id=control_id, tenant=tenant)

    if request.method == 'POST':
        client_id = request.POST.get('client')
        name = request.POST.get('name')
        control_type = request.POST.get('control_type')
        description = request.POST.get('description', '')
        effectiveness = request.POST.get('effectiveness')
        maturity = request.POST.get('maturity')
        last_tested_at = request.POST.get('last_tested_at') or None
        next_test_date = request.POST.get('next_test_date') or None

        # Linkages lists
        central_risk_ids = request.POST.getlist('central_risks')
        assessment_risk_ids = request.POST.getlist('assessment_risks')
        assessment_ids = request.POST.getlist('assessments')
        finding_ids = request.POST.getlist('findings')
        recommendation_ids = request.POST.getlist('recommendations')

        if not name or not client_id or not control_type or not effectiveness or not maturity:
            messages.error(request, "Required fields are missing.")
            return redirect(request.path)

        client = get_object_or_404(Client, id=client_id, tenant=tenant)

        is_new = control is None
        if is_new:
            control = Control(tenant=tenant)

        control.client = client
        control.name = name
        control.control_type = control_type
        control.description = description
        control.effectiveness = effectiveness
        control.maturity = maturity
        control.last_tested_at = last_tested_at
        control.next_test_date = next_test_date
        control.save()

        # Set linkages ManyToMany relationships
        control.central_risks.set(CentralRisk.objects.filter(id__in=central_risk_ids, tenant=tenant))
        control.assessment_risks.set(RiskItem.objects.filter(id__in=assessment_risk_ids, tenant=tenant))
        control.assessments.set(Assessment.objects.filter(id__in=assessment_ids, tenant=tenant))
        control.findings.set(Finding.objects.filter(id__in=finding_ids, tenant=tenant))
        control.recommendations.set(Recommendation.objects.filter(id__in=recommendation_ids, tenant=tenant))

        log_audit_event(
            tenant=tenant,
            user=request.user,
            event_type='CONTROL',
            action='CREATE' if is_new else 'UPDATE',
            payload={'control_id': control.id, 'name': control.name},
            ip_address=request.META.get('REMOTE_ADDR')
        )

        create_activity_feed_entry(
            tenant, request.user, 'control_updated' if not is_new else 'control_created',
            f"Saved control '{control.name}'"
        )

        messages.success(request, f"Control '{control.name}' saved successfully.")
        return redirect('controls:control_detail', control_id=control.id)

    clients = Client.objects.filter(tenant=tenant)
    central_risks = CentralRisk.objects.filter(tenant=tenant).select_related('threat')
    assessment_risks = RiskItem.objects.filter(tenant=tenant).select_related('threat', 'assessment')
    assessments = Assessment.objects.filter(tenant=tenant)
    findings = Finding.objects.filter(tenant=tenant)
    recommendations = Recommendation.objects.filter(tenant=tenant).select_related('finding')

    # Gather currently linked IDs
    linked_central_risk_ids = list(control.central_risks.values_list('id', flat=True)) if control else []
    linked_assessment_risk_ids = list(control.assessment_risks.values_list('id', flat=True)) if control else []
    linked_assessment_ids = list(control.assessments.values_list('id', flat=True)) if control else []
    linked_finding_ids = list(control.findings.values_list('id', flat=True)) if control else []
    linked_recommendation_ids = list(control.recommendations.values_list('id', flat=True)) if control else []

    return render(request, 'controls/control_edit.html', {
        'control': control,
        'clients': clients,
        'central_risks': central_risks,
        'assessment_risks': assessment_risks,
        'assessments': assessments,
        'findings': findings,
        'recommendations': recommendations,
        'type_choices': Control.CONTROL_TYPE_CHOICES,
        'effectiveness_choices': Control.EFFECTIVENESS_CHOICES,
        'maturity_choices': Control.MATURITY_CHOICES,
        'linked_central_risk_ids': linked_central_risk_ids,
        'linked_assessment_risk_ids': linked_assessment_risk_ids,
        'linked_assessment_ids': linked_assessment_ids,
        'linked_finding_ids': linked_finding_ids,
        'linked_recommendation_ids': linked_recommendation_ids,
        'active_tenant': tenant,
    })

@login_required
@transaction.atomic
def control_delete(request, control_id):
    tenant = request.tenant
    user_role = getattr(request, 'user_role', None)
    if user_role == 'client':
        return HttpResponseForbidden("Permission denied. Clients cannot delete controls.")

    control = get_object_or_404(Control, id=control_id, tenant=tenant)
    name = control.name
    control.delete()

    log_audit_event(
        tenant=tenant,
        user=request.user,
        event_type='CONTROL',
        action='DELETE',
        payload={'control_id': control_id, 'name': name},
        ip_address=request.META.get('REMOTE_ADDR')
    )

    create_activity_feed_entry(
        tenant, request.user, 'control_deleted',
        f"Deleted control '{name}'"
    )

    messages.success(request, f"Control '{name}' deleted successfully.")
    return redirect('controls:control_list')
