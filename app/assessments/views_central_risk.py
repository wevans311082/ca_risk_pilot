import json
import datetime
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db import transaction
from django.db.models import Q, Avg
from django.utils import timezone
from django.http import Http404, HttpResponseForbidden

from accounts.models import User
from tenants.models import Client
from auditlog.utils import log_audit_event
from collaboration.views import create_activity_feed_entry
from .models import (
    AssessmentMethodologyVersion, ThreatFrequencyCriteria,
    VulnerabilityProbabilityCriteria, ImpactCriteria, Threat,
    CentralRisk, RiskHistory, RiskItem
)

def get_snapshot(risk):
    """
    Helper to serialize CentralRisk attributes for history snapshots.
    """
    return {
        'asset_name': risk.asset_name,
        'asset_location': risk.asset_location,
        'asset_owner': risk.asset_owner,
        'threat_id': risk.threat_id,
        'vulnerability': risk.vulnerability,
        'existing_controls': risk.existing_controls,
        'threat_frequency_id': risk.threat_frequency_id,
        'vulnerability_probability_id': risk.vulnerability_probability_id,
        'impact_severity_id': risk.impact_severity_id,
        'proposed_controls': risk.proposed_controls,
        'additional_mitigations': risk.additional_mitigations,
        'residual_threat_frequency_id': risk.residual_threat_frequency_id,
        'residual_vulnerability_probability_id': risk.residual_vulnerability_probability_id,
        'residual_impact_severity_id': risk.residual_impact_severity_id,
        'status': risk.status,
        'review_date': str(risk.review_date) if risk.review_date else None,
        'acceptance_status': risk.acceptance_status,
        'acceptance_expiry': str(risk.acceptance_expiry) if risk.acceptance_expiry else None,
        'risk_score': risk.risk_score,
        'residual_risk_score': risk.residual_risk_score,
    }

@login_required
def central_risk_list(request):
    tenant = getattr(request, 'tenant', None)
    if not tenant:
        messages.error(request, "No active tenant association found.")
        return redirect('login')

    user_role = getattr(request, 'user_role', None)
    user_client = getattr(request, 'user_client', None)

    # Base Queryset
    risks = CentralRisk.objects.filter(tenant=tenant).select_related('client', 'owner', 'threat')

    # Enforce Client isolation
    if user_role == 'client':
        risks = risks.filter(client=user_client)

    # Filter parameters
    client_id = request.GET.get('client')
    owner_id = request.GET.get('owner')
    status_filter = request.GET.get('status')
    category_filter = request.GET.get('category')

    if user_role != 'client' and client_id:
        risks = risks.filter(client_id=client_id)
    if owner_id:
        risks = risks.filter(owner_id=owner_id)
    if status_filter:
        risks = risks.filter(status=status_filter)

    # Filter by category in Python (due to calculated property risk_category)
    risks_list = list(risks)
    for r in risks_list:
        r.check_acceptance_expiry()
    if category_filter:
        risks_list = [r for r in risks_list if r.risk_category == category_filter]

    # Metrics
    today = timezone.now().date()
    total_risks = len(risks_list)
    active_risks = sum(1 for r in risks_list if r.status == 'Active')
    accepted_risks = sum(1 for r in risks_list if r.status == 'Accepted')
    
    # Overdue review count
    overdue_reviews = sum(1 for r in risks_list if r.review_date and r.review_date < today and r.status != 'Archived')

    # Filter selections data
    filter_clients = Client.objects.filter(tenant=tenant)
    filter_owners = User.objects.filter(memberships__tenant=tenant)

    # Generate trend tracking data (last 6 months average residual risk score)
    trend_data = []
    # Query history logs representing updates to reconstruct score progression
    history_entries = RiskHistory.objects.filter(
        risk__tenant=tenant
    ).select_related('risk').order_by('changed_at')
    
    if user_role == 'client':
        history_entries = history_entries.filter(risk__client=user_client)

    # Bucket scores by year-month
    month_buckets = {}
    for entry in history_entries:
        try:
            res_score = entry.snapshot.get('residual_risk_score') if entry.snapshot else None
            if res_score is None:
                res_score = entry.snapshot.get('risk_score') # fallback
            if res_score is not None:
                month_key = entry.changed_at.strftime('%Y-%m')
                if month_key not in month_buckets:
                    month_buckets[month_key] = []
                month_buckets[month_key].append(float(res_score))
        except (AttributeError, ValueError):
            pass

    sorted_months = sorted(month_buckets.keys())[-6:] # last 6 months
    for m in sorted_months:
        avg_score = sum(month_buckets[m]) / len(month_buckets[m])
        trend_data.append({
            'month': m,
            'avg_score': round(avg_score, 2)
        })

    # Fallback to current risks if history is sparse
    if not trend_data and risks_list:
        avg_current = sum(r.residual_risk_score or r.risk_score for r in risks_list) / total_risks
        current_month = timezone.now().strftime('%Y-%m')
        trend_data.append({
            'month': current_month,
            'avg_score': round(avg_current, 2)
        })

    context = {
        'risks': risks_list,
        'active_tenant': tenant,
        'user_role': user_role,
        'filter_clients': filter_clients,
        'filter_owners': filter_owners,
        'selected_client_id': client_id,
        'selected_owner_id': owner_id,
        'selected_status': status_filter,
        'selected_category': category_filter,
        
        # Metrics
        'total_risks_count': total_risks,
        'active_risks_count': active_risks,
        'accepted_risks_count': accepted_risks,
        'overdue_reviews_count': overdue_reviews,
        
        # Trend data
        'trend_data': trend_data,
        
        # Select choices
        'status_choices': CentralRisk.STATUS_CHOICES,
        'category_choices': ['Critical', 'High', 'Medium', 'Low'],
    }

    return render(request, 'assessments/central_risk_list.html', context)

@login_required
def central_risk_detail(request, risk_id):
    tenant = request.tenant
    user_role = getattr(request, 'user_role', None)
    user_client = getattr(request, 'user_client', None)

    if user_role == 'client':
        risk = get_object_or_404(CentralRisk, id=risk_id, tenant=tenant, client=user_client)
    else:
        risk = get_object_or_404(CentralRisk, id=risk_id, tenant=tenant)

    risk.check_acceptance_expiry()

    # History trail
    history = risk.history_entries.all().select_related('changed_by').order_by('-changed_at')
    
    # Linked assessment risk items
    linked_items = risk.assessment_items.all().select_related('assessment')

    return render(request, 'assessments/central_risk_detail.html', {
        'risk': risk,
        'history': history,
        'linked_items': linked_items,
        'active_tenant': tenant,
        'user_role': user_role
    })

@login_required
@transaction.atomic
def central_risk_edit(request, risk_id=None):
    tenant = request.tenant
    user_role = getattr(request, 'user_role', None)
    if user_role == 'client':
        return HttpResponseForbidden("Permission denied. Clients cannot edit risk parameters.")

    risk = None
    if risk_id:
        risk = get_object_or_404(CentralRisk, id=risk_id, tenant=tenant)

    # Get active methodology version
    version = AssessmentMethodologyVersion.objects.filter(tenant=tenant, is_active=True).first()
    if not version:
        messages.error(request, "Please set up and activate an Assessment Methodology Version first.")
        return redirect('central_risk_list')

    if request.method == 'POST':
        client_id = request.POST.get('client')
        owner_id = request.POST.get('owner') or None
        asset_name = request.POST.get('asset_name')
        asset_location = request.POST.get('asset_location', '')
        asset_owner = request.POST.get('asset_owner', '')
        threat_id = request.POST.get('threat')
        vulnerability = request.POST.get('vulnerability')
        existing_controls = request.POST.get('existing_controls', '')
        
        confidentiality_affected = 'confidentiality_affected' in request.POST
        integrity_affected = 'integrity_affected' in request.POST
        availability_affected = 'availability_affected' in request.POST

        # Scoring parameters
        freq_id = request.POST.get('threat_frequency')
        prob_id = request.POST.get('vulnerability_probability')
        imp_id = request.POST.get('impact_severity')

        proposed_controls = request.POST.get('proposed_controls', '')
        additional_mitigations = request.POST.get('additional_mitigations', '')

        res_freq_id = request.POST.get('residual_threat_frequency') or None
        res_prob_id = request.POST.get('residual_vulnerability_probability') or None
        res_imp_id = request.POST.get('residual_impact_severity') or None

        status = request.POST.get('status', 'Draft')
        review_date_val = request.POST.get('review_date') or None

        if not asset_name or not threat_id or not freq_id or not prob_id or not imp_id or not client_id:
            messages.error(request, "Required fields are missing.")
            return redirect(request.path)

        client = get_object_or_404(Client, id=client_id, tenant=tenant)
        threat = get_object_or_404(Threat, id=threat_id, tenant=tenant)
        freq = get_object_or_404(ThreatFrequencyCriteria, id=freq_id, methodology_version=version, tenant=tenant)
        prob = get_object_or_404(VulnerabilityProbabilityCriteria, id=prob_id, methodology_version=version, tenant=tenant)
        imp = get_object_or_404(ImpactCriteria, id=imp_id, methodology_version=version, tenant=tenant)

        res_freq = get_object_or_404(ThreatFrequencyCriteria, id=res_freq_id, methodology_version=version, tenant=tenant) if res_freq_id else None
        res_prob = get_object_or_404(VulnerabilityProbabilityCriteria, id=res_prob_id, methodology_version=version, tenant=tenant) if res_prob_id else None
        res_imp = get_object_or_404(ImpactCriteria, id=res_imp_id, methodology_version=version, tenant=tenant) if res_imp_id else None

        owner = get_object_or_404(User, id=owner_id, memberships__tenant=tenant) if owner_id else None

        is_new = risk is None
        if is_new:
            risk = CentralRisk(tenant=tenant)

        risk.client = client
        risk.owner = owner
        risk.asset_name = asset_name
        risk.asset_location = asset_location
        risk.asset_owner = asset_owner
        risk.threat = threat
        risk.vulnerability = vulnerability
        risk.existing_controls = existing_controls
        risk.confidentiality_affected = confidentiality_affected
        risk.integrity_affected = integrity_affected
        risk.availability_affected = availability_affected
        risk.threat_frequency = freq
        risk.vulnerability_probability = prob
        risk.impact_severity = imp
        risk.proposed_controls = proposed_controls
        risk.additional_mitigations = additional_mitigations
        risk.residual_threat_frequency = res_freq
        risk.residual_vulnerability_probability = res_prob
        risk.residual_impact_severity = res_imp
        
        # Maintain lifecycle transitions safely
        if not is_new and risk.status == 'Accepted' and status != 'Accepted':
            # Acceptance revoked/changed status
            risk.acceptance_status = 'None'
            risk.accepted_by = None
            risk.acceptance_date = None
            risk.acceptance_expiry = None
            risk.acceptance_rationale = ''

        risk.status = status
        risk.review_date = review_date_val
        risk.save()

        # Log History Entry
        action_type = "Create" if is_new else "Update"
        desc = f"Risk registry entry {action_type.lower()}d."
        RiskHistory.objects.create(
            tenant=tenant,
            risk=risk,
            changed_by=request.user,
            action=action_type,
            description=desc,
            snapshot=get_snapshot(risk)
        )

        log_audit_event(
            tenant=tenant,
            user=request.user,
            event_type='RISK_ITEM',
            action='CREATE' if is_new else 'UPDATE',
            payload={'central_risk_id': risk.id, 'asset_name': risk.asset_name},
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        create_activity_feed_entry(
            tenant, request.user, 'risk_updated',
            f"Saved central risk '{risk.asset_name}' (Status: {risk.status})"
        )

        messages.success(request, f"Central Risk '{risk.asset_name}' saved successfully.")
        return redirect('central_risk_detail', risk_id=risk.id)

    # Setup context options
    clients = Client.objects.filter(tenant=tenant)
    owners = User.objects.filter(memberships__tenant=tenant)
    threats = Threat.objects.filter(tenant=tenant).select_related('category').order_by('category__name', 'name')
    freq_criteria = ThreatFrequencyCriteria.objects.filter(methodology_version=version, tenant=tenant)
    prob_criteria = VulnerabilityProbabilityCriteria.objects.filter(methodology_version=version, tenant=tenant)
    impact_criteria = ImpactCriteria.objects.filter(methodology_version=version, tenant=tenant)

    return render(request, 'assessments/central_risk_edit.html', {
        'risk': risk,
        'clients': clients,
        'owners': owners,
        'threats': threats,
        'freq_criteria': freq_criteria,
        'prob_criteria': prob_criteria,
        'impact_criteria': impact_criteria,
        'status_choices': CentralRisk.STATUS_CHOICES,
        'active_tenant': tenant,
    })

@login_required
@transaction.atomic
def central_risk_review(request, risk_id):
    tenant = request.tenant
    user_role = getattr(request, 'user_role', None)
    if user_role == 'client':
        return HttpResponseForbidden("Permission denied. Clients cannot review risks.")

    risk = get_object_or_404(CentralRisk, id=risk_id, tenant=tenant)
    version = AssessmentMethodologyVersion.objects.filter(tenant=tenant, is_active=True).first()

    if request.method == 'POST':
        review_notes = request.POST.get('review_notes')
        next_review_date = request.POST.get('next_review_date')
        status = request.POST.get('status', risk.status)

        # Allow updating scores during review
        freq_id = request.POST.get('threat_frequency')
        prob_id = request.POST.get('vulnerability_probability')
        imp_id = request.POST.get('impact_severity')

        if not review_notes or not next_review_date:
            messages.error(request, "Review notes and next review date are required.")
            return redirect(request.path)

        if freq_id:
            risk.threat_frequency = get_object_or_404(ThreatFrequencyCriteria, id=freq_id, methodology_version=version, tenant=tenant)
        if prob_id:
            risk.vulnerability_probability = get_object_or_404(VulnerabilityProbabilityCriteria, id=prob_id, methodology_version=version, tenant=tenant)
        if imp_id:
            risk.impact_severity = get_object_or_404(ImpactCriteria, id=imp_id, methodology_version=version, tenant=tenant)

        # Update review stats
        risk.status = status
        risk.review_date = next_review_date
        risk.last_reviewed_at = timezone.now()
        
        # Reset acceptance if state is no longer Accepted
        if risk.status != 'Accepted':
            risk.acceptance_status = 'None'
            risk.accepted_by = None
            risk.acceptance_date = None
            risk.acceptance_expiry = None
            risk.acceptance_rationale = ''

        risk.save()

        # Log History Entry
        desc = f"Risk reviewed. Notes: {review_notes}"
        RiskHistory.objects.create(
            tenant=tenant,
            risk=risk,
            changed_by=request.user,
            action="Review",
            description=desc,
            snapshot=get_snapshot(risk)
        )

        log_audit_event(
            tenant=tenant,
            user=request.user,
            event_type='RISK_ITEM',
            action='UPDATE',
            payload={'central_risk_id': risk.id, 'review_performed': True},
            ip_address=request.META.get('REMOTE_ADDR')
        )

        messages.success(request, f"Review documented for risk '{risk.asset_name}'.")
        return redirect('central_risk_detail', risk_id=risk.id)

    # Default next review date in 6 months
    default_next_review = (timezone.now() + datetime.timedelta(days=180)).date().strftime('%Y-%m-%d')
    freq_criteria = ThreatFrequencyCriteria.objects.filter(methodology_version=version, tenant=tenant)
    prob_criteria = VulnerabilityProbabilityCriteria.objects.filter(methodology_version=version, tenant=tenant)
    impact_criteria = ImpactCriteria.objects.filter(methodology_version=version, tenant=tenant)

    return render(request, 'assessments/central_risk_review.html', {
        'risk': risk,
        'default_next_review': default_next_review,
        'freq_criteria': freq_criteria,
        'prob_criteria': prob_criteria,
        'impact_criteria': impact_criteria,
        'status_choices': CentralRisk.STATUS_CHOICES,
        'active_tenant': tenant,
    })

@login_required
@transaction.atomic
def central_risk_accept(request, risk_id):
    tenant = request.tenant
    user_role = getattr(request, 'user_role', None)
    if user_role == 'client':
        return HttpResponseForbidden("Permission denied. Clients cannot accept risks.")

    risk = get_object_or_404(CentralRisk, id=risk_id, tenant=tenant)

    if request.method == 'POST':
        rationale = request.POST.get('acceptance_rationale')
        expiry = request.POST.get('acceptance_expiry')

        if not rationale or not expiry:
            messages.error(request, "Acceptance rationale and expiry date are required.")
            return redirect(request.path)

        risk.status = 'Accepted'
        risk.acceptance_status = 'Accepted'
        risk.accepted_by = request.user
        risk.acceptance_rationale = rationale
        risk.acceptance_date = timezone.now().date()
        risk.acceptance_expiry = expiry
        risk.save()

        # Log History Entry
        desc = f"Risk accepted until {expiry}. Rationale: {rationale}"
        RiskHistory.objects.create(
            tenant=tenant,
            risk=risk,
            changed_by=request.user,
            action="Acceptance",
            description=desc,
            snapshot=get_snapshot(risk)
        )

        log_audit_event(
            tenant=tenant,
            user=request.user,
            event_type='RISK_ITEM',
            action='UPDATE',
            payload={'central_risk_id': risk.id, 'acceptance_approved': True},
            ip_address=request.META.get('REMOTE_ADDR')
        )

        messages.success(request, f"Risk '{risk.asset_name}' has been officially accepted.")
        return redirect('central_risk_detail', risk_id=risk.id)

    # Default expiry is 1 year from now
    default_expiry = (timezone.now() + datetime.timedelta(days=365)).date().strftime('%Y-%m-%d')

    return render(request, 'assessments/central_risk_accept.html', {
        'risk': risk,
        'default_expiry': default_expiry,
        'active_tenant': tenant,
    })
