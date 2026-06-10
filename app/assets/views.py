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
from evidence.models import EvidenceDocument
from .models import Asset

@login_required
def asset_list(request):
    tenant = getattr(request, 'tenant', None)
    if not tenant:
        messages.error(request, "No active tenant association found.")
        return redirect('login')

    user_role = getattr(request, 'user_role', None)
    user_client = getattr(request, 'user_client', None)

    # Base query
    assets = Asset.objects.filter(tenant=tenant).select_related('client', 'owner')

    # Client isolation
    if user_role == 'client':
        assets = assets.filter(client=user_client)

    # Filtering parameters
    client_id = request.GET.get('client')
    owner_id = request.GET.get('owner')
    criticality = request.GET.get('criticality')
    asset_type = request.GET.get('asset_type')

    if user_role != 'client' and client_id:
        assets = assets.filter(client_id=client_id)
    if owner_id:
        assets = assets.filter(owner_id=owner_id)
    if criticality:
        assets = assets.filter(criticality=criticality)
    if asset_type:
        assets = assets.filter(asset_type=asset_type)

    assets_list = list(assets)

    # Metrics
    total_count = len(assets_list)
    critical_count = sum(1 for a in assets_list if a.criticality == 'Critical')
    high_count = sum(1 for a in assets_list if a.criticality == 'High')
    software_count = sum(1 for a in assets_list if a.asset_type == 'Software')
    hardware_count = sum(1 for a in assets_list if a.asset_type == 'Hardware')

    filter_clients = Client.objects.filter(tenant=tenant)
    filter_owners = User.objects.filter(memberships__tenant=tenant)

    context = {
        'assets': assets_list,
        'active_tenant': tenant,
        'user_role': user_role,
        'filter_clients': filter_clients,
        'filter_owners': filter_owners,
        'selected_client_id': client_id,
        'selected_owner_id': owner_id,
        'selected_criticality': criticality,
        'selected_type': asset_type,
        
        'total_count': total_count,
        'critical_count': critical_count,
        'high_count': high_count,
        'software_count': software_count,
        'hardware_count': hardware_count,
        
        'type_choices': Asset.TYPE_CHOICES,
        'classification_choices': Asset.CLASSIFICATION_CHOICES,
        'criticality_choices': Asset.CRITICALITY_CHOICES,
    }

    return render(request, 'assets/asset_list.html', context)

@login_required
def asset_detail(request, asset_id):
    tenant = request.tenant
    user_role = getattr(request, 'user_role', None)
    user_client = getattr(request, 'user_client', None)

    if user_role == 'client':
        asset = get_object_or_404(Asset, id=asset_id, tenant=tenant, client=user_client)
    else:
        asset = get_object_or_404(Asset, id=asset_id, tenant=tenant)

    linked_risks = asset.central_risks.all().prefetch_related('threat')
    linked_assessment_risks = asset.assessment_risks.all().prefetch_related('threat', 'assessment')
    linked_assessments = asset.assessments.all()
    linked_evidence = asset.evidence_documents.all().prefetch_related('versions')

    return render(request, 'assets/asset_detail.html', {
        'asset': asset,
        'linked_risks': linked_risks,
        'linked_assessment_risks': linked_assessment_risks,
        'linked_assessments': linked_assessments,
        'linked_evidence': linked_evidence,
        'active_tenant': tenant,
        'user_role': user_role
    })

@login_required
@transaction.atomic
def asset_edit(request, asset_id=None):
    tenant = request.tenant
    user_role = getattr(request, 'user_role', None)
    if user_role == 'client':
        return HttpResponseForbidden("Permission denied. Clients cannot edit assets.")

    asset = None
    if asset_id:
        asset = get_object_or_404(Asset, id=asset_id, tenant=tenant)

    if request.method == 'POST':
        client_id = request.POST.get('client')
        name = request.POST.get('name')
        asset_type = request.POST.get('asset_type')
        supplier = request.POST.get('supplier', '')
        owner_id = request.POST.get('owner') or None
        classification = request.POST.get('classification')
        location = request.POST.get('location', '')
        criticality = request.POST.get('criticality')
        business_function = request.POST.get('business_function', '')
        description = request.POST.get('description', '')

        # Linkages lists
        central_risk_ids = request.POST.getlist('central_risks')
        assessment_risk_ids = request.POST.getlist('assessment_risks')
        assessment_ids = request.POST.getlist('assessments')
        evidence_ids = request.POST.getlist('evidence_documents')

        if not name or not client_id or not asset_type or not classification or not criticality:
            messages.error(request, "Required fields are missing.")
            return redirect(request.path)

        client = get_object_or_404(Client, id=client_id, tenant=tenant)
        owner = get_object_or_404(User, id=owner_id, memberships__tenant=tenant) if owner_id else None

        is_new = asset is None
        if is_new:
            asset = Asset(tenant=tenant)

        asset.client = client
        asset.name = name
        asset.asset_type = asset_type
        asset.supplier = supplier
        asset.owner = owner
        asset.classification = classification
        asset.location = location
        asset.criticality = criticality
        asset.business_function = business_function
        asset.description = description
        asset.save()

        # Set linkages ManyToMany relationships
        asset.central_risks.set(CentralRisk.objects.filter(id__in=central_risk_ids, tenant=tenant))
        asset.assessment_risks.set(RiskItem.objects.filter(id__in=assessment_risk_ids, tenant=tenant))
        asset.assessments.set(Assessment.objects.filter(id__in=assessment_ids, tenant=tenant))
        asset.evidence_documents.set(EvidenceDocument.objects.filter(id__in=evidence_ids, tenant=tenant))

        log_audit_event(
            tenant=tenant,
            user=request.user,
            event_type='ASSET',
            action='CREATE' if is_new else 'UPDATE',
            payload={'asset_id': asset.id, 'name': asset.name},
            ip_address=request.META.get('REMOTE_ADDR')
        )

        create_activity_feed_entry(
            tenant, request.user, 'asset_updated' if not is_new else 'asset_created',
            f"Saved asset '{asset.name}'"
        )

        messages.success(request, f"Asset '{asset.name}' saved successfully.")
        return redirect('assets:asset_detail', asset_id=asset.id)

    clients = Client.objects.filter(tenant=tenant)
    owners = User.objects.filter(memberships__tenant=tenant)
    central_risks = CentralRisk.objects.filter(tenant=tenant).select_related('threat')
    assessment_risks = RiskItem.objects.filter(tenant=tenant).select_related('threat', 'assessment')
    assessments = Assessment.objects.filter(tenant=tenant)
    evidence_documents = EvidenceDocument.objects.filter(tenant=tenant)

    # Gather currently linked IDs
    linked_central_risk_ids = list(asset.central_risks.values_list('id', flat=True)) if asset else []
    linked_assessment_risk_ids = list(asset.assessment_risks.values_list('id', flat=True)) if asset else []
    linked_assessment_ids = list(asset.assessments.values_list('id', flat=True)) if asset else []
    linked_evidence_ids = list(asset.evidence_documents.values_list('id', flat=True)) if asset else []

    return render(request, 'assets/asset_edit.html', {
        'asset': asset,
        'clients': clients,
        'owners': owners,
        'central_risks': central_risks,
        'assessment_risks': assessment_risks,
        'assessments': assessments,
        'evidence_documents': evidence_documents,
        'type_choices': Asset.TYPE_CHOICES,
        'classification_choices': Asset.CLASSIFICATION_CHOICES,
        'criticality_choices': Asset.CRITICALITY_CHOICES,
        'linked_central_risk_ids': linked_central_risk_ids,
        'linked_assessment_risk_ids': linked_assessment_risk_ids,
        'linked_assessment_ids': linked_assessment_ids,
        'linked_evidence_ids': linked_evidence_ids,
        'active_tenant': tenant,
    })

@login_required
@transaction.atomic
def asset_delete(request, asset_id):
    tenant = request.tenant
    user_role = getattr(request, 'user_role', None)
    if user_role == 'client':
        return HttpResponseForbidden("Permission denied. Clients cannot delete assets.")

    asset = get_object_or_404(Asset, id=asset_id, tenant=tenant)
    name = asset.name
    asset.delete()

    log_audit_event(
        tenant=tenant,
        user=request.user,
        event_type='ASSET',
        action='DELETE',
        payload={'asset_id': asset_id, 'name': name},
        ip_address=request.META.get('REMOTE_ADDR')
    )

    create_activity_feed_entry(
        tenant, request.user, 'asset_deleted',
        f"Deleted asset '{name}'"
    )

    messages.success(request, f"Asset '{name}' deleted successfully.")
    return redirect('assets:asset_list')
