from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
import datetime

from accounts.models import User
from tenants.models import Client
from .models import (
    AssessmentMethodology, AssessmentMethodologyVersion,
    ThreatFrequencyCriteria, VulnerabilityProbabilityCriteria, ImpactCriteria,
    ThreatCategory, Threat, Assessment, RiskItem, RiskTreatment, TemplateAssessment,
    CentralRisk, RiskHistory
)
from .workflows import (
    ASSESSMENT_TRANSITIONS,
    allowed_dashboard_types,
    default_dashboard_type,
    validate_transition,
)
from auditlog.utils import log_audit_event
from collaboration.views import create_activity_feed_entry
from collaboration.models import CollaborationActivity, EvidenceRequest
from findings.models import Finding
from ai_assist.models import AISuggestion

@login_required
def dashboard(request):
    """
    Renders a unified role-based dashboard for Executive, Assessor, or Client roles
    with advanced filtering and localized Chart.js visualization arrays.
    """
    tenant = getattr(request, 'tenant', None)
    if not tenant:
        messages.error(request, "No active tenant association found.")
        return redirect('login')

    user_role = getattr(request, 'user_role', None)
    user_client = getattr(request, 'user_client', None)

    # 1. Dashboard switching permissions
    allowed_types = allowed_dashboard_types(request)
    dashboard_type = request.GET.get('dashboard_type', default_dashboard_type(request))
    if dashboard_type not in allowed_types:
        dashboard_type = default_dashboard_type(request)

    # Force client users to their client dashboard
    if user_role == 'client':
        dashboard_type = 'client'

    # 2. Filtering parameters (for executives and assessors)
    client_id = request.GET.get('client')
    assessment_filter_id = request.GET.get('assessment')
    date_start_str = request.GET.get('date_start')
    date_end_str = request.GET.get('date_end')

    # Base querysets
    assessments = Assessment.objects.filter(tenant=tenant).select_related('client', 'methodology_version__methodology')
    template_assessments = TemplateAssessment.objects.filter(tenant=tenant).select_related('client', 'template')

    # Apply Client scoping
    if user_role == 'client':
        assessments = assessments.filter(client=user_client)
        template_assessments = template_assessments.filter(client=user_client)
    elif client_id:
        assessments = assessments.filter(client_id=client_id)
        template_assessments = template_assessments.filter(client_id=client_id)

    # Apply date range filters
    parsed_start = None
    parsed_end = None
    if date_start_str:
        try:
            parsed_start = datetime.datetime.strptime(date_start_str, '%Y-%m-%d').date()
            assessments = assessments.filter(created_at__date__gte=parsed_start)
            template_assessments = template_assessments.filter(created_at__date__gte=parsed_start)
        except ValueError:
            pass
    if date_end_str:
        try:
            parsed_end = datetime.datetime.strptime(date_end_str, '%Y-%m-%d').date()
            assessments = assessments.filter(created_at__date__lte=parsed_end)
            template_assessments = template_assessments.filter(created_at__date__lte=parsed_end)
        except ValueError:
            pass

    # Apply specific Assessment filter
    if assessment_filter_id:
        assessments = assessments.filter(id=assessment_filter_id)
        # Dynamic Template Assessment won't match standard assessment ID, so we exclude/filter them
        # if a standard assessment filter is specified.
        template_assessments = template_assessments.none()

    # Base collections for filters
    filter_clients = Client.objects.filter(tenant=tenant)
    filter_assessments = Assessment.objects.filter(tenant=tenant)
    if user_role == 'client':
        filter_assessments = filter_assessments.filter(client=user_client)

    # 3. Gather Dashboard Specific Data
    context = {
        'active_tenant': tenant,
        'user_role': user_role,
        'dashboard_type': dashboard_type,
        'filter_clients': filter_clients,
        'filter_assessments': filter_assessments,
        'selected_client_id': client_id,
        'selected_assessment_id': assessment_filter_id,
        'date_start': date_start_str,
        'date_end': date_end_str,
    }

    if dashboard_type == 'executive':
        # Risks by Category / Severity (Inherent vs Residual)
        inherent_cat_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'N/A': 0}
        residual_cat_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'N/A': 0}
        
        # Treatment Progress Statuses
        treatment_status_counts = {'Open': 0, 'In Progress': 0, 'Accepted Risk': 0, 'Mitigated': 0, 'Closed': 0}

        all_risk_items = RiskItem.objects.filter(assessment__in=assessments).select_related(
            'assessment', 'threat', 'threat_frequency', 'vulnerability_probability', 'impact_severity'
        )

        for item in all_risk_items:
            cat = item.risk_category
            if cat in inherent_cat_counts:
                inherent_cat_counts[cat] += 1
            else:
                inherent_cat_counts['N/A'] += 1

            res_cat = item.residual_risk_category
            if res_cat in residual_cat_counts:
                residual_cat_counts[res_cat] += 1
            else:
                residual_cat_counts['N/A'] += 1

        # Query treatment progress status for treatments linked to filtered risks
        treatments = RiskTreatment.objects.filter(risk_item__in=all_risk_items)
        for tr in treatments:
            if tr.status in treatment_status_counts:
                treatment_status_counts[tr.status] += 1

        # Open Findings list and count
        open_findings = Finding.objects.filter(tenant=tenant, status='Open', assessment__in=assessments).select_related('assessment', 'assignee')
        open_findings_count = open_findings.count()

        # Overdue Treatments
        overdue_treatments = RiskTreatment.objects.filter(
            risk_item__in=all_risk_items,
            target_date__lt=timezone.now().date()
        ).exclude(status__in=['Mitigated', 'Closed', 'Accepted Risk']).select_related('risk_item__assessment')
        overdue_treatments_count = overdue_treatments.count()

        # Residual Risk Trend (Inherent vs Residual over assessments)
        trend_data = []
        for ass in assessments.order_by('created_at'):
            items = ass.risk_items.all()
            if items.exists():
                avg_inherent = sum(item.risk_score for item in items) / items.count()
                avg_residual = sum((item.residual_risk_score or 0) for item in items) / items.count()
                trend_data.append({
                    'name': ass.name,
                    'avg_inherent': round(avg_inherent, 2),
                    'avg_residual': round(avg_residual, 2)
                })

        context.update({
            'assessments': assessments,
            'inherent_cat_counts': inherent_cat_counts,
            'residual_cat_counts': residual_cat_counts,
            'treatment_status_counts': treatment_status_counts,
            'open_findings': open_findings[:10],
            'open_findings_count': open_findings_count,
            'overdue_treatments': overdue_treatments,
            'overdue_treatments_count': overdue_treatments_count,
            'trend_data': trend_data,
        })

    elif dashboard_type == 'assessor':
        # Assigned Assessments
        assigned_assessments = assessments.filter(assessor=request.user)
        assigned_templates = template_assessments.filter(assessor=request.user)

        # Overdue Actions (assigned findings, or overdue treatments for assessor's risks)
        overdue_findings = Finding.objects.filter(
            tenant=tenant, 
            assignee=request.user, 
            due_date__lt=timezone.now().date(),
            status='Open'
        ).select_related('assessment')
        
        overdue_treatments = RiskTreatment.objects.filter(
            risk_item__assessment__tenant=tenant,
            risk_item__assessment__assessor=request.user,
            target_date__lt=timezone.now().date()
        ).exclude(status__in=['Mitigated', 'Closed', 'Accepted Risk']).select_related('risk_item__assessment')

        # Evidence Requests
        evidence_requests = EvidenceRequest.objects.filter(
            tenant=tenant, 
            requested_by=request.user
        ).select_related('client', 'assessment')

        # AI Suggestions Awaiting Review
        ai_suggestions = AISuggestion.objects.filter(
            tenant=tenant, 
            status='Pending'
        ).select_related('risk_item__assessment', 'finding__assessment')

        # Dynamic charts for Assessor (e.g. status distribution of assigned assessments)
        assigned_status_counts = {'Draft': 0, 'InProgress': 0, 'UnderReview': 0, 'Completed': 0}
        for ass in assigned_assessments:
            if ass.status in assigned_status_counts:
                assigned_status_counts[ass.status] += 1
        for ass in assigned_templates:
            if ass.status in assigned_status_counts:
                assigned_status_counts[ass.status] += 1

        context.update({
            'assigned_assessments': assigned_assessments,
            'assigned_templates': assigned_templates,
            'overdue_findings': overdue_findings,
            'overdue_treatments': overdue_treatments,
            'evidence_requests': evidence_requests,
            'ai_suggestions': ai_suggestions,
            'assigned_status_counts': assigned_status_counts,
        })

    elif dashboard_type == 'client':
        # Assessments In Progress (client scope)
        client_assessments = assessments.filter(status__in=['InProgress', 'UnderReview'])
        client_templates = template_assessments.filter(status__in=['InProgress', 'UnderReview'])

        # Outstanding Actions (Open / In Progress treatments)
        outstanding_actions = RiskTreatment.objects.filter(
            risk_item__assessment__tenant=tenant,
            risk_item__assessment__client=user_client,
            status__in=['Open', 'In Progress']
        ).select_related('risk_item__assessment')

        # Open Findings (Open / In Progress findings)
        open_findings = Finding.objects.filter(
            tenant=tenant,
            assessment__client=user_client,
            status__in=['Open', 'InProgress']
        ).select_related('assessment', 'assignee')

        # Client specific stats for doughnut chart
        outstanding_status_counts = {'Open': 0, 'In Progress': 0}
        for tr in outstanding_actions:
            if tr.status == 'Open':
                outstanding_status_counts['Open'] += 1
            elif tr.status == 'In Progress':
                outstanding_status_counts['In Progress'] += 1

        context.update({
            'client_assessments': client_assessments,
            'client_templates': client_templates,
            'outstanding_actions': outstanding_actions,
            'open_findings': open_findings,
            'outstanding_status_counts': outstanding_status_counts,
        })

    return render(request, 'assessments/dashboard.html', context)

@login_required
def create_assessment(request):
    """
    Creates a new risk assessment container.
    """
    tenant = getattr(request, 'tenant', None)
    if not tenant:
        messages.error(request, "No active tenant association found.")
        return redirect('login')
        
    user_role = getattr(request, 'user_role', None)
    if user_role == 'client':
        messages.error(request, "Permission denied. Client users cannot create assessments.")
        return redirect('dashboard')
        
    if request.method == 'POST':
        name = request.POST.get('name')
        client_id = request.POST.get('client')
        version_id = request.POST.get('methodology_version')
        change_request = request.POST.get('change_request', '')
        asset = request.POST.get('asset', '')
        location = request.POST.get('location', '')
        owner = request.POST.get('owner', '')
        vulnerability = request.POST.get('vulnerability', '')
        existing_controls = request.POST.get('existing_controls', '')
        business_process_impact = request.POST.get('business_process_impact', '')
        
        confidentiality_affected = 'confidentiality_affected' in request.POST
        integrity_affected = 'integrity_affected' in request.POST
        availability_affected = 'availability_affected' in request.POST
        
        if not name or not client_id or not version_id:
            messages.error(request, "Name, Client, and Methodology Version are required.")
            return redirect('create_assessment')
            
        client = get_object_or_404(Client, id=client_id, tenant=tenant)
        methodology_version = get_object_or_404(AssessmentMethodologyVersion, id=version_id, tenant=tenant)
        
        assessment = Assessment.objects.create(
            tenant=tenant,
            client=client,
            methodology_version=methodology_version,
            name=name,
            change_request=change_request,
            asset=asset,
            location=location,
            owner=owner,
            vulnerability=vulnerability,
            existing_controls=existing_controls,
            business_process_impact=business_process_impact,
            confidentiality_affected=confidentiality_affected,
            integrity_affected=integrity_affected,
            availability_affected=availability_affected,
            status='InProgress'
        )
        
        log_audit_event(
            tenant=tenant,
            user=request.user,
            event_type='ASSESSMENT',
            action='CREATE',
            payload={
                'assessment_id': assessment.id,
                'name': assessment.name,
                'client_id': client.id,
            },
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        messages.success(request, f"Assessment '{name}' created successfully.")
        return redirect('assessment_detail', assessment_id=assessment.id)
        
    clients = Client.objects.filter(tenant=tenant)
    methodologies = AssessmentMethodologyVersion.objects.filter(tenant=tenant, is_active=True).select_related('methodology')
    
    return render(request, 'assessments/create_assessment.html', {
        'clients': clients,
        'methodologies': methodologies,
        'active_tenant': tenant,
    })

@login_required
def assessment_detail(request, assessment_id):
    """
    Renders risk assessment metadata and the risk register list.
    """
    tenant = getattr(request, 'tenant', None)
    if not tenant:
        messages.error(request, "No active tenant association found.")
        return redirect('login')
        
    user_role = getattr(request, 'user_role', None)
    user_client = getattr(request, 'user_client', None)
    if user_role == 'client':
        assessment = get_object_or_404(Assessment, id=assessment_id, tenant=tenant, client=user_client)
    else:
        assessment = get_object_or_404(Assessment, id=assessment_id, tenant=tenant)
    risk_items = assessment.risk_items.all().select_related('threat__category')
    
    # Handle status change POST
    if request.method == 'POST' and 'update_status' in request.POST:
        if user_role == 'client':
            messages.error(request, "Permission denied. Client users cannot update assessment status.")
            return redirect('assessment_detail', assessment_id=assessment.id)
        new_status = request.POST.get('status')
        if new_status in dict(Assessment.STATUS_CHOICES):
            try:
                validate_transition(assessment.status, new_status, ASSESSMENT_TRANSITIONS, 'assessment')
            except Exception as e:
                messages.error(request, str(e))
                return redirect('assessment_detail', assessment_id=assessment.id)
            assessment.status = new_status
            assessment.save()
            if new_status == 'Completed':
                for item in risk_items:
                    if item.central_risk:
                        item.sync_to_central_risk(request.user)
            # Audit log
            log_audit_event(
                tenant=tenant,
                user=request.user,
                event_type='ASSESSMENT',
                action='UPDATE',
                payload={
                    'assessment_id': assessment.id,
                    'status': new_status,
                },
                ip_address=request.META.get('REMOTE_ADDR')
            )
            messages.success(request, f"Assessment status updated to '{assessment.get_status_display()}'.")
        else:
            messages.error(request, "Invalid status choice.")
        return redirect('assessment_detail', assessment_id=assessment.id)
        
    # Get overall risk score/category (using maximum of items as the posture indicator)
    if risk_items.exists():
        max_item = max(risk_items, key=lambda i: i.risk_score)
        posture_score = max_item.risk_score
        posture_category = max_item.risk_category
    else:
        posture_score = None
        posture_category = "N/A"
        
    # Fetch associated reports
    from reporting.models import ReportDocument
    reports = ReportDocument.objects.filter(tenant=tenant, assessment=assessment).prefetch_related('versions')

    # Fetch comments, evidence requests, and activities for context
    comments = assessment.comments.filter(parent=None).select_related('user').prefetch_related('replies__user')
    evidence_requests = assessment.evidence_requests.all().select_related('requested_by', 'submitted_evidence')
    activities = CollaborationActivity.objects.filter(tenant=tenant).select_related('user')[:15]

    return render(request, 'assessments/assessment_detail.html', {
        'assessment': assessment,
        'risk_items': risk_items,
        'posture_score': posture_score,
        'posture_category': posture_category,
        'status_choices': Assessment.STATUS_CHOICES,
        'active_tenant': tenant,
        'reports': reports,
        'report_types': ReportDocument.REPORT_TYPE_CHOICES,
        'file_formats': ReportDocument.FILE_FORMAT_CHOICES,
        'comments': comments,
        'evidence_requests': evidence_requests,
        'activities': activities,
        'user_role': user_role,
    })


@login_required
@transaction.atomic
def risk_item_grid(request, assessment_id):
    """
    Spreadsheet-style bulk entry for risk assessment rows.
    """
    tenant = getattr(request, 'tenant', None)
    if not tenant:
        messages.error(request, "No active tenant association found.")
        return redirect('login')

    user_role = getattr(request, 'user_role', None)
    if user_role == 'client':
        messages.error(request, "Permission denied. Client users cannot bulk edit risk items.")
        return redirect('dashboard')

    assessment = get_object_or_404(Assessment, id=assessment_id, tenant=tenant)
    version = assessment.methodology_version

    if request.method == 'POST':
        row_numbers = sorted({key.split('_')[-1] for key in request.POST if key.startswith('asset_name_')}, key=lambda value: int(value))
        saved_count = 0
        for row in row_numbers:
            asset_name = request.POST.get(f'asset_name_{row}', '').strip()
            threat_id = request.POST.get(f'threat_{row}')
            threat_freq_id = request.POST.get(f'threat_frequency_{row}')
            vuln_prob_id = request.POST.get(f'vulnerability_probability_{row}')
            imp_sev_id = request.POST.get(f'impact_severity_{row}')
            risk_item_id = request.POST.get(f'risk_item_id_{row}')

            if not any([asset_name, threat_id, threat_freq_id, vuln_prob_id, imp_sev_id, risk_item_id]):
                continue
            if not all([asset_name, threat_id, threat_freq_id, vuln_prob_id, imp_sev_id]):
                messages.error(request, f"Row {row}: asset, threat, frequency, probability, and impact are required.")
                return redirect('risk_item_grid', assessment_id=assessment.id)

            risk_item = RiskItem.objects.filter(id=risk_item_id, assessment=assessment, tenant=tenant).first() if risk_item_id else RiskItem(tenant=tenant, assessment=assessment)
            risk_item.asset_name = asset_name
            risk_item.asset_location = request.POST.get(f'asset_location_{row}', '').strip()
            risk_item.asset_owner = request.POST.get(f'asset_owner_{row}', '').strip()
            risk_item.threat = get_object_or_404(Threat, id=threat_id, tenant=tenant)
            risk_item.vulnerability = request.POST.get(f'vulnerability_{row}', '').strip()
            risk_item.existing_controls = request.POST.get(f'existing_controls_{row}', '').strip()
            risk_item.confidentiality_affected = f'confidentiality_affected_{row}' in request.POST
            risk_item.integrity_affected = f'integrity_affected_{row}' in request.POST
            risk_item.availability_affected = f'availability_affected_{row}' in request.POST
            risk_item.threat_frequency = get_object_or_404(ThreatFrequencyCriteria, id=threat_freq_id, methodology_version=version, tenant=tenant)
            risk_item.vulnerability_probability = get_object_or_404(VulnerabilityProbabilityCriteria, id=vuln_prob_id, methodology_version=version, tenant=tenant)
            risk_item.impact_severity = get_object_or_404(ImpactCriteria, id=imp_sev_id, methodology_version=version, tenant=tenant)
            risk_item.proposed_controls = request.POST.get(f'proposed_controls_{row}', '').strip()
            risk_item.additional_mitigations = request.POST.get(f'additional_mitigations_{row}', '').strip()

            residual_freq_id = request.POST.get(f'residual_threat_frequency_{row}')
            residual_prob_id = request.POST.get(f'residual_vulnerability_probability_{row}')
            residual_impact_id = request.POST.get(f'residual_impact_severity_{row}')
            risk_item.residual_threat_frequency = get_object_or_404(ThreatFrequencyCriteria, id=residual_freq_id, methodology_version=version, tenant=tenant) if residual_freq_id else None
            risk_item.residual_vulnerability_probability = get_object_or_404(VulnerabilityProbabilityCriteria, id=residual_prob_id, methodology_version=version, tenant=tenant) if residual_prob_id else None
            risk_item.residual_impact_severity = get_object_or_404(ImpactCriteria, id=residual_impact_id, methodology_version=version, tenant=tenant) if residual_impact_id else None
            risk_item.save()

            treatment, _ = RiskTreatment.objects.get_or_create(tenant=tenant, risk_item=risk_item)
            treatment.action = request.POST.get(f'treatment_action_{row}', '').strip()
            treatment.owner = request.POST.get(f'treatment_owner_{row}', '').strip()
            treatment.target_date = request.POST.get(f'treatment_target_date_{row}') or None
            treatment.status = request.POST.get(f'treatment_status_{row}', 'Open')
            treatment.save()
            saved_count += 1

        log_audit_event(
            tenant=tenant,
            user=request.user,
            event_type='RISK_ITEM',
            action='BULK_UPDATE',
            payload={'assessment_id': assessment.id, 'saved_rows': saved_count},
            ip_address=request.META.get('REMOTE_ADDR')
        )
        messages.success(request, f"Saved {saved_count} risk register row(s).")
        return redirect('assessment_detail', assessment_id=assessment.id)

    risk_items = list(assessment.risk_items.all().select_related(
        'threat', 'threat__category', 'threat_frequency', 'vulnerability_probability',
        'impact_severity', 'residual_threat_frequency', 'residual_vulnerability_probability',
        'residual_impact_severity',
    ).prefetch_related('treatment'))
    blank_rows = range(len(risk_items) + 1, len(risk_items) + 6)

    return render(request, 'assessments/risk_item_grid.html', {
        'assessment': assessment,
        'risk_items': risk_items,
        'blank_rows': blank_rows,
        'threats': Threat.objects.filter(tenant=tenant).select_related('category').order_by('category__name', 'name'),
        'freq_criteria': ThreatFrequencyCriteria.objects.filter(methodology_version=version, tenant=tenant),
        'prob_criteria': VulnerabilityProbabilityCriteria.objects.filter(methodology_version=version, tenant=tenant),
        'impact_criteria': ImpactCriteria.objects.filter(methodology_version=version, tenant=tenant),
        'treatment_statuses': RiskTreatment.STATUS_CHOICES,
        'active_tenant': tenant,
    })


@login_required
def risk_item_spreadsheet(request, assessment_id):
    """
    Workbook-style view of the change risk assessment spreadsheet.
    """
    if request.method == 'POST':
        return risk_item_grid(request, assessment_id)

    tenant = getattr(request, 'tenant', None)
    if not tenant:
        messages.error(request, "No active tenant association found.")
        return redirect('login')

    user_role = getattr(request, 'user_role', None)
    if user_role == 'client':
        messages.error(request, "Permission denied. Client users cannot bulk edit risk items.")
        return redirect('dashboard')

    assessment = get_object_or_404(Assessment, id=assessment_id, tenant=tenant)
    version = assessment.methodology_version
    risk_items = list(assessment.risk_items.all().select_related(
        'threat', 'threat__category', 'threat_frequency', 'vulnerability_probability',
        'impact_severity', 'residual_threat_frequency', 'residual_vulnerability_probability',
        'residual_impact_severity',
    ).prefetch_related('treatment'))
    blank_rows = range(len(risk_items) + 1, len(risk_items) + 11)

    return render(request, 'assessments/risk_item_spreadsheet.html', {
        'assessment': assessment,
        'risk_items': risk_items,
        'blank_rows': blank_rows,
        'threats': Threat.objects.filter(tenant=tenant).select_related('category').order_by('category__name', 'name'),
        'freq_criteria': ThreatFrequencyCriteria.objects.filter(methodology_version=version, tenant=tenant),
        'prob_criteria': VulnerabilityProbabilityCriteria.objects.filter(methodology_version=version, tenant=tenant),
        'impact_criteria': ImpactCriteria.objects.filter(methodology_version=version, tenant=tenant),
        'treatment_statuses': RiskTreatment.STATUS_CHOICES,
        'active_tenant': tenant,
    })


@login_required
@transaction.atomic
def risk_item_edit(request, assessment_id, risk_item_id=None):
    """
    Adds a new risk item or edits an existing one, including its scoring and treatment.
    """
    tenant = getattr(request, 'tenant', None)
    if not tenant:
        messages.error(request, "No active tenant association found.")
        return redirect('login')
        
    user_role = getattr(request, 'user_role', None)
    user_client = getattr(request, 'user_client', None)

    if user_role == 'client':
        assessment = get_object_or_404(Assessment, id=assessment_id, tenant=tenant, client=user_client)
    else:
        assessment = get_object_or_404(Assessment, id=assessment_id, tenant=tenant)
        
    version = assessment.methodology_version
    
    risk_item = None
    treatment = None
    if risk_item_id:
        risk_item = get_object_or_404(RiskItem, id=risk_item_id, assessment=assessment, tenant=tenant)
        treatment, _ = RiskTreatment.objects.get_or_create(risk_item=risk_item, tenant=tenant)
    elif user_role == 'client':
        messages.error(request, "Permission denied. Client users cannot add new risk items.")
        return redirect('assessment_detail', assessment_id=assessment.id)
        
    if request.method == 'POST':
        if user_role == 'client':
            # Clients can only update the treatment status and completion notes
            if treatment:
                treatment.status = request.POST.get('treatment_status', 'Open')
                treatment.completion_notes = request.POST.get('treatment_notes', '')
                treatment.owner = request.POST.get('treatment_owner', '')
                target_date_val = request.POST.get('treatment_target_date')
                treatment.target_date = target_date_val if target_date_val else None
                treatment.save()
                
                # Audit event
                log_payload = {
                    'risk_item_id': risk_item.id,
                    'treatment_id': treatment.id,
                    'status': treatment.status,
                    'owner': treatment.owner
                }
                log_audit_event(tenant, request.user, 'COLLABORATION', 'UPDATE', log_payload)
                log_audit_event(
                    tenant=tenant,
                    user=request.user,
                    event_type='TREATMENT',
                    action='UPDATE',
                    payload={
                        'treatment_id': treatment.id,
                        'risk_item_id': risk_item.id,
                        'status': treatment.status,
                        'owner': treatment.owner,
                    },
                    ip_address=request.META.get('REMOTE_ADDR')
                )
                create_activity_feed_entry(tenant, request.user, 'treatment_updated', f"Updated treatment status to '{treatment.get_status_display()}' for asset '{risk_item.asset_name}'")
                
                messages.success(request, "Risk treatment action updated successfully.")
            return redirect('assessment_detail', assessment_id=assessment.id)
        # 1. Read Risk Item details
        asset_name = request.POST.get('asset_name')
        asset_location = request.POST.get('asset_location')
        asset_owner = request.POST.get('asset_owner')
        threat_id = request.POST.get('threat')
        vulnerability = request.POST.get('vulnerability')
        existing_controls = request.POST.get('existing_controls')
        
        confidentiality_affected = 'confidentiality_affected' in request.POST
        integrity_affected = 'integrity_affected' in request.POST
        availability_affected = 'availability_affected' in request.POST
        
        # Inherent scoring criteria IDs
        threat_freq_id = request.POST.get('threat_frequency')
        vuln_prob_id = request.POST.get('vulnerability_probability')
        imp_sev_id = request.POST.get('impact_severity')
        
        # Residual scoring criteria IDs & proposed controls
        proposed_controls = request.POST.get('proposed_controls', '')
        additional_mitigations = request.POST.get('additional_mitigations', '')
        res_threat_freq_id = request.POST.get('residual_threat_frequency') or None
        res_vuln_prob_id = request.POST.get('residual_vulnerability_probability') or None
        res_imp_sev_id = request.POST.get('residual_impact_severity') or None
        
        if not asset_name or not threat_id or not threat_freq_id or not vuln_prob_id or not imp_sev_id:
            messages.error(request, "Asset name, threat, and inherent scores are required.")
            return redirect(request.path)
            
        threat = get_object_or_404(Threat, id=threat_id, tenant=tenant)
        threat_freq = get_object_or_404(ThreatFrequencyCriteria, id=threat_freq_id, methodology_version=version, tenant=tenant)
        vuln_prob = get_object_or_404(VulnerabilityProbabilityCriteria, id=vuln_prob_id, methodology_version=version, tenant=tenant)
        imp_sev = get_object_or_404(ImpactCriteria, id=imp_sev_id, methodology_version=version, tenant=tenant)
        
        # Parse optional residual inputs
        res_threat_freq = None
        if res_threat_freq_id:
            res_threat_freq = get_object_or_404(ThreatFrequencyCriteria, id=res_threat_freq_id, methodology_version=version, tenant=tenant)
            
        res_vuln_prob = None
        if res_vuln_prob_id:
            res_vuln_prob = get_object_or_404(VulnerabilityProbabilityCriteria, id=res_vuln_prob_id, methodology_version=version, tenant=tenant)
            
        res_imp_sev = None
        if res_imp_sev_id:
            res_imp_sev = get_object_or_404(ImpactCriteria, id=res_imp_sev_id, methodology_version=version, tenant=tenant)
            
        if not risk_item:
            risk_item = RiskItem(assessment=assessment, tenant=tenant)
            
        is_new_risk = (risk_item.pk is None)
        risk_item.asset_name = asset_name
        risk_item.asset_location = asset_location or ''
        risk_item.asset_owner = asset_owner or ''
        risk_item.threat = threat
        risk_item.vulnerability = vulnerability or ''
        risk_item.existing_controls = existing_controls or ''
        risk_item.confidentiality_affected = confidentiality_affected
        risk_item.integrity_affected = integrity_affected
        risk_item.availability_affected = availability_affected
        risk_item.threat_frequency = threat_freq
        risk_item.vulnerability_probability = vuln_prob
        risk_item.impact_severity = imp_sev
        
        risk_item.proposed_controls = proposed_controls
        risk_item.additional_mitigations = additional_mitigations
        risk_item.residual_threat_frequency = res_threat_freq
        risk_item.residual_vulnerability_probability = res_vuln_prob
        risk_item.residual_impact_severity = res_imp_sev
        
        # Link Central Risk
        central_risk_id = request.POST.get('central_risk')
        if central_risk_id:
            central_risk = get_object_or_404(
                CentralRisk,
                id=central_risk_id,
                tenant=tenant,
                client=assessment.client,
            )
            risk_item.central_risk = central_risk
        elif 'publish_to_register' in request.POST and not risk_item.central_risk:
            from .views_central_risk import get_snapshot
            central_risk = CentralRisk.objects.create(
                tenant=tenant,
                client=assessment.client,
                asset_name=asset_name,
                asset_location=asset_location or '',
                asset_owner=asset_owner or '',
                threat=threat,
                vulnerability=vulnerability or '',
                existing_controls=existing_controls or '',
                confidentiality_affected=confidentiality_affected,
                integrity_affected=integrity_affected,
                availability_affected=availability_affected,
                threat_frequency=threat_freq,
                vulnerability_probability=vuln_prob,
                impact_severity=imp_sev,
                proposed_controls=proposed_controls,
                additional_mitigations=additional_mitigations,
                residual_threat_frequency=res_threat_freq,
                residual_vulnerability_probability=res_vuln_prob,
                residual_impact_severity=res_imp_sev,
                status='Active' if assessment.status == 'Completed' else 'Draft'
            )
            # Log creation to RiskHistory
            RiskHistory.objects.create(
                tenant=tenant,
                risk=central_risk,
                changed_by=request.user,
                action="Create",
                description=f"Risk registered from assessment '{assessment.name}'.",
                snapshot=get_snapshot(central_risk)
            )
            risk_item.central_risk = central_risk
            
        risk_item.save()
        
        # Sync details to linked central risk
        if risk_item.central_risk:
            risk_item.sync_to_central_risk(request.user)
        
        # 2. Read Treatment details
        treat_action = request.POST.get('treatment_action', '')
        treat_owner = request.POST.get('treatment_owner', '')
        treat_target = request.POST.get('treatment_target_date') or None
        treat_status = request.POST.get('treatment_status', 'Open')
        treat_notes = request.POST.get('treatment_notes', '')
        
        is_new_treatment = False
        if not treatment:
            treatment = RiskTreatment(risk_item=risk_item, tenant=tenant)
            is_new_treatment = True
        elif treatment.pk is None:
            is_new_treatment = True
            
        treatment.action = treat_action
        treatment.owner = treat_owner
        treatment.target_date = treat_target
        treatment.status = treat_status
        treatment.completion_notes = treat_notes
        treatment.save()

        # Audit logs for risk and treatment
        log_audit_event(
            tenant=tenant,
            user=request.user,
            event_type='RISK_ITEM',
            action='CREATE' if is_new_risk else 'UPDATE',
            payload={
                'risk_item_id': risk_item.id,
                'asset_name': risk_item.asset_name,
                'threat_id': risk_item.threat.id,
                'risk_score': risk_item.risk_score,
            },
            ip_address=request.META.get('REMOTE_ADDR')
        )
        log_audit_event(
            tenant=tenant,
            user=request.user,
            event_type='TREATMENT',
            action='CREATE' if is_new_treatment else 'UPDATE',
            payload={
                'treatment_id': treatment.id,
                'risk_item_id': risk_item.id,
                'status': treatment.status,
                'owner': treatment.owner,
            },
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        messages.success(request, f"Risk Item '{asset_name}' saved successfully.")
        return redirect('assessment_detail', assessment_id=assessment.id)
        
    # Get selectors data
    threats = Threat.objects.filter(tenant=tenant).select_related('category').order_by('category__name', 'name')
    freq_criteria = ThreatFrequencyCriteria.objects.filter(methodology_version=version, tenant=tenant)
    prob_criteria = VulnerabilityProbabilityCriteria.objects.filter(methodology_version=version, tenant=tenant)
    impact_criteria = ImpactCriteria.objects.filter(methodology_version=version, tenant=tenant)
    treatment_statuses = RiskTreatment.STATUS_CHOICES
    
    # Fetch central risks for selection
    central_risks = CentralRisk.objects.filter(tenant=tenant, client=assessment.client)
    
    comments = None
    if risk_item:
        comments = risk_item.comments.filter(parent=None).select_related('user').prefetch_related('replies__user')
        
    return render(request, 'assessments/risk_item_edit.html', {
        'assessment': assessment,
        'risk_item': risk_item,
        'treatment': treatment,
        'threats': threats,
        'freq_criteria': freq_criteria,
        'prob_criteria': prob_criteria,
        'impact_criteria': impact_criteria,
        'treatment_statuses': treatment_statuses,
        'active_tenant': tenant,
        'comments': comments,
        'user_role': user_role,
        'central_risks': central_risks,
    })

@login_required
def risk_item_delete(request, assessment_id, risk_item_id):
    """
    Soft-deletes a specific RiskItem.
    """
    tenant = getattr(request, 'tenant', None)
    user_role = getattr(request, 'user_role', None)
    if user_role == 'client':
        messages.error(request, "Permission denied. Client users cannot delete risk items.")
        return redirect('assessment_detail', assessment_id=assessment_id)
        
    if not tenant:
        messages.error(request, "No active tenant association found.")
        return redirect('login')
        
    assessment = get_object_or_404(Assessment, id=assessment_id, tenant=tenant)
    risk_item = get_object_or_404(RiskItem, id=risk_item_id, assessment=assessment, tenant=tenant)
    
    risk_item.delete()
    log_audit_event(
        tenant=tenant,
        user=request.user,
        event_type='RISK_ITEM',
        action='DELETE',
        payload={
            'risk_item_id': risk_item.id,
            'asset_name': risk_item.asset_name,
        },
        ip_address=request.META.get('REMOTE_ADDR')
    )
    messages.success(request, f"Risk Item '{risk_item.asset_name}' deleted.")
    return redirect('assessment_detail', assessment_id=assessment.id)
