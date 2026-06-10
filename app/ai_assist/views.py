import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.http import JsonResponse
from django.contrib import messages
from django.db import transaction

from tenants.models import Client
from assessments.models import Assessment, RiskItem, TemplateAssessment
from findings.models import Finding
from evidence.models import EvidenceDocument
from auditlog.utils import log_audit_event
from .models import AISettings, AIInteraction, AISuggestion
from .providers import get_provider

def is_admin_user(request):
    return request.user.is_superuser or request.user.is_staff or request.user.is_tenant_admin(request.tenant)

@login_required
def ai_settings(request):
    tenant = request.tenant
    if not is_admin_user(request):
        messages.error(request, "Permission denied. Admin privileges required.")
        return redirect('dashboard')
        
    settings, created = AISettings.objects.get_or_create(
        tenant=tenant,
        defaults={
            'provider': 'Gemini',
            'model_name': 'gemini-1.5-flash',
            'api_key': '',
            'api_url': ''
        }
    )
    
    if request.method == 'POST':
        provider = request.POST.get('provider')
        api_key = request.POST.get('api_key', '').strip()
        api_url = request.POST.get('api_url', '').strip()
        model_name = request.POST.get('model_name', '').strip()
        
        if provider in ['Gemini', 'OpenAI', 'Ollama']:
            settings.provider = provider
            settings.api_key = api_key
            settings.api_url = api_url
            if model_name:
                settings.model_name = model_name
            else:
                if provider == 'Gemini':
                    settings.model_name = 'gemini-1.5-flash'
                elif provider == 'OpenAI':
                    settings.model_name = 'gpt-4o-mini'
                elif provider == 'Ollama':
                    settings.model_name = 'llama3'
            settings.save()
            messages.success(request, "AI configuration saved successfully.")
            return redirect('ai_settings')
        else:
            messages.error(request, "Invalid AI provider selection.")
            
    return render(request, 'ai_assist/settings.html', {
        'settings': settings
    })

@login_required
def ai_history(request):
    tenant = request.tenant
    interactions = AIInteraction.objects.filter(tenant=tenant).select_related('user').order_by('-created_at')
    return render(request, 'ai_assist/history.html', {
        'interactions': interactions
    })

@login_required
@require_POST
def ai_suggestion_review(request, suggestion_id):
    tenant = request.tenant
    if request.user_role not in ['admin', 'owner', 'assessor'] and not request.user.is_superuser:
        return JsonResponse({'status': 'error', 'message': 'Permission denied.'}, status=403)
        
    suggestion = get_object_or_404(AISuggestion, id=suggestion_id, tenant=tenant)
    action = request.POST.get('action')
    if action == 'apply':
        # Enforce WORM rules: modifying status is permitted for workflow progression,
        # but original fields remain frozen.
        suggestion.status = 'Applied'
        suggestion.save(update_fields=['status'])
        
        log_audit_event(
            tenant=tenant,
            user=request.user,
            event_type='AI_ASSIST',
            action='SUGGESTION_APPLY',
            payload={'suggestion_id': suggestion.id},
            ip_address=request.META.get('REMOTE_ADDR')
        )
        return JsonResponse({'status': 'success', 'message': 'Suggestion applied.'})
    elif action == 'reject':
        suggestion.status = 'Rejected'
        suggestion.save(update_fields=['status'])
        
        log_audit_event(
            tenant=tenant,
            user=request.user,
            event_type='AI_ASSIST',
            action='SUGGESTION_REJECT',
            payload={'suggestion_id': suggestion.id},
            ip_address=request.META.get('REMOTE_ADDR')
        )
        return JsonResponse({'status': 'success', 'message': 'Suggestion rejected.'})
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid review action.'}, status=400)

@login_required
@require_POST
def generate_ai_suggestion(request):
    tenant = request.tenant
    
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        data = request.POST
        
    feature = data.get('feature')
    if not feature:
        return JsonResponse({'status': 'error', 'message': 'Missing parameter: feature'}, status=400)
        
    prompt = ""
    system_instruction = "You are an expert advisory cyber security risk assistant. Your suggestions are strictly advisory and require human review."
    
    # 1. Risk Rationale Generation
    if feature == 'rationale_generation':
        risk_item_id = data.get('risk_item_id')
        item = get_object_or_404(RiskItem, id=risk_item_id, assessment__tenant=tenant)
        prompt = (
            f"Generate a professional vulnerability and risk rationale paragraph for the following risk assessment item.\n"
            f"Affected Asset: {item.asset_name} (located in {item.asset_location}, owned by {item.asset_owner})\n"
            f"Threat: {item.threat.name} - {item.threat.description}\n"
            f"Vulnerability: {item.vulnerability}\n"
            f"Existing Controls: {item.existing_controls}\n"
            f"Threat Frequency Score: {item.threat_frequency.score} ({item.threat_frequency.label})\n"
            f"Vulnerability Probability Score: {item.vulnerability_probability.score} ({item.vulnerability_probability.label})\n"
            f"Impact Severity Score: {item.impact_severity.score} ({item.impact_severity.label})\n"
            f"Combined Inherent Risk Score: {item.risk_score} (Rating Category: {item.risk_category}).\n"
            f"Explain in 2-3 sentences why this risk rating is appropriate based on the vulnerability context and threat library guidelines."
        )

    # 2. Finding Suggestions
    elif feature == 'finding_suggestions':
        risk_item_id = data.get('risk_item_id')
        item = get_object_or_404(RiskItem, id=risk_item_id, assessment__tenant=tenant)
        prompt = (
            f"Suggest a formal security audit finding based on the details of this risk item.\n"
            f"Asset Name: {item.asset_name}\n"
            f"Threat Name: {item.threat.name}\n"
            f"Vulnerability: {item.vulnerability}\n"
            f"Existing Controls: {item.existing_controls}\n"
            f"Inherent Risk Category: {item.risk_category}\n"
            f"Format your response strictly as:\n"
            f"Title: [Clear Title]\n"
            f"Description: [Detailed Description of the vulnerability and exposure]\n"
            f"Severity: [Low, Medium, High, or Critical]"
        )

    # 3. Recommendation Suggestions
    elif feature == 'recommendation_suggestions':
        finding_id = data.get('finding_id')
        finding = get_object_or_404(Finding, id=finding_id, tenant=tenant)
        prompt = (
            f"Suggest a security recommendation to remediate the following finding.\n"
            f"Finding Title: {finding.title}\n"
            f"Finding Description: {finding.description}\n"
            f"Severity: {finding.severity}\n"
            f"Format your response strictly as:\n"
            f"Recommendation: [Remediation Action Text]\n"
            f"Priority: [Low, Medium, or High]\n"
            f"Effort: [Low, Medium, or High]\n"
            f"Cost Estimate: [Numerical estimate in GBP, e.g. 1500.0]"
        )

    # 4. Control Recommendations
    elif feature == 'control_recommendations':
        risk_item_id = data.get('risk_item_id')
        item = get_object_or_404(RiskItem, id=risk_item_id, assessment__tenant=tenant)
        prompt = (
            f"Recommend a list of standard security controls to mitigate the following risk.\n"
            f"Asset Name: {item.asset_name}\n"
            f"Threat Name: {item.threat.name}\n"
            f"Vulnerability: {item.vulnerability}\n"
            f"Existing Controls: {item.existing_controls}\n"
            f"Provide a numbered list of 2-3 specific control actions."
        )

    # 5. Evidence Summarisation
    elif feature == 'evidence_summarisation':
        evidence_id = data.get('evidence_id')
        doc = get_object_or_404(EvidenceDocument, id=evidence_id, tenant=tenant)
        latest_version = doc.versions.first()
        if not latest_version:
            return JsonResponse({'status': 'error', 'message': 'No uploaded file version found.'}, status=400)
            
        extracted_text = latest_version.extracted_text or "No text could be extracted from this document."
        prompt = (
            f"Summarise the following extracted text from evidence document '{latest_version.file_name}' "
            f"and explain how it supports security audits and risk controls:\n"
            f"{extracted_text[:4000]}"
        )

    # 6. Missing Control Identification
    elif feature == 'missing_control_identification':
        risk_item_id = data.get('risk_item_id')
        item = get_object_or_404(RiskItem, id=risk_item_id, assessment__tenant=tenant)
        prompt = (
            f"Analyze the following risk item to identify missing security controls that should be implemented.\n"
            f"Asset Name: {item.asset_name}\n"
            f"Threat: {item.threat.name}\n"
            f"Vulnerability: {item.vulnerability}\n"
            f"Existing Controls: {item.existing_controls}\n"
            f"Proposed Controls: {item.proposed_controls}\n"
            f"Identify 1-2 critical controls that are missing."
        )

    # 7. Assessment Completeness Review
    elif feature == 'completeness_review':
        assessment_id = data.get('assessment_id')
        # Check both core Assessment and TemplateAssessment
        core_ass = Assessment.objects.filter(id=assessment_id, tenant=tenant).first()
        if core_ass:
            risk_items = core_ass.risk_items.all()
            prompt = (
                f"Review the completeness of this Risk Register assessment.\n"
                f"Assessment Name: {core_ass.name}\n"
                f"Status: {core_ass.status}\n"
                f"Number of Risk Items: {risk_items.count()}\n"
                f"Provide feedback on what fields, details, or treatments look sparse, missing or incomplete."
            )
        else:
            temp_ass = get_object_or_404(TemplateAssessment, id=assessment_id, tenant=tenant)
            total_questions = temp_ass.template.sections.all().values_list('questions', flat=True).count()
            answered_questions = temp_ass.answers.count()
            prompt = (
                f"Review the completeness of this dynamic questionnaire assessment run.\n"
                f"Assessment Run: {temp_ass.name}\n"
                f"Standard Template: {temp_ass.template.name}\n"
                f"Questions Answered: {answered_questions} out of {total_questions}.\n"
                f"Review if there are critical missing answers and suggest next steps."
            )

    # 8. Contradiction Detection
    elif feature == 'contradiction_detection':
        assessment_id = data.get('assessment_id')
        core_ass = Assessment.objects.filter(id=assessment_id, tenant=tenant).first()
        if core_ass:
            items_desc = []
            for item in core_ass.risk_items.all():
                items_desc.append(
                    f"- Asset: {item.asset_name}, Threat: {item.threat.name}, "
                    f"Vulnerability: {item.vulnerability}, Existing Controls: {item.existing_controls}, "
                    f"Proposed Controls: {item.proposed_controls}"
                )
            risk_details = "\n".join(items_desc)
            prompt = (
                f"Detect contradictions in this risk register. Look for discrepancies where existing controls "
                f"are claimed to protect an asset, but the vulnerability description states it is completely exposed.\n"
                f"Assessment: {core_ass.name}\n"
                f"Risk Items:\n{risk_details}\n"
                f"Report any conflicting control statements or logical contradictions."
            )
        else:
            temp_ass = get_object_or_404(TemplateAssessment, id=assessment_id, tenant=tenant)
            answers_desc = []
            for ans in temp_ass.answers.all().select_related('question'):
                choices_str = ", ".join([c.text for c in ans.selected_choices.all()])
                answers_desc.append(
                    f"Q: {ans.question.text}\nAnswer: {ans.text_value or choices_str}"
                )
            risk_details = "\n\n".join(answers_desc)
            prompt = (
                f"Detect contradictions in this completed compliance questionnaire assessment.\n"
                f"Assessment Run: {temp_ass.name}\n"
                f"Answers:\n{risk_details}\n"
                f"Flag any contradictory answers (e.g. answering 'Yes' to firewalls present but answering 'No' to active perimeter defenses)."
            )
            
    else:
        return JsonResponse({'status': 'error', 'message': 'Unknown AI feature request.'}, status=400)

    try:
        provider = get_provider(tenant)
        response_text = provider.generate_text(prompt, system_instruction=system_instruction, feature=feature)
        model_name = getattr(provider, 'model_name', None) or 'MockModel'
        
        # Log the AI interaction in database
        AIInteraction.objects.create(
            tenant=tenant,
            user=request.user,
            feature=feature,
            prompt=prompt,
            response=response_text,
            model_used=model_name
        )
        
        # Log to AISuggestion for assessor review if it targets a risk item or finding
        risk_item_id = data.get('risk_item_id')
        finding_id = data.get('finding_id')
        
        risk_item = None
        if risk_item_id:
            try:
                risk_item = RiskItem.objects.get(id=risk_item_id, assessment__tenant=tenant)
            except RiskItem.DoesNotExist:
                pass
                
        finding = None
        if finding_id:
            try:
                finding = Finding.objects.get(id=finding_id, tenant=tenant)
            except Finding.DoesNotExist:
                pass
                
        if risk_item or finding:
            AISuggestion.objects.create(
                tenant=tenant,
                risk_item=risk_item,
                finding=finding,
                prompt=prompt,
                suggestion_text=response_text,
                status='Pending'
            )
        
        # Log AuditEvent
        log_audit_event(
            tenant=tenant,
            user=request.user,
            event_type='AI_ASSIST',
            action='GENERATE',
            payload={
                'feature': feature,
                'model_used': model_name,
                'prompt_length': len(prompt),
                'response_length': len(response_text)
            },
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        return JsonResponse({
            'status': 'success',
            'feature': feature,
            'suggestion': response_text,
            'model_used': model_name
        })
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)
