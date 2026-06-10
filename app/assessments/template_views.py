from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db import transaction
from django.utils import timezone
from tenants.models import Client
from evidence.models import EvidenceDocument
from .models import (
    AssessmentTemplate, TemplateSection, TemplateQuestion, QuestionChoice,
    TemplateScoringRange, TemplateAssessment, TemplateAnswer
)
from auditlog.utils import log_audit_event

def is_admin_user(request):
    return request.user.is_superuser or request.user.is_staff or request.user.is_tenant_admin(request.tenant)

@login_required
def template_list(request):
    tenant = request.tenant
    templates = AssessmentTemplate.objects.filter(tenant=tenant).order_by('name', '-version')
    return render(request, 'assessments/template_list.html', {
        'templates': templates,
        'is_admin': is_admin_user(request)
    })

@login_required
def template_edit(request, template_id=None):
    tenant = request.tenant
    if not is_admin_user(request):
        messages.error(request, "Permission denied. Admin privileges required.")
        return redirect('template_list')
        
    template = None
    ranges = []
    
    if template_id:
        template = get_object_or_404(AssessmentTemplate, id=template_id, tenant=tenant)
        if template.state != 'Draft':
            messages.error(request, "Published templates cannot be edited. Create a new version instead.")
            return redirect('template_list')
        ranges = template.scoring_ranges.all()
        
    if request.method == 'POST':
        name = request.POST.get('name')
        desc = request.POST.get('description', '')
        
        if not name:
            messages.error(request, "Template name is required.")
        else:
            with transaction.atomic():
                if not template:
                    template = AssessmentTemplate.objects.create(
                        tenant=tenant,
                        name=name,
                        description=desc,
                        version=1,
                        state='Draft',
                        is_latest=True
                    )
                else:
                    template.name = name
                    template.description = desc
                    template.save()
                    
                # Handle scoring ranges
                range_labels = request.POST.getlist('range_label')
                range_mins = request.POST.getlist('range_min')
                range_maxs = request.POST.getlist('range_max')
                range_colors = request.POST.getlist('range_color')
                
                TemplateScoringRange.objects.filter(template=template).delete()
                for i in range(len(range_labels)):
                    if range_labels[i]:
                        try:
                            min_val = float(range_mins[i])
                            max_val = float(range_maxs[i])
                        except ValueError:
                            min_val = 0.0
                            max_val = 0.0
                        TemplateScoringRange.objects.create(
                            tenant=tenant,
                            template=template,
                            label=range_labels[i].strip(),
                            min_score=min_val,
                            max_score=max_val,
                            color=range_colors[i]
                        )
                        
            messages.success(request, f"Template '{template.name}' saved successfully.")
            return redirect('template_list')
            
    return render(request, 'assessments/template_edit.html', {
        'template': template,
        'ranges': ranges
    })

@login_required
def template_builder(request, template_id):
    tenant = request.tenant
    if not is_admin_user(request):
        messages.error(request, "Permission denied. Admin privileges required.")
        return redirect('template_list')
        
    template = get_object_or_404(AssessmentTemplate, id=template_id, tenant=tenant)
    if template.state != 'Draft':
        messages.error(request, "Published templates cannot be modified. Create a new version first.")
        return redirect('template_list')

    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'add_section':
            name = request.POST.get('name')
            desc = request.POST.get('description', '')
            order = request.POST.get('order') or 1
            if name:
                TemplateSection.objects.create(
                    tenant=tenant,
                    template=template,
                    name=name.strip(),
                    description=desc,
                    order=int(order)
                )
                messages.success(request, f"Section '{name}' added successfully.")
            else:
                messages.error(request, "Section name is required.")
                
        elif action == 'edit_section':
            sec_id = request.POST.get('section_id')
            sec = get_object_or_404(TemplateSection, id=sec_id, template=template)
            sec.name = request.POST.get('name', sec.name).strip()
            sec.description = request.POST.get('description', '')
            sec.order = int(request.POST.get('order') or sec.order)
            sec.save()
            messages.success(request, "Section updated successfully.")
            
        elif action == 'delete_section':
            sec_id = request.POST.get('section_id')
            sec = get_object_or_404(TemplateSection, id=sec_id, template=template)
            sec.delete()
            messages.success(request, "Section deleted successfully.")
            
        elif action == 'add_question':
            sec_id = request.POST.get('section_id')
            sec = get_object_or_404(TemplateSection, id=sec_id, template=template)
            text = request.POST.get('text')
            q_type = request.POST.get('question_type')
            is_req = request.POST.get('is_required') == '1'
            help_txt = request.POST.get('help_text', '')
            guidance = request.POST.get('guidance_notes', '')
            order = request.POST.get('order') or 1
            
            if text and q_type:
                q = TemplateQuestion.objects.create(
                    tenant=tenant,
                    section=sec,
                    text=text.strip(),
                    question_type=q_type,
                    is_required=is_req,
                    help_text=help_txt,
                    guidance_notes=guidance,
                    order=int(order)
                )
                
                if q_type in ['Dropdown', 'Radio', 'MultiSelect']:
                    choices_raw = request.POST.get('choices_raw', '')
                    lines = [line.strip() for line in choices_raw.split('\n') if line.strip()]
                    for i, line in enumerate(lines, 1):
                        if '|' in line:
                            c_text, c_score = line.split('|', 1)
                        else:
                            c_text, c_score = line, 0.0
                        try:
                            score_val = float(c_score.strip())
                        except ValueError:
                            score_val = 0.0
                        QuestionChoice.objects.create(
                            question=q,
                            text=c_text.strip(),
                            score=score_val,
                            order=i
                        )
                messages.success(request, "Question added successfully.")
            else:
                messages.error(request, "Question text and type are required.")
                
        elif action == 'edit_question':
            q_id = request.POST.get('question_id')
            q = get_object_or_404(TemplateQuestion, id=q_id, section__template=template)
            q.text = request.POST.get('text', q.text).strip()
            q.is_required = request.POST.get('is_required') == '1'
            q.help_text = request.POST.get('help_text', '')
            q.guidance_notes = request.POST.get('guidance_notes', '')
            q.order = int(request.POST.get('order') or q.order)
            q.save()
            
            if q.question_type in ['Dropdown', 'Radio', 'MultiSelect']:
                choices_raw = request.POST.get('choices_raw', '')
                QuestionChoice.objects.filter(question=q).delete()
                lines = [line.strip() for line in choices_raw.split('\n') if line.strip()]
                for i, line in enumerate(lines, 1):
                    if '|' in line:
                        c_text, c_score = line.split('|', 1)
                    else:
                        c_text, c_score = line, 0.0
                    try:
                        score_val = float(c_score.strip())
                    except ValueError:
                        score_val = 0.0
                    QuestionChoice.objects.create(
                        question=q,
                        text=c_text.strip(),
                        score=score_val,
                        order=i
                    )
            messages.success(request, "Question updated successfully.")
            
        elif action == 'delete_question':
            q_id = request.POST.get('question_id')
            q = get_object_or_404(TemplateQuestion, id=q_id, section__template=template)
            q.delete()
            messages.success(request, "Question deleted successfully.")
            
        return redirect('template_builder', template_id=template.id)
        
    sections = template.sections.all().prefetch_related('questions__choices')
    return render(request, 'assessments/template_builder.html', {
        'template': template,
        'sections': sections,
        'question_types': TemplateQuestion.TYPE_CHOICES
    })

@login_required
def template_clone(request, template_id):
    tenant = request.tenant
    if not is_admin_user(request):
        messages.error(request, "Permission denied. Admin privileges required.")
        return redirect('template_list')
        
    original = get_object_or_404(AssessmentTemplate, id=template_id, tenant=tenant)
    
    with transaction.atomic():
        cloned = AssessmentTemplate.objects.create(
            tenant=tenant,
            name=f"Clone of {original.name}",
            description=original.description,
            version=1,
            state='Draft',
            is_latest=True,
            parent_template=None
        )
        
        for r in original.scoring_ranges.all():
            TemplateScoringRange.objects.create(
                tenant=tenant,
                template=cloned,
                label=r.label,
                min_score=r.min_score,
                max_score=r.max_score,
                color=r.color
            )
            
        for s in original.sections.all():
            sec_clone = TemplateSection.objects.create(
                tenant=tenant,
                template=cloned,
                name=s.name,
                description=s.description,
                order=s.order
            )
            for q in s.questions.all():
                q_clone = TemplateQuestion.objects.create(
                    tenant=tenant,
                    section=sec_clone,
                    text=q.text,
                    help_text=q.help_text,
                    guidance_notes=q.guidance_notes,
                    question_type=q.question_type,
                    is_required=q.is_required,
                    order=q.order
                )
                for c in q.choices.all():
                    QuestionChoice.objects.create(
                        question=q_clone,
                        text=c.text,
                        score=c.score,
                        order=c.order
                    )
                    
    messages.success(request, f"Template '{original.name}' successfully cloned as '{cloned.name}'.")
    return redirect('template_list')

@login_required
def template_create_version(request, template_id):
    tenant = request.tenant
    if not is_admin_user(request):
        messages.error(request, "Permission denied. Admin privileges required.")
        return redirect('template_list')
        
    parent = get_object_or_404(AssessmentTemplate, id=template_id, tenant=tenant)
    if parent.state != 'Published':
        messages.error(request, "Only published templates can be versioned.")
        return redirect('template_list')
        
    with transaction.atomic():
        AssessmentTemplate.objects.filter(tenant=tenant, name=parent.name).update(is_latest=False)
        
        new_ver = AssessmentTemplate.objects.create(
            tenant=tenant,
            name=parent.name,
            description=parent.description,
            version=parent.version + 1,
            state='Draft',
            is_latest=True,
            parent_template=parent
        )
        
        for r in parent.scoring_ranges.all():
            TemplateScoringRange.objects.create(
                tenant=tenant,
                template=new_ver,
                label=r.label,
                min_score=r.min_score,
                max_score=r.max_score,
                color=r.color
            )
            
        for s in parent.sections.all():
            sec_clone = TemplateSection.objects.create(
                tenant=tenant,
                template=new_ver,
                name=s.name,
                description=s.description,
                order=s.order
            )
            for q in s.questions.all():
                q_clone = TemplateQuestion.objects.create(
                    tenant=tenant,
                    section=sec_clone,
                    text=q.text,
                    help_text=q.help_text,
                    guidance_notes=q.guidance_notes,
                    question_type=q.question_type,
                    is_required=q.is_required,
                    order=q.order
                )
                for c in q.choices.all():
                    QuestionChoice.objects.create(
                        question=q_clone,
                        text=c.text,
                        score=c.score,
                        order=c.order
                    )
                    
    messages.success(request, f"New draft version {new_ver.version} created for template '{parent.name}'.")
    return redirect('template_list')

@login_required
def template_publish(request, template_id):
    tenant = request.tenant
    if not is_admin_user(request):
        messages.error(request, "Permission denied. Admin privileges required.")
        return redirect('template_list')
        
    template = get_object_or_404(AssessmentTemplate, id=template_id, tenant=tenant)
    if template.state != 'Draft':
        messages.warning(request, "Template is already published.")
        return redirect('template_list')
        
    template.state = 'Published'
    template.save()
    messages.success(request, f"Template '{template.name}' has been successfully published.")
    return redirect('template_list')

@login_required
def template_delete(request, template_id):
    tenant = request.tenant
    if not is_admin_user(request):
        messages.error(request, "Permission denied. Admin privileges required.")
        return redirect('template_list')
        
    template = get_object_or_404(AssessmentTemplate, id=template_id, tenant=tenant)
    template.delete()
    messages.success(request, f"Template '{template.name}' deleted successfully.")
    return redirect('template_list')

@login_required
def template_assessment_list(request):
    tenant = request.tenant
    user_role = getattr(request, 'user_role', None)
    user_client = getattr(request, 'user_client', None)
    
    assessments = TemplateAssessment.objects.filter(tenant=tenant).select_related('client', 'template').order_by('-created_at')
    if user_role == 'client':
        assessments = assessments.filter(client=user_client)
        
    return render(request, 'assessments/template_assessment_list.html', {
        'assessments': assessments,
        'user_role': user_role
    })


@login_required
def template_assessment_delete(request, assessment_id):
    tenant = request.tenant
    user_role = getattr(request, 'user_role', None)
    if user_role == 'client':
        messages.error(request, "Permission denied. Client users cannot delete questionnaire runs.")
        return redirect('template_assessment_list')

    assessment = get_object_or_404(TemplateAssessment, id=assessment_id, tenant=tenant)
    if request.method != 'POST':
        messages.error(request, "Invalid delete request.")
        return redirect('template_assessment_list')

    assessment_name = assessment.name
    assessment.delete()
    log_audit_event(
        tenant=tenant,
        user=request.user,
        event_type='ASSESSMENT',
        action='DELETE',
        payload={
            'template_assessment_id': assessment_id,
            'name': assessment_name,
        },
        ip_address=request.META.get('REMOTE_ADDR')
    )
    messages.success(request, f"Questionnaire run '{assessment_name}' was deleted.")
    return redirect('template_assessment_list')

@login_required
def template_assessment_create(request):
    tenant = request.tenant
    user_role = getattr(request, 'user_role', None)
    if user_role == 'client':
        messages.error(request, "Permission denied. Client users cannot initialize assessment runs.")
        return redirect('template_assessment_list')
    clients = Client.objects.filter(tenant=tenant)
    templates = AssessmentTemplate.objects.filter(tenant=tenant, state='Published', is_latest=True)
    
    if request.method == 'POST':
        name = request.POST.get('name')
        client_id = request.POST.get('client')
        tpl_id = request.POST.get('template')
        
        client_obj = get_object_or_404(Client, id=client_id, tenant=tenant)
        tpl_obj = get_object_or_404(AssessmentTemplate, id=tpl_id, tenant=tenant)
        
        if name:
            ass = TemplateAssessment.objects.create(
                tenant=tenant,
                client=client_obj,
                template=tpl_obj,
                name=name.strip(),
                status='Draft'
            )
            log_audit_event(
                tenant=tenant,
                user=request.user,
                event_type='ASSESSMENT',
                action='CREATE',
                payload={
                    'template_assessment_id': ass.id,
                    'name': ass.name,
                    'client_id': client_obj.id,
                    'template_id': tpl_obj.id,
                },
                ip_address=request.META.get('REMOTE_ADDR')
            )
            messages.success(request, f"Assessment run '{name}' initialized.")
            first_sec = tpl_obj.sections.first()
            if first_sec:
                return redirect('template_assessment_fill', assessment_id=ass.id, section_id=first_sec.id)
            else:
                messages.warning(request, "Template has no sections defined.")
                return redirect('template_assessment_list')
        else:
            messages.error(request, "Assessment name is required.")
            
    return render(request, 'assessments/template_assessment_create.html', {
        'clients': clients,
        'templates': templates
    })

@login_required
def template_assessment_fill(request, assessment_id, section_id):
    tenant = request.tenant
    user_role = getattr(request, 'user_role', None)
    user_client = getattr(request, 'user_client', None)
    
    if user_role == 'client':
        assessment = get_object_or_404(TemplateAssessment, id=assessment_id, tenant=tenant, client=user_client)
    else:
        assessment = get_object_or_404(TemplateAssessment, id=assessment_id, tenant=tenant)
    if assessment.status == 'Completed' and request.method == 'POST':
        messages.error(request, "Completed assessment runs are locked. Create a new run or reopen the assessment before editing answers.")
        return redirect('template_assessment_list')
    template = assessment.template
    sections = template.sections.all()
    current_section = get_object_or_404(TemplateSection, id=section_id, template=template)
    questions = current_section.questions.all().prefetch_related('choices')
    
    # Save answers on POST
    if request.method == 'POST':
        with transaction.atomic():
            for q in questions:
                input_name = f"answer_{q.id}"
                ans, _ = TemplateAnswer.objects.get_or_create(assessment=assessment, question=q)
                
                if q.question_type in ['Text', 'LongText', 'Date', 'Numeric']:
                    ans.text_value = request.POST.get(input_name, '').strip()
                    ans.save()
                elif q.question_type in ['Dropdown', 'Radio']:
                    choice_id = request.POST.get(input_name)
                    ans.selected_choices.clear()
                    if choice_id:
                        choice_obj = get_object_or_404(QuestionChoice, id=choice_id, question=q)
                        ans.selected_choices.add(choice_obj)
                    ans.save()
                elif q.question_type == 'MultiSelect':
                    choice_ids = request.POST.getlist(input_name)
                    ans.selected_choices.clear()
                    for cid in choice_ids:
                        choice_obj = get_object_or_404(QuestionChoice, id=cid, question=q)
                        ans.selected_choices.add(choice_obj)
                    ans.save()
                elif q.question_type == 'Evidence':
                    doc_ids = request.POST.getlist(input_name)
                    ans.attached_evidence.clear()
                    for doc_id in doc_ids:
                        doc_obj = get_object_or_404(EvidenceDocument, id=doc_id, tenant=tenant)
                        ans.attached_evidence.add(doc_obj)
                    ans.save()
            
            if assessment.status == 'Draft':
                assessment.status = 'InProgress'
                assessment.save()
                
        # Log Audit Event
        log_audit_event(
            tenant=tenant,
            user=request.user,
            event_type='ASSESSMENT',
            action='UPDATE',
            payload={
                'template_assessment_id': assessment.id,
                'section_id': current_section.id,
                'status': assessment.status,
            },
            ip_address=request.META.get('REMOTE_ADDR')
        )
        messages.success(request, "Progress saved successfully.")
        
        if request.POST.get('action') == 'complete':
            return redirect('template_assessment_complete', assessment_id=assessment.id)
            
        next_sec_id = request.POST.get('next_section_id')
        if next_sec_id:
            return redirect('template_assessment_fill', assessment_id=assessment.id, section_id=next_sec_id)
            
        return redirect('template_assessment_fill', assessment_id=assessment.id, section_id=current_section.id)

    # Load existing answers
    existing_answers = {ans.question_id: ans for ans in assessment.answers.all()}
    for q in questions:
        q.answer = existing_answers.get(q.id)
        
    # Restrict evidence documents selection for clients
    from django.db.models import Q
    evidence_docs = EvidenceDocument.objects.filter(tenant=tenant)
    if user_role == 'client':
        evidence_docs = evidence_docs.filter(
            Q(assessment__client=user_client) |
            Q(risk_item__assessment__client=user_client) |
            Q(finding__assessment__client=user_client) |
            Q(treatment__risk_item__assessment__client=user_client) |
            Q(created_by=request.user)
        ).distinct()
    
    # Simple navigation logic
    prev_section = sections.filter(order__lt=current_section.order).last()
    next_section = sections.filter(order__gt=current_section.order).first()
    
    # Fetch comments thread for discussion
    comments = assessment.comments.filter(parent=None).select_related('user').prefetch_related('replies__user')
    
    return render(request, 'assessments/template_assessment_fill.html', {
        'assessment': assessment,
        'template': template,
        'sections': sections,
        'current_section': current_section,
        'questions': questions,
        'answers': existing_answers,
        'evidence_docs': evidence_docs,
        'prev_section': prev_section,
        'next_section': next_section,
        'comments': comments,
        'user_role': user_role
    })

@login_required
def template_assessment_complete(request, assessment_id):
    tenant = request.tenant
    user_role = getattr(request, 'user_role', None)
    user_client = getattr(request, 'user_client', None)
    
    if user_role == 'client':
        assessment = get_object_or_404(TemplateAssessment, id=assessment_id, tenant=tenant, client=user_client)
    else:
        assessment = get_object_or_404(TemplateAssessment, id=assessment_id, tenant=tenant)
    if assessment.status == 'Completed':
        messages.warning(request, "This assessment run is already completed.")
        return redirect('template_assessment_list')
    template = assessment.template
    
    # Validate required answers
    errors = []
    for sec in template.sections.all():
        for q in sec.questions.all():
            if q.is_required:
                ans = TemplateAnswer.objects.filter(assessment=assessment, question=q).first()
                is_filled = False
                if ans:
                    if q.question_type in ['Text', 'LongText', 'Date', 'Numeric'] and ans.text_value:
                        is_filled = True
                    elif q.question_type in ['Dropdown', 'Radio', 'MultiSelect'] and ans.selected_choices.exists():
                        is_filled = True
                    elif q.question_type == 'Evidence' and ans.attached_evidence.exists():
                        is_filled = True
                if not is_filled:
                    errors.append(f"Question '{q.text}' in section '{sec.name}' is required.")
                    
    if errors:
        for err in errors:
            messages.error(request, err)
        first_sec = template.sections.first()
        if first_sec:
            return redirect('template_assessment_fill', assessment_id=assessment.id, section_id=first_sec.id)
        return redirect('template_assessment_list')
        
    # Calculate score
    total_score = 0.0
    answers = assessment.answers.all()
    for ans in answers:
        if ans.question.question_type in ['Dropdown', 'Radio', 'MultiSelect']:
            for choice in ans.selected_choices.all():
                total_score += choice.score
                
    # Evaluate range
    rating = "Unrated"
    r_range = template.scoring_ranges.filter(min_score__lte=total_score, max_score__gte=total_score).first()
    if r_range:
        rating = r_range.label
        
    assessment.total_score = total_score
    assessment.compliance_rating = rating
    assessment.status = 'Completed'
    assessment.completed_at = timezone.now()
    assessment.save()
    
    log_audit_event(
        tenant=tenant,
        user=request.user,
        event_type='ASSESSMENT',
        action='UPDATE',
        payload={
            'template_assessment_id': assessment.id,
            'status': 'Completed',
            'total_score': total_score,
            'compliance_rating': rating,
        },
        ip_address=request.META.get('REMOTE_ADDR')
    )
    
    messages.success(request, f"Assessment '{assessment.name}' completed! Score: {total_score}, Rating: {rating}")
    return redirect('template_assessment_list')
