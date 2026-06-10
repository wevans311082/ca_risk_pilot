from django.db.models import Q


ASSESSMENT_TRANSITIONS = {
    'Draft': {'Draft', 'InProgress', 'Archived'},
    'InProgress': {'InProgress', 'UnderReview', 'Completed', 'Archived'},
    'UnderReview': {'UnderReview', 'InProgress', 'Completed', 'Archived'},
    'Completed': {'Completed', 'Archived'},
    'Archived': {'Archived'},
}

CENTRAL_RISK_TRANSITIONS = {
    'Draft': {'Draft', 'Active', 'Archived'},
    'Active': {'Active', 'Under Review', 'Mitigated', 'Archived'},
    'Under Review': {'Under Review', 'Active', 'Mitigated', 'Archived'},
    'Mitigated': {'Mitigated', 'Active', 'Archived'},
    'Accepted': {'Accepted', 'Active', 'Under Review', 'Archived'},
    'Archived': {'Archived'},
}


def get_user_role(request):
    return getattr(request, 'user_role', None)


def get_user_client(request):
    return getattr(request, 'user_client', None)


def can_manage_risk_content(request):
    role = get_user_role(request)
    return request.user.is_superuser or role in {'owner', 'admin', 'assessor', 'reviewer'}


def can_administer_tenant(request):
    role = get_user_role(request)
    return request.user.is_superuser or role in {'owner', 'admin'}


def allowed_dashboard_types(request):
    role = get_user_role(request)
    if request.user.is_superuser or role in {'owner', 'admin'}:
        return ['executive', 'assessor', 'client']
    if role in {'assessor', 'reviewer'}:
        return ['assessor', 'client']
    return ['client']


def default_dashboard_type(request):
    allowed = allowed_dashboard_types(request)
    return allowed[0]


def validate_transition(current_status, new_status, transition_map, label):
    allowed = transition_map.get(current_status, {current_status})
    if new_status not in allowed:
        allowed_text = ', '.join(sorted(allowed))
        raise ValueError(
            f"Invalid {label} status transition from '{current_status}' to '{new_status}'. "
            f"Allowed next states: {allowed_text}."
        )


def scope_assessments_for_user(queryset, request):
    if get_user_role(request) == 'client':
        return queryset.filter(client=get_user_client(request))
    return queryset


def scope_reports_for_user(queryset, request):
    if get_user_role(request) == 'client':
        return queryset.filter(assessment__client=get_user_client(request))
    return queryset


def scope_report_versions_for_user(queryset, request):
    if get_user_role(request) == 'client':
        return queryset.filter(document__assessment__client=get_user_client(request))
    return queryset


def evidence_scope_filter(request, prefix=''):
    user_client = get_user_client(request)
    fields = {
        'assessment__client': user_client,
        'risk_item__assessment__client': user_client,
        'finding__assessment__client': user_client,
        'treatment__risk_item__assessment__client': user_client,
        'created_by': request.user,
    }
    criteria = Q()
    for field, value in fields.items():
        criteria |= Q(**{f'{prefix}{field}': value})
    return criteria


def scope_evidence_for_user(queryset, request):
    if get_user_role(request) == 'client':
        return queryset.filter(evidence_scope_filter(request)).distinct()
    return queryset


def latest_evidence_version(document):
    return document.versions.order_by('-version_number').first()


def evidence_is_clean(document):
    latest = latest_evidence_version(document)
    return latest is not None and latest.status == 'Clean'
