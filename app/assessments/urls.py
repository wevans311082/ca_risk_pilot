from django.urls import path
from .views import (
    dashboard, create_assessment, assessment_detail,
    risk_item_edit, risk_item_delete
)
from .template_views import (
    template_list, template_edit, template_builder,
    template_clone, template_create_version, template_publish, template_delete,
    template_assessment_list, template_assessment_create,
    template_assessment_fill, template_assessment_complete
)

from .views_central_risk import (
    central_risk_list, central_risk_edit, central_risk_detail,
    central_risk_review, central_risk_accept
)

urlpatterns = [
    path('', dashboard, name='dashboard'),
    path('assessments/create/', create_assessment, name='create_assessment'),
    path('assessments/<int:assessment_id>/', assessment_detail, name='assessment_detail'),
    path('assessments/<int:assessment_id>/risk-items/add/', risk_item_edit, name='risk_item_add'),
    path('assessments/<int:assessment_id>/risk-items/<int:risk_item_id>/edit/', risk_item_edit, name='risk_item_edit'),
    path('assessments/<int:assessment_id>/risk-items/<int:risk_item_id>/delete/', risk_item_delete, name='risk_item_delete'),

    # Central Risk Register paths
    path('risks/', central_risk_list, name='central_risk_list'),
    path('risks/add/', central_risk_edit, name='central_risk_add'),
    path('risks/<int:risk_id>/', central_risk_detail, name='central_risk_detail'),
    path('risks/<int:risk_id>/edit/', central_risk_edit, name='central_risk_edit'),
    path('risks/<int:risk_id>/review/', central_risk_review, name='central_risk_review'),
    path('risks/<int:risk_id>/accept/', central_risk_accept, name='central_risk_accept'),

    # Dynamic templates paths
    path('templates/', template_list, name='template_list'),
    path('templates/create/', template_edit, name='template_create'),
    path('templates/<int:template_id>/edit/', template_edit, name='template_edit'),
    path('templates/<int:template_id>/builder/', template_builder, name='template_builder'),
    path('templates/<int:template_id>/clone/', template_clone, name='template_clone'),
    path('templates/<int:template_id>/version/', template_create_version, name='template_create_version'),
    path('templates/<int:template_id>/publish/', template_publish, name='template_publish'),
    path('templates/<int:template_id>/delete/', template_delete, name='template_delete'),
    
    # Template assessments (questionnaires) paths
    path('template-assessments/', template_assessment_list, name='template_assessment_list'),
    path('template-assessments/create/', template_assessment_create, name='template_assessment_create'),
    path('template-assessments/<int:assessment_id>/fill/<int:section_id>/', template_assessment_fill, name='template_assessment_fill'),
    path('template-assessments/<int:assessment_id>/complete/', template_assessment_complete, name='template_assessment_complete'),
]
