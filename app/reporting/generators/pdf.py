import io
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from django.utils import timezone

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and render 'Page X of Y' 
    along with corporate headers/footers.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        
        # Colors
        deep_blue = colors.HexColor("#003388")
        grey = colors.HexColor("#777777")
        
        # Top Header line & text
        self.setStrokeColor(deep_blue)
        self.setLineWidth(1)
        self.line(36, 756, 576, 756)
        
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(deep_blue)
        self.drawString(36, 762, "RISKPILOT CYBER RISK ASSESSMENT PLATFORM")
        
        # Bottom Footer line & text
        self.setStrokeColor(colors.HexColor("#E0E0E0"))
        self.line(36, 54, 576, 54)
        
        self.setFont("Helvetica", 8)
        self.setFillColor(grey)
        self.drawString(36, 42, "Branded for: www.ishelp.co.uk - STRICTLY CONFIDENTIAL")
        
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(576, 42, page_text)
        
        self.restoreState()


def generate_pdf_report(assessment, report_type):
    # Setup document template
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=54,
        bottomMargin=54
    )

    # Styles
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#003388"),
        spaceAfter=15
    )

    h1_style = ParagraphStyle(
        'Heading1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#003388"),
        spaceBefore=12,
        spaceAfter=8,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Heading2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#882211"), # Rust Red
        spaceBefore=10,
        spaceAfter=6,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'BodyText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#333333"),
        spaceAfter=6
    )

    tbl_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=11,
        textColor=colors.white,
        alignment=0
    )

    tbl_body_style = ParagraphStyle(
        'TableBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#333333")
    )

    story = []

    # 1. Executive Summary
    if report_type == 'ExecutiveSummary':
        story.append(Paragraph(f"Executive Summary: {assessment.name}", title_style))
        story.append(Spacer(1, 10))
        
        # Meta info
        meta_html = (
            f"<b>Client Organisation:</b> {assessment.client.name}<br/>"
            f"<b>Client Contact:</b> {assessment.client.email}<br/>"
            f"<b>Generated Date:</b> {timezone.now().strftime('%Y-%m-%d %H:%M')}<br/>"
            f"<b>Assessment Methodology:</b> {assessment.methodology_version}<br/>"
            f"<b>Current Assessment Status:</b> {assessment.status}"
        )
        story.append(Paragraph(meta_html, body_style))
        story.append(Spacer(1, 15))

        story.append(Paragraph("Assessment Overview", h1_style))
        overview_text = (
            f"This Executive Summary Report outlines the high-level security profile and posture evaluation of "
            f"'{assessment.name}'. The goal is to provide corporate stakeholders and executive teams "
            f"a direct overview of evaluated threat environments, existing controls effectiveness, and needed treatments."
        )
        story.append(Paragraph(overview_text, body_style))
        
        story.append(Paragraph("Corporate Posture Summary", h1_style))
        
        total_risks = assessment.risk_items.count()
        high_risks = len([r for r in assessment.risk_items.all() if r.risk_category in ['High', 'Critical']])
        open_findings = assessment.findings.filter(status='Open').count()
        mitigated_risks = assessment.risk_items.filter(treatment__status__in=['Mitigated', 'Closed']).count()

        # Build table
        table_data = [
            [Paragraph("Risk Metric", tbl_header_style), Paragraph("Count / Value", tbl_header_style)],
            [Paragraph("Total Identified Risks", tbl_body_style), Paragraph(str(total_risks), tbl_body_style)],
            [Paragraph("High & Critical Severity Risks", tbl_body_style), Paragraph(str(high_risks), tbl_body_style)],
            [Paragraph("Open Gaps / Findings Logged", tbl_body_style), Paragraph(str(open_findings), tbl_body_style)],
            [Paragraph("Mitigated Risks", tbl_body_style), Paragraph(str(mitigated_risks), tbl_body_style)],
        ]
        
        t = Table(table_data, colWidths=[340, 200])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#003388")),
            ('ALIGN', (1,1), (1,-1), 'RIGHT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#D0D0D0")),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(t)

    # 2. Detailed Risk Assessment
    elif report_type == 'DetailedRiskAssessment':
        story.append(Paragraph(f"Detailed Cyber Risk Assessment: {assessment.name}", title_style))
        story.append(Spacer(1, 10))

        story.append(Paragraph("Assessment Metadata & Scope", h1_style))
        scope_html = (
            f"<b>Client Organisation:</b> {assessment.client.name} ({assessment.client.email})<br/>"
            f"<b>Methodology Framework:</b> {assessment.methodology_version}<br/>"
            f"<b>Main Asset Evaluated:</b> {assessment.asset}<br/>"
            f"<b>Asset Location:</b> {assessment.location}<br/>"
            f"<b>Asset Owner:</b> {assessment.owner}"
        )
        story.append(Paragraph(scope_html, body_style))
        story.append(Spacer(1, 15))

        story.append(Paragraph("Identified Threat Registers & Calculations", h1_style))
        for idx, item in enumerate(assessment.risk_items.all(), start=1):
            item_story = []
            item_story.append(Paragraph(f"Risk Item #{idx}: {item.asset_name}", h2_style))
            
            details_html = (
                f"<b>Threat Scenario:</b> {item.threat.name} - {item.threat.description}<br/>"
                f"<b>Vulnerability:</b> {item.vulnerability}<br/>"
                f"<b>Existing Controls:</b> {item.existing_controls}<br/>"
                f"<b>Inherent Risk Score:</b> {item.risk_score} (Category: {item.risk_category})<br/>"
                f"<b>Residual Risk Score:</b> {item.residual_risk_score if item.residual_risk_score is not None else 'N/A'} (Category: {item.residual_risk_category})"
            )
            item_story.append(Paragraph(details_html, body_style))

            findings = item.findings.all()
            if findings.exists():
                item_story.append(Paragraph("<b>Associated Gaps / Findings:</b>", tbl_body_style))
                for f in findings:
                    item_story.append(Paragraph(f"• {f.title} - Severity: {f.severity} (Status: {f.status})", tbl_body_style))
            
            item_story.append(Spacer(1, 8))
            story.append(KeepTogether(item_story))

    # 3. Risk Register
    elif report_type == 'RiskRegister':
        story.append(Paragraph(f"Risk Register - {assessment.name}", title_style))
        story.append(Paragraph("Tabular listing of all identified threats, inherent calculations, and residual ratings.", body_style))
        story.append(Spacer(1, 10))

        table_data = [
            [
                Paragraph("Asset", tbl_header_style), 
                Paragraph("Threat Scenario", tbl_header_style), 
                Paragraph("Inherent", tbl_header_style), 
                Paragraph("Residual", tbl_header_style)
            ]
        ]
        
        for item in assessment.risk_items.all():
            table_data.append([
                Paragraph(item.asset_name, tbl_body_style),
                Paragraph(item.threat.name, tbl_body_style),
                Paragraph(f"{item.risk_score} ({item.risk_category})", tbl_body_style),
                Paragraph(f"{item.residual_risk_score if item.residual_risk_score is not None else 'N/A'} ({item.residual_risk_category})", tbl_body_style)
            ])

        t = Table(table_data, colWidths=[120, 220, 100, 100])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#003388")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#D0D0D0")),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(t)

    # 4. Treatment Plan
    elif report_type == 'TreatmentPlan':
        story.append(Paragraph(f"Risk Treatment Plan: {assessment.name}", title_style))
        story.append(Paragraph("Action tracking register mapping controls and treatment plans assigned to mitigate vulnerabilities.", body_style))
        story.append(Spacer(1, 10))

        table_data = [
            [
                Paragraph("Asset Affected", tbl_header_style), 
                Paragraph("Treatment Action Description", tbl_header_style), 
                Paragraph("Owner", tbl_header_style), 
                Paragraph("Target Date", tbl_header_style), 
                Paragraph("Status", tbl_header_style)
            ]
        ]

        for item in assessment.risk_items.all():
            treatment = getattr(item, 'treatment', None)
            if treatment:
                table_data.append([
                    Paragraph(item.asset_name, tbl_body_style),
                    Paragraph(treatment.action, tbl_body_style),
                    Paragraph(treatment.owner or "Unassigned", tbl_body_style),
                    Paragraph(treatment.target_date.strftime("%Y-%m-%d") if treatment.target_date else "N/A", tbl_body_style),
                    Paragraph(treatment.status, tbl_body_style)
                ])

        t = Table(table_data, colWidths=[90, 210, 80, 80, 80])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#003388")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#D0D0D0")),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(t)

    # 5. Change Request
    elif report_type == 'ChangeRequest':
        story.append(Paragraph(f"Change Request Assessment: {assessment.name}", title_style))
        story.append(Spacer(1, 10))

        story.append(Paragraph("Change Context", h1_style))
        story.append(Paragraph(assessment.change_request or "No associated change request details provided.", body_style))
        story.append(Spacer(1, 10))

        story.append(Paragraph("Business Process Impact", h1_style))
        story.append(Paragraph(assessment.business_process_impact or "No impact assessment provided.", body_style))
        story.append(Spacer(1, 10))

        story.append(Paragraph("CIA Impact Assessment Checkmarks", h1_style))
        cia_html = (
            f"• <b>Confidentiality Affected:</b> {'Yes' if assessment.confidentiality_affected else 'No'}<br/>"
            f"• <b>Integrity Affected:</b> {'Yes' if assessment.integrity_affected else 'No'}<br/>"
            f"• <b>Availability Affected:</b> {'Yes' if assessment.availability_affected else 'No'}"
        )
        story.append(Paragraph(cia_html, body_style))

    # Build PDF
    doc.build(story, canvasmaker=NumberedCanvas)
    return buffer.getvalue()
