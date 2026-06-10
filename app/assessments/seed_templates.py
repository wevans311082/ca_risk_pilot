import re
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[2]
EXAMPLE_ASSESSMENTS_DIR = ROOT_DIR / "example_assessments"

ASSESSMENT_CHOICES = [
    ("Implemented and evidenced", 1.0),
    ("Partially implemented", 0.5),
    ("Not implemented", 0.0),
    ("Not applicable with rationale", 0.0),
]

ACHIEVEMENT_CHOICES = [
    ("Achieved with strong evidence", 2.0),
    ("Partially achieved", 1.0),
    ("Not achieved", 0.0),
    ("Not applicable with rationale", 0.0),
]

GAP_SEVERITY_CHOICES = [
    ("No material gap", 0.0),
    ("Low gap", 0.0),
    ("Medium gap", 0.0),
    ("High gap", 0.0),
]

REMEDIATION_PRIORITY_CHOICES = [
    ("No action required", 0.0),
    ("Low priority", 0.0),
    ("Medium priority", 0.0),
    ("High priority", 0.0),
    ("Critical priority", 0.0),
]

RISK_ASSESSMENT_FIELD_CHOICES = [
    ("Complete", 1.0),
    ("Needs review", 0.5),
    ("Missing", 0.0),
]


def get_seed_templates():
    templates = [
        change_request_risk_template(),
        caf_template(),
        cyber_essentials_template(),
    ]
    templates.extend(dcc_templates())
    return templates


def change_request_risk_template():
    return {
        "name": "Change Request Risk Assessment Register",
        "description": (
            "Risk assessment template matching the example spreadsheet layout: change context, "
            "asset/threat rows, inherent scoring, CIA impact, risk treatment, residual scoring, "
            "actions, ownership, and approvals."
        ),
        "sections": [
            {
                "name": "Change Request",
                "description": "Front-sheet context from the Change Request worksheet.",
                "order": 1,
                "questions": [
                    text_q("Change reference", "Record the change ticket/reference number.", 1),
                    text_q("Equipment, software, supplier or service in scope", "Match the workbook's Equipment/Software/Supplier field.", 2),
                    text_q("Originator name", "Workbook front-sheet field.", 3),
                    {"text": "Date raised", "question_type": "Date", "order": 4, "help_text": "Workbook front-sheet field."},
                    dropdown_zero_q("Change type", "Classify the change to support risk triage.", 5, ["New system", "System replacement", "Supplier change", "Configuration change", "Data migration", "Process change", "Emergency change"]),
                    long_q("Change proposed", "Describe the change being assessed.", 6),
                    long_q("Business justification", "Why the change is required and what business outcome it supports.", 7),
                    long_q("Systems, data and locations in scope", "Capture all systems, data classes, locations, and dependencies in scope.", 8),
                    long_q("Systems, data and locations out of scope", "Record exclusions and rationale.", 9),
                    long_q("Implementation plan", "Deployment steps, timings, owners, and dependencies.", 10),
                    long_q("Rollback plan", "Rollback decision point, steps, owners, and tested restore approach.", 11),
                    long_q("Testing and validation plan", "Pre-change, implementation, and post-change checks.", 12),
                    long_q("Communication and approval plan", "Stakeholders, approvers, CAB references, customer/client notifications.", 13),
                ],
            },
            {
                "name": "Risk Register Row Fields",
                "description": "Per-risk fields that mirror the spreadsheet risk assessment row.",
                "order": 2,
                "questions": [
                    text_q("Asset affected", "Spreadsheet column: Asset Affected.", 1),
                    text_q("Location", "Spreadsheet column: Location.", 2),
                    text_q("Owner", "Spreadsheet column: Owner.", 3),
                    dropdown_q("Threat category", "Spreadsheet column: Threat.", 4, [
                        "Physical damage",
                        "Natural events",
                        "Loss of essential services",
                        "Technical failures",
                        "Unauthorised actions",
                        "Compromise of information",
                        "Compromise of functions",
                    ]),
                    long_q("Vulnerability", "Spreadsheet column: Vulnerability.", 5),
                    long_q("Existing control measures", "Spreadsheet column: Existing control measures.", 6),
                    long_q("Threat source and scenario", "Describe accidental, deliberate, environmental, supplier, insider, or external threat source.", 7),
                    long_q("Affected information assets and data classes", "Record personal data, commercial data, operational data, credentials, logs, or regulated data.", 8),
                    multi_q("Key processes affected", "Spreadsheet columns for business processes affected.", 9, [
                        "Invoicing",
                        "Credit Control",
                        "Sales Order Processing",
                        "Tax Returns",
                        "Accounts Preparation",
                        "Customer Service",
                        "Operations",
                    ]),
                    long_q("Operational impact narrative", "Explain how the risk would affect people, process, technology, customers, legal obligations, or suppliers.", 10),
                    long_q("Evidence supporting current controls", "Reference policies, screenshots, configurations, contracts, test outputs, or tickets.", 11),
                ],
            },
            {
                "name": "Inherent Risk Scoring",
                "description": "Frequency, probability, event likelihood, impact severity, and risk rating.",
                "order": 3,
                "questions": [
                    dropdown_q("Frequency of threat occurrence", "Use the workbook criteria: <1/year, 1/month to 1/year, >1/month.", 1, ["<1/year", "1/month to 1/year", ">1/month"]),
                    dropdown_q("Probability of vulnerability breach", "Use the workbook criteria: <1%, 1% to 20%, >20%.", 2, ["<1% of instances", "1% to 20% of instances", ">20% of instances"]),
                    multi_q("Security impact dimensions", "Spreadsheet CIA columns.", 3, ["Confidentiality", "Integrity", "Availability"]),
                    dropdown_q("Impact severity", "Use the workbook impact criteria.", 4, ["Insignificant", "Minor", "Moderate", "High", "Major"]),
                    dropdown_q("Risk rating", "Calculated from likelihood x impact in the spreadsheet.", 5, ["Low", "Medium", "High"]),
                    long_q("Likelihood rationale", "Justify selected threat frequency and vulnerability probability.", 6),
                    long_q("Impact rationale", "Justify selected CIA dimensions and impact severity.", 7),
                    long_q("Risk acceptance threshold check", "Explain whether the inherent risk is within appetite and why.", 8),
                    dropdown_zero_q("Regulatory or contractual exposure", "Identify compliance exposure created by the risk.", 9, ["None", "Contractual SLA", "UK GDPR", "NIS/CAF", "DCC/MOD", "Financial/regulatory", "Other"]),
                    long_q("Assessor challenge notes", "Record challenge, assumptions, contradictory evidence, or validation needed.", 10),
                ],
            },
            {
                "name": "Treatment and Residual Risk",
                "description": "Proposed controls, residual scoring, action owner, date, and approval trail.",
                "order": 4,
                "questions": [
                    long_q("Actions or additional controls required", "Spreadsheet action plan field.", 1),
                    text_q("Responsibility", "Action owner or responsible function.", 2),
                    {"text": "Required completion date", "question_type": "Date", "order": 3, "help_text": "Target date for treatment completion."},
                    dropdown_q("Residual threat frequency", "Recalculated frequency after proposed actions.", 4, ["<1/year", "1/month to 1/year", ">1/month"]),
                    dropdown_q("Residual vulnerability probability", "Recalculated vulnerability probability after proposed actions.", 5, ["<1% of instances", "1% to 20% of instances", ">20% of instances"]),
                    dropdown_q("Residual impact severity", "Recalculated impact after proposed actions.", 6, ["Insignificant", "Minor", "Moderate", "High", "Major"]),
                    dropdown_q("Residual risk rating", "Residual rating after controls.", 7, ["Low", "Medium", "High"]),
                    long_q("Residual risk rationale", "Explain why treatment changes likelihood, probability, or impact.", 8),
                    dropdown_zero_q("Treatment decision", "Select how this risk will be handled.", 9, ["Mitigate", "Accept", "Transfer", "Avoid", "Monitor"]),
                    long_q("Dependencies and blockers", "Record dependencies, constraints, budget, supplier, or technical blockers.", 10),
                    dropdown_zero_q("Remediation priority", "Prioritise remediation for tracking.", 11, ["Critical", "High", "Medium", "Low", "No action"]),
                    long_q("Validation evidence required", "What evidence is required to close or re-rate the treatment.", 12),
                    long_q("Assessment team approval notes", "Capture assessor, business owner, and approver rationale.", 13),
                    text_q("Business owner approval", "Name or role of approver.", 14),
                    {"text": "Approval date", "question_type": "Date", "order": 15, "help_text": "Date risk decision was approved."},
                ],
            },
        ],
        "ranges": [("Incomplete", 0.0, 30.0, "danger"), ("Review Required", 30.1, 45.0, "warning"), ("Complete", 45.1, 60.0, "success")],
    }


def caf_template():
    objectives = [
        ("Objective A - Managing Security Risk", [
            ("A1 Governance", [
                "Senior accountable owner is assigned for cyber security and essential function resilience.",
                "Board or executive governance receives regular cyber risk reporting.",
                "Cyber security objectives are aligned to business objectives and risk appetite.",
                "Policies, standards and procedures are owned, approved, communicated and reviewed.",
                "Cyber security responsibilities are embedded across operational teams and suppliers.",
            ]),
            ("A2 Risk Management", [
                "Cyber risks to essential functions are identified and assessed using a repeatable method.",
                "Risk owners are assigned and accountable for treatment decisions.",
                "Risk assessments consider threat, vulnerability, impact, dependencies and business harm.",
                "Risk treatment plans are tracked through to completion or formal acceptance.",
                "Risk appetite and tolerance are defined and used in decision making.",
            ]),
            ("A3 Asset Management", [
                "Essential functions, supporting systems, data, people and dependencies are documented.",
                "Asset inventories are maintained with ownership, location, criticality and lifecycle state.",
                "Data assets are classified and mapped to systems, users and processing locations.",
                "Changes to assets and dependencies update the inventory in a timely way.",
                "Asset information supports incident response, recovery and vulnerability management.",
            ]),
            ("A4 Supply Chain", [
                "Suppliers supporting essential functions are identified and risk assessed.",
                "Security requirements are included in contracts, onboarding and assurance activities.",
                "Supplier access, data handling and service dependencies are governed and monitored.",
                "Supplier incidents, vulnerabilities and changes are communicated through defined routes.",
                "Exit, continuity and contingency arrangements are documented for critical suppliers.",
            ]),
        ]),
        ("Objective B - Protecting Against Cyber Attack", [
            ("B1 Service Protection Policies and Processes", [
                "Security policies and operational procedures protect essential services throughout their lifecycle.",
                "Secure configuration baselines are defined and enforced for relevant technologies.",
                "Change management assesses cyber risk before implementation.",
                "Security controls are monitored for effectiveness and exceptions are managed.",
                "Operational procedures include backup, restore, maintenance and secure administration.",
            ]),
            ("B2 Identity and Access Control", [
                "User identities are uniquely assigned, approved, reviewed and removed promptly.",
                "Privileged access is minimised, monitored and subject to stronger authentication.",
                "MFA is applied to remote, privileged and high-risk access paths.",
                "Access rights follow least privilege and separation of duties.",
                "Authentication secrets and service accounts are managed securely.",
            ]),
            ("B3 Data Security", [
                "Sensitive and essential service data is identified, classified and protected.",
                "Data is protected at rest, in transit and during transfer to suppliers or partners.",
                "Cryptographic methods and key management are appropriate and governed.",
                "Removable media, mobile devices and alternate working locations are controlled.",
                "Retention, disposal, sanitisation and destruction requirements are implemented.",
            ]),
            ("B4 System Security", [
                "Systems are securely configured and hardened against known attack techniques.",
                "Vulnerabilities are identified, prioritised, remediated and exceptions tracked.",
                "Patch management meets risk-based timelines for operating systems, applications and firmware.",
                "Anti-malware, application control or equivalent protection is deployed where appropriate.",
                "Penetration testing or technical assurance validates security of exposed systems.",
            ]),
            ("B5 Resilient Networks and Systems", [
                "Network architecture separates public, internal, administrative and critical zones.",
                "Traffic is denied by default at managed interfaces unless explicitly authorised.",
                "Backups are protected, tested and resilient to ransomware or destructive events.",
                "Capacity, redundancy and recovery designs meet essential function resilience needs.",
                "Remote maintenance and diagnostics are authorised, authenticated and supervised.",
            ]),
            ("B6 Staff Awareness and Training", [
                "Staff receive cyber security training appropriate to their role and access.",
                "Users understand reporting routes for incidents, phishing, weaknesses and policy breaches.",
                "Privileged users and administrators receive deeper technical/security training.",
                "Training is refreshed and measured for completion and effectiveness.",
                "Acceptable use and security responsibilities are acknowledged by staff and contractors.",
            ]),
        ]),
        ("Objective C - Detecting Cyber Security Events", [
            ("C1 Security Monitoring", [
                "Security logs cover key systems, identities, network boundaries and essential service components.",
                "Logs are protected, retained and correlated to support investigation.",
                "Alerts are triaged with defined severity, ownership and response timelines.",
                "Monitoring rules cover known threats, misuse, abnormal activity and control failure.",
                "Monitoring capability is tested and reviewed for coverage gaps.",
            ]),
            ("C2 Proactive Security Event Discovery", [
                "Threat intelligence, advisories and indicators are reviewed and acted upon.",
                "Proactive searches are performed for compromise, misconfiguration and unauthorised components.",
                "Detection use cases are updated after incidents, exercises and new threat information.",
                "Security teams can investigate anomalies across relevant logs and systems.",
                "Findings from proactive discovery feed risk, remediation and improvement processes.",
            ]),
        ]),
        ("Objective D - Minimising the Impact of Cyber Security Incidents", [
            ("D1 Response and Recovery Planning", [
                "Incident response plans define roles, severity, escalation, communications and decision authority.",
                "Recovery plans define restore priorities, dependencies, RTO/RPO and validation steps.",
                "Response and recovery plans are exercised using realistic cyber scenarios.",
                "Legal, regulatory, customer and supplier notification requirements are understood.",
                "Incident tooling, evidence handling and communications channels are available when needed.",
            ]),
            ("D2 Lessons Learned", [
                "Post-incident reviews identify root causes, control failures and improvement actions.",
                "Lessons learned are assigned owners, tracked to completion and reviewed for effectiveness.",
                "Playbooks, detections, training and risk assessments are updated after incidents.",
                "Exercises and near misses generate the same learning cycle as live incidents.",
                "Senior leadership receives reporting on incident trends and improvement progress.",
            ]),
        ]),
    ]
    sections = []
    for index, (name, principles) in enumerate(objectives, 1):
        questions = []
        order = 1
        for code, indicators in principles:
            questions.extend(principle_question_set(code, indicators, order))
            order += len(indicators) * 7
        questions.append(evidence_q(f"Evidence pack for {name}", "Attach policy, process, technical, operational, or assurance evidence.", order, required=False))
        sections.append({
            "name": name,
            "order": index,
            "questions": questions,
        })
    max_score = float(sum(
        2
        for section in sections
        for question in section["questions"]
        if question["question_type"] == "Radio" and question["choices"] == ACHIEVEMENT_CHOICES
    ))
    return {
        "name": "NCSC CAF 4.0 Assessment",
        "description": "Detailed CAF 4.0 template organised by the four CAF objectives, fourteen principles, outcome indicators, evidence, findings, gaps, and remediation.",
        "sections": sections,
        "ranges": [("Not Achieved", 0.0, max_score * 0.49, "danger"), ("Partially Achieved", max_score * 0.49 + 0.01, max_score * 0.84, "warning"), ("Achieved", max_score * 0.84 + 0.01, max_score, "success")],
    }


def cyber_essentials_template():
    parsed_questions = _parse_cyber_essentials_questions()
    if not parsed_questions:
        parsed_questions = [
            ("A1.1", "Organisation name"),
            ("A2.1", "Scope of certification"),
            ("A3.1", "Boundary firewalls and internet gateways"),
            ("A4.1", "Secure configuration"),
            ("A5.1", "User access control"),
            ("A6.1", "Malware protection"),
            ("A7.1", "Security update management"),
        ]

    sections_by_prefix = [
        ("Organisation and Scope", ("A1", "A2")),
        ("Firewalls and Internet Gateways", ("A3",)),
        ("Secure Configuration", ("A4",)),
        ("User Access Control", ("A5",)),
        ("Malware Protection", ("A6",)),
        ("Security Update Management", ("A7",)),
    ]
    sections = []
    for order, (section_name, prefixes) in enumerate(sections_by_prefix, 1):
        section_questions = []
        question_order = 1
        for code, text in [(code, text) for code, text in parsed_questions if code.startswith(prefixes)]:
            section_questions.extend(control_question_set(
                code=code,
                title=text,
                base_order=question_order,
                status_help="Answer using the Cyber Essentials Danzell question set. Capture evidence and assessor rationale for every answer.",
            ))
            question_order += 7
        if section_questions:
            section_questions.append(evidence_q(f"Evidence pack for {section_name}", "Attach supporting screenshots, exports, policy records, configuration evidence, or assessor notes.", question_order, required=False))
        if section_questions:
            sections.append({"name": section_name, "order": order, "questions": section_questions})

    max_score = float(len(parsed_questions))
    return {
        "name": "Cyber Essentials 2026 Danzell Assessment",
        "description": "Detailed Cyber Essentials preparation template seeded from the local Danzell question set where available, with evidence, findings, gaps and remediation tracking for each question.",
        "sections": sections,
        "ranges": [("Fail", 0.0, max(1.0, max_score - 0.1), "danger"), ("Pass", max_score, max_score, "success")],
    }


def dcc_templates():
    templates = []
    for level in ("L0", "L1", "L2", "L3"):
        controls = _parse_dcc_controls(level)
        if not controls:
            controls = _fallback_dcc_controls(level)
        sections = []
        for order, (section_name, code_prefix) in enumerate([
            ("Certification Prerequisites", "0"),
            ("Objective A - Managing Security Risk", "1"),
            ("Objective B - Protecting Against Cyber Attack", "2"),
            ("Objective C - Detecting Cyber Security Events", "3"),
            ("Objective D - Minimising the Impact of Cyber Security Incidents", "4"),
        ], 1):
            section_controls = [control for control in controls if control["code"].startswith(code_prefix)]
            if not section_controls:
                continue
            questions = []
            question_order = 1
            for control in section_controls:
                questions.extend(control_question_set(
                    code=control["code"],
                    title=control["title"],
                    base_order=question_order,
                    status_help=f"{control['ref']} {control['levels']}. Record implementation status, evidence, and assessor rationale.",
                ))
                question_order += 7
            questions.append(evidence_q(f"Evidence pack for {section_name}", "Attach the evidence bundle supporting this objective.", question_order, required=False))
            sections.append({"name": section_name, "order": order, "questions": questions})
        max_score = float(len(controls))
        templates.append({
            "name": f"DCC {level} Assessment",
            "description": f"Defence Cyber Certification {level} template seeded from the local applicant guide where available.",
            "sections": sections,
            "ranges": [("Not Ready", 0.0, max_score * 0.69, "danger"), ("Remediation Required", max_score * 0.69 + 0.01, max_score * 0.94, "warning"), ("Assessment Ready", max_score * 0.94 + 0.01, max_score, "success")],
        })
    return templates


def text_q(text, help_text, order):
    return {"text": text, "question_type": "Text", "order": order, "help_text": help_text}


def long_q(text, help_text, order):
    return {"text": text, "question_type": "LongText", "order": order, "help_text": help_text}


def evidence_q(text, help_text, order, required=True):
    return {"text": text, "question_type": "Evidence", "order": order, "help_text": help_text, "is_required": required}


def dropdown_q(text, help_text, order, choices):
    return {
        "text": text,
        "question_type": "Dropdown",
        "order": order,
        "help_text": help_text,
        "choices": [(choice, float(index)) for index, choice in enumerate(choices, 1)],
    }


def dropdown_zero_q(text, help_text, order, choices):
    return {
        "text": text,
        "question_type": "Dropdown",
        "order": order,
        "help_text": help_text,
        "choices": [(choice, 0.0) for choice in choices],
    }


def multi_q(text, help_text, order, choices):
    return {
        "text": text,
        "question_type": "MultiSelect",
        "order": order,
        "help_text": help_text,
        "choices": [(choice, 1.0) for choice in choices],
    }


def radio_q(text, help_text, order, choices):
    return {
        "text": text[:500],
        "question_type": "Radio",
        "order": order,
        "help_text": help_text,
        "choices": choices,
    }


def control_question_set(code, title, base_order, status_help):
    prefix = f"{code}: {title}"
    return [
        radio_q(prefix, status_help, base_order, ASSESSMENT_CHOICES),
        long_q(f"{code}: Evidence summary", "Summarise the evidence reviewed, including document names, screenshots, system exports, tickets, or interviews.", base_order + 1),
        evidence_q(f"{code}: Attach evidence", "Attach the evidence used to support this answer.", base_order + 2, required=False),
        long_q(f"{code}: Assessor finding", "Record assessor judgement, test observations, contradictions, limitations, and rationale.", base_order + 3),
        dropdown_zero_q(f"{code}: Gap severity", "Classify the materiality of any gap found.", base_order + 4, [choice[0] for choice in GAP_SEVERITY_CHOICES]),
        long_q(f"{code}: Remediation action", "Describe the action required to reach the expected outcome, including control owner and dependency notes.", base_order + 5),
        dropdown_zero_q(f"{code}: Remediation priority", "Prioritise the remediation action.", base_order + 6, [choice[0] for choice in REMEDIATION_PRIORITY_CHOICES]),
    ]


def principle_question_set(principle_code, indicators, base_order):
    questions = []
    order = base_order
    for index, indicator in enumerate(indicators, 1):
        code = f"{principle_code}.{index}"
        questions.append(radio_q(
            f"{code}: {indicator}",
            "Assess this CAF outcome indicator and record achievement level.",
            order,
            ACHIEVEMENT_CHOICES,
        ))
        questions.append(long_q(f"{code}: Evidence summary", "Summarise the evidence supporting the achievement rating.", order + 1))
        questions.append(evidence_q(f"{code}: Attach evidence", "Attach supporting evidence for this CAF indicator.", order + 2, required=False))
        questions.append(long_q(f"{code}: Assessor finding", "Record observations, weaknesses, contradictions, and achievement rationale.", order + 3))
        questions.append(dropdown_zero_q(f"{code}: Gap severity", "Classify any gap against this CAF indicator.", order + 4, [choice[0] for choice in GAP_SEVERITY_CHOICES]))
        questions.append(long_q(f"{code}: Improvement action", "Record remediation, owner, dependency, and validation notes.", order + 5))
        questions.append(dropdown_zero_q(f"{code}: Improvement priority", "Prioritise improvement work.", order + 6, [choice[0] for choice in REMEDIATION_PRIORITY_CHOICES]))
        order += 7
    return questions


def _parse_cyber_essentials_questions():
    pdf_path = EXAMPLE_ASSESSMENTS_DIR / "CE2026_DanzellQuestionSet.pdf"
    text = _extract_pdf_text(pdf_path)
    if not text:
        return []
    matches = re.findall(r"\b([A-Z]\d+\.\d+(?:\.\d+)?)\.\s+(.{8,220}?\?)", text.replace("\n", " "))
    seen = set()
    questions = []
    for code, question in matches:
        if code in seen:
            continue
        seen.add(code)
        questions.append((code, " ".join(question.split())))
    return questions[:120]


def _parse_dcc_controls(level):
    pdf_path = EXAMPLE_ASSESSMENTS_DIR / f"DCC Applicant Guide - {level} - V.1.3.pdf"
    text = _extract_pdf_text(pdf_path)
    if not text:
        return []
    compact = " ".join(text.split())
    body_start = compact.find("0001 - Cyber Essentials Terms")
    if body_start > -1:
        compact = compact[body_start:]
    pattern = re.compile(
        r"\b(?P<code>\d{4}\.\d+)\s+-\s+\((?P<ref>MOD\s+[^)]+)\)\s+-\s+\((?P<levels>L[^)]+)\)\s+(?P<title>.*?)(?=\s+(?:Jargon Buster|Available answers|Expected Evidence|Example:|\d{4}(?:\.\d+)?\s+-|OBJECTIVE\s+[A-D]|$))"
    )
    controls = []
    seen = set()
    for match in pattern.finditer(compact):
        code = match.group("code")
        title = _clean_control_title(match.group("title"))
        if not title or title.isdigit():
            continue
        if code in seen:
            continue
        seen.add(code)
        if not title:
            title = "Control assessment"
        controls.append({
            "code": code,
            "ref": f"({match.group('ref')})",
            "levels": f"({match.group('levels')})",
            "title": title,
        })
    return controls


def _fallback_dcc_controls(level):
    base = [
        {"code": "0001.1", "ref": "(MOD 000011)", "levels": "(L0-L3)", "title": "Cyber Essentials certification scope is current and aligned to DCC scope."},
        {"code": "0001.2", "ref": "(MOD 000625)", "levels": "(L0-L3)", "title": "Cyber Essentials certification is maintained for the certification period."},
        {"code": "2314.1", "ref": "(MOD 000447)", "levels": "(L0-L3)", "title": "UK GDPR responsibilities are identified and evidenced."},
        {"code": "2314.2", "ref": "(MOD 000446)", "levels": "(L0-L3)", "title": "Personal data processing is managed in line with UK GDPR."},
        {"code": "2500.1", "ref": "(MOD 000452)", "levels": "(L0-L3)", "title": "Resilience needs for systems have been assessed."},
        {"code": "2500.2", "ref": "(MOD 000453)", "levels": "(L0-L3)", "title": "Systems are resilient to meet assessed resilience needs."},
    ]
    if level == "L0":
        return base
    return base + [
        {"code": "1100.1", "ref": "(MOD 000366)", "levels": "(L1-L3)", "title": "Security governance policies and processes are established."},
        {"code": "1200.1", "ref": "(MOD 000369)", "levels": "(L1-L3)", "title": "Cyber risk management is documented and maintained."},
        {"code": "1300.1", "ref": "(MOD 000031)", "levels": "(L1-L3)", "title": "Assets supporting business functions are inventoried."},
        {"code": "2200.1", "ref": "(MOD 000392)", "levels": "(L1-L3)", "title": "Identity and access controls are implemented."},
        {"code": "2402.1", "ref": "(MOD 000473)", "levels": "(L1-L3)", "title": "Vulnerability management is implemented."},
        {"code": "3100.1", "ref": "(MOD 000562)", "levels": "(L1-L3)", "title": "Security monitoring is implemented."},
        {"code": "4100.1", "ref": "(MOD 000603)", "levels": "(L1-L3)", "title": "Response and recovery planning is implemented."},
    ]


def _clean_control_title(value):
    value = re.sub(r"\s+", " ", value).strip()
    value = re.sub(r"\s+Terms\s+.*$", "", value)
    value = re.sub(r"\s+Control Requirement\s+.*$", "", value)
    value = re.sub(r"\s+Available answers.*$", "", value)
    return value[:360].strip()


def _extract_pdf_text(pdf_path):
    if not pdf_path.exists():
        return ""
    try:
        from pypdf import PdfReader
    except ImportError:
        return ""
    import logging
    logging.getLogger("pypdf").setLevel(logging.ERROR)
    reader = PdfReader(str(pdf_path))
    return "\n".join(page.extract_text() or "" for page in reader.pages)
