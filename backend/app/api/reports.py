import io
import csv
from datetime import datetime, timezone
from xml.sax.saxutils import escape as xml_escape
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from backend.app.database.session import get_db
from backend.app.models.models import Scan, Incident, ThreatIndicator, AgentExecution, QuarantinedFile

router = APIRouter(prefix="/reports", tags=["Reports"])


def _pdf_text(value) -> str:
    """Escape untrusted text before handing it to ReportLab Paragraph."""
    if value is None:
        return ""
    return xml_escape(str(value))


def _csv_cell(value) -> str:
    """Neutralize spreadsheet formula injection in exported cells."""
    if value is None:
        return ""
    text = str(value)
    if text and text[0] in ("=", "+", "-", "@"):
        return "'" + text
    return text

@router.get("")
def get_reports_summary(db: Session = Depends(get_db)):
    """
    Returns executive summary metrics for SOC reporting.
    """
    total_scans = db.query(Scan).count()
    critical_count = db.query(Scan).filter(Scan.risk_score >= 70).count()
    high_count = db.query(Scan).filter(Scan.risk_score >= 40, Scan.risk_score < 70).count()
    moderate_count = db.query(Scan).filter(Scan.risk_score >= 20, Scan.risk_score < 40).count()
    safe_count = db.query(Scan).filter(Scan.risk_score < 20).count()
    
    total_incidents = db.query(Incident).count()
    open_incidents = db.query(Incident).filter(Incident.status == "OPEN").count()
    resolved_incidents = db.query(Incident).filter(Incident.status == "RESOLVED").count()
    quarantined_files = db.query(QuarantinedFile).count()

    recent_critical_scans = db.query(Scan).filter(Scan.risk_score >= 40).order_by(desc(Scan.created_at)).limit(10).all()

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_scans": total_scans,
            "critical_scans": critical_count,
            "high_risk_scans": high_count,
            "moderate_risk_scans": moderate_count,
            "safe_scans": safe_count,
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
            "resolved_incidents": resolved_incidents,
            "quarantined_files": quarantined_files
        },
        "critical_findings": [
            {
                "id": s.id,
                "type": s.scan_type,
                "target": s.input_reference,
                "score": s.risk_score,
                "level": s.risk_level,
                "created_at": s.created_at
            }
            for s in recent_critical_scans
        ]
    }

@router.get("/export/csv")
def export_incidents_csv(db: Session = Depends(get_db)):
    """
    Exports incident records as downloadable CSV.
    """
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow([
        "Incident ID", "Scan ID", "Title", "Type", "Severity", 
        "Status", "Assigned Action", "Potential Impact", "Created At"
    ])
    
    incidents = db.query(Incident).order_by(desc(Incident.created_at)).all()
    for inc in incidents:
        writer.writerow([
            _csv_cell(inc.id),
            _csv_cell(inc.scan_id or ""),
            _csv_cell(inc.title),
            _csv_cell(inc.incident_type),
            _csv_cell(inc.severity),
            _csv_cell(inc.status),
            _csv_cell(inc.assigned_action or ""),
            _csv_cell(inc.potential_impact),
            _csv_cell(inc.created_at.isoformat() if inc.created_at else "")
        ])
        
    output.seek(0)
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=security_incidents_{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"}
    )

@router.get("/{scan_id}/pdf")
def generate_pdf_report(scan_id: str, db: Session = Depends(get_db)):
    """
    Generates a formal, high-resolution PDF Incident Investigation Report using ReportLab.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")
        
    indicators = db.query(ThreatIndicator).filter(ThreatIndicator.scan_id == scan_id).all()
    executions = db.query(AgentExecution).filter(AgentExecution.scan_id == scan_id).order_by(AgentExecution.created_at).all()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontSize=20, leading=24, textColor=colors.HexColor('#0f172a'))
    subtitle_style = ParagraphStyle('DocSubtitle', parent=styles['Normal'], fontSize=10, leading=14, textColor=colors.HexColor('#64748b'))
    section_style = ParagraphStyle('SectionHeading', parent=styles['Heading2'], fontSize=13, leading=16, textColor=colors.HexColor('#1e293b'), spaceBefore=10, spaceAfter=6)
    body_style = ParagraphStyle('BodyTextCustom', parent=styles['Normal'], fontSize=9, leading=12, textColor=colors.HexColor('#334155'))
    bold_style = ParagraphStyle('BoldCustom', parent=styles['Normal'], fontSize=9, leading=12, fontName='Helvetica-Bold', textColor=colors.HexColor('#0f172a'))

    elements = []

    # Header
    elements.append(Paragraph("AI-POWERED FRAUD DETECTION & RESPONSE PLATFORM", ParagraphStyle('TopHeader', fontSize=8, fontName='Helvetica-Bold', textColor=colors.HexColor('#0284c7'))))
    elements.append(Paragraph(f"Forensic Security Report - Scan #{scan.id[:8]}", title_style))
    elements.append(Paragraph(f"Generated on {datetime.now(timezone.utc).strftime('%B %d, %Y at %H:%M:%S UTC')} | Classification: SOC CONFIDENTIAL", subtitle_style))
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=14))

    # Executive Summary Card Table
    score_color = colors.HexColor('#dc2626') if scan.risk_score >= 70 else colors.HexColor('#ea580c') if scan.risk_score >= 40 else colors.HexColor('#16a34a')
    summary_data = [
        [Paragraph("Target Reference:", bold_style), Paragraph(_pdf_text(str(scan.input_reference)[:50]), body_style), Paragraph("Scan Protocol:", bold_style), Paragraph(_pdf_text(scan.scan_type), body_style)],
        [Paragraph("Calculated Risk Score:", bold_style), Paragraph(f"<b>{scan.risk_score} / 100</b>", ParagraphStyle('Score', textColor=score_color, fontSize=11, fontName='Helvetica-Bold')), Paragraph("Threat Classification:", bold_style), Paragraph(_pdf_text(scan.risk_level), ParagraphStyle('Level', textColor=score_color, fontSize=10, fontName='Helvetica-Bold'))],
        [Paragraph("Model Confidence:", bold_style), Paragraph(f"{scan.confidence * 100:.1f}%", body_style), Paragraph("Fraud Probability:", bold_style), Paragraph(f"{scan.fraud_probability * 100:.1f}%" if scan.fraud_probability is not None else "N/A (rules only)", body_style)]
    ]
    summary_table = Table(summary_data, colWidths=[130, 140, 120, 140])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#e2e8f0')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 12))

    # Summary Narrative
    elements.append(Paragraph("Executive Threat Synthesis", section_style))
    elements.append(Paragraph(_pdf_text(scan.summary or "Evaluation completed without anomalies."), body_style))
    elements.append(Spacer(1, 12))

    # Threat Indicators Table
    elements.append(Paragraph(f"Detected Security Indicators ({len(indicators)})", section_style))
    if indicators:
        ind_data = [[Paragraph("Severity", bold_style), Paragraph("Indicator Title", bold_style), Paragraph("Description & Evidence", bold_style)]]
        for ind in indicators:
            sev_color = colors.HexColor('#dc2626') if ind.severity == "CRITICAL" else colors.HexColor('#f97316') if ind.severity == "HIGH" else colors.HexColor('#eab308')
            ind_data.append([
                Paragraph(_pdf_text(ind.severity), ParagraphStyle('Sev', textColor=sev_color, fontSize=8, fontName='Helvetica-Bold')),
                Paragraph(_pdf_text(ind.title), bold_style),
                Paragraph(f"{_pdf_text(ind.description)}<br/><i>Evidence: {_pdf_text(ind.evidence or 'N/A')}</i>", body_style)
            ])
        ind_table = Table(ind_data, colWidths=[65, 175, 290])
        ind_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ]))
        elements.append(ind_table)
    else:
        elements.append(Paragraph("No threat indicators or heuristic anomalies observed.", body_style))
    elements.append(Spacer(1, 14))

    # Agent Audit Trail Table
    elements.append(Paragraph("Multi-Agent Execution Timeline", section_style))
    agent_data = [[Paragraph("Agent Name", bold_style), Paragraph("Status", bold_style), Paragraph("Latency", bold_style), Paragraph("Action / Output Summary", bold_style)]]
    for ex in executions:
        agent_data.append([
            Paragraph(_pdf_text(ex.agent_name), bold_style),
            Paragraph(_pdf_text(ex.status), ParagraphStyle('Stat', textColor=colors.HexColor('#16a34a') if ex.status=="SUCCESS" else colors.HexColor('#dc2626'), fontSize=8)),
            Paragraph(f"{ex.execution_time * 1000:.1f} ms", body_style),
            Paragraph(_pdf_text(ex.output_summary or "Completed"), body_style)
        ])
    if len(agent_data) > 1:
        agent_table = Table(agent_data, colWidths=[110, 60, 65, 295])
        agent_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(agent_table)

    doc.build(elements)
    buffer.seek(0)
    
    return Response(
        content=buffer.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=Forensic_Report_{scan.id[:8]}.pdf"}
    )
