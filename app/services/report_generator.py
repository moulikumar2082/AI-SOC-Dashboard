import os
from datetime import datetime, timezone
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from flask import current_app

class SOCReportGenerator:
    """
    Generates professional PDF security reports using ReportLab.
    """

    @classmethod
    def generate_pdf_report(cls, report_type, logs_data=None, incidents_data=None, summary_stats=None, filename=None):
        """
        Creates a PDF file and returns the file path.
        """
        report_dir = os.path.abspath(current_app.config['REPORT_FOLDER'])
        os.makedirs(report_dir, exist_ok=True)
        
        if not filename:
            timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"SOC_{report_type.replace(' ', '_')}_{timestamp_str}.pdf"

        file_path = os.path.join(report_dir, filename)

        doc = SimpleDocTemplate(
            file_path,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        # Custom PDF Styles
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=colors.HexColor('#0b0f19'),
            spaceAfter=6
        )

        subtitle_style = ParagraphStyle(
            'SubTitleStyle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=11,
            leading=14,
            textColor=colors.HexColor('#0088cc'),
            spaceAfter=15
        )

        h2_style = ParagraphStyle(
            'H2Style',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            textColor=colors.HexColor('#1e293b'),
            spaceBefore=12,
            spaceAfter=6
        )

        body_style = ParagraphStyle(
            'BodyStyle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=12,
            textColor=colors.HexColor('#334155')
        )

        table_header_style = ParagraphStyle(
            'TableHeader',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=9,
            textColor=colors.white
        )

        story = []

        # Header Title
        story.append(Paragraph(f"AI-Powered SOC {report_type}", title_style))
        story.append(Paragraph(f"Generated on {datetime.now(timezone.utc).strftime('%B %d, %Y - %H:%M:%S UTC')} | Classification: INTERNAL SECURITY USE ONLY", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#0f172a'), spaceAfter=15))

        # Executive Summary Section
        story.append(Paragraph("Executive Security Overview", h2_style))
        if summary_stats:
            summary_text = f"""
            This report presents automated security telemetry gathered by the AI-Powered Threat Detection Engine.<br/>
            <b>Total Log Telemetry Analyzed:</b> {summary_stats.get('total_logs', 0)}<br/>
            <b>Critical Alerts:</b> {summary_stats.get('critical_count', 0)} | 
            <b>High Alerts:</b> {summary_stats.get('high_count', 0)} | 
            <b>Medium Alerts:</b> {summary_stats.get('medium_count', 0)} | 
            <b>Low Alerts:</b> {summary_stats.get('low_count', 0)}<br/>
            <b>Active Open Incidents:</b> {summary_stats.get('active_incidents', 0)}
            """
            story.append(Paragraph(summary_text, body_style))
        story.append(Spacer(1, 10))

        # Table Section based on Report Type
        if report_type in ['Daily Summary', 'Weekly Summary', 'Attack Statistics'] and logs_data:
            story.append(Paragraph("Top Security Telemetry & Alerts", h2_style))
            
            table_data = [[
                Paragraph("Time (UTC)", table_header_style),
                Paragraph("Source IP", table_header_style),
                Paragraph("Severity", table_header_style),
                Paragraph("Attack Vector", table_header_style),
                Paragraph("Risk Score", table_header_style),
                Paragraph("Event Summary", table_header_style)
            ]]

            import html
            for log in logs_data[:25]:
                severity_str = str(log.severity) if log.severity else 'Low'
                severity_color = '#dc2626' if severity_str == 'Critical' else '#f97316' if severity_str == 'High' else '#eab308' if severity_str == 'Medium' else '#3b82f6'
                sev_p = Paragraph(f"<font color='{severity_color}'><b>{html.escape(severity_str)}</b></font>", body_style)
                
                clean_event = html.escape(str(log.event or ''))
                ts_str = log.timestamp.strftime('%m-%d %H:%M') if (hasattr(log, 'timestamp') and log.timestamp) else 'N/A'
                
                table_data.append([
                    Paragraph(html.escape(ts_str), body_style),
                    Paragraph(html.escape(str(log.source_ip or '')), body_style),
                    sev_p,
                    Paragraph(html.escape(str(log.attack_type or '')), body_style),
                    Paragraph(html.escape(str(log.risk_score if log.risk_score is not None else 0)), body_style),
                    Paragraph(clean_event[:60] + ('...' if len(clean_event) > 60 else ''), body_style)
                ])

            t = Table(table_data, colWidths=[65, 75, 55, 105, 50, 190])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f8fafc'), colors.white]),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(t)

        elif report_type == 'Incident Report' and incidents_data:
            story.append(Paragraph("Active Security Incidents Detail", h2_style))
            
            table_data = [[
                Paragraph("ID", table_header_style),
                Paragraph("Title", table_header_style),
                Paragraph("Priority", table_header_style),
                Paragraph("Status", table_header_style),
                Paragraph("Assigned Analyst", table_header_style),
                Paragraph("Created At", table_header_style)
            ]]

            import html
            for inc in incidents_data[:20]:
                analyst_name = inc.assigned_analyst.username if (hasattr(inc, 'assigned_analyst') and inc.assigned_analyst) else 'Unassigned'
                created_str = inc.created_at.strftime('%Y-%m-%d %H:%M') if (hasattr(inc, 'created_at') and inc.created_at) else 'N/A'
                table_data.append([
                    Paragraph(html.escape(f"INC-{inc.id}"), body_style),
                    Paragraph(html.escape(str(inc.title or '')), body_style),
                    Paragraph(html.escape(str(inc.priority or '')), body_style),
                    Paragraph(html.escape(str(inc.status or '')), body_style),
                    Paragraph(html.escape(str(analyst_name)), body_style),
                    Paragraph(html.escape(created_str), body_style)
                ])

            t = Table(table_data, colWidths=[40, 180, 60, 70, 95, 95])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f8fafc'), colors.white]),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(t)

        story.append(Spacer(1, 20))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cbd5e1'), spaceAfter=10))
        story.append(Paragraph("AI-Powered SOC Operations Platform | Confidential Security Intelligence Report", ParagraphStyle('Footer', parent=body_style, fontSize=8, textColor=colors.HexColor('#64748b'), alignment=1)))

        doc.build(story)
        return filename
