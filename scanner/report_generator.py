from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

def generate_report(target_url, findings, file_path):
    doc = SimpleDocTemplate(file_path)
    styles = getSampleStyleSheet()
    story = []

    title = Paragraph(f"Security Scan Report: {target_url}", styles['h1'])
    story.append(title)
    story.append(Spacer(1,0.2*inch))

    for key, details in findings.items():
        finding_title = Paragraph(f"<b>{key.replace('_', ' ').title()} ({details['status']})</b>", styles['h3'])
        finding_details = Paragraph(details['message'],styles['BodyText'])
        story.append(finding_title)
        story.append(finding_details)
        story.append(Spacer(1, 0.1*inch))

    doc.build(story)