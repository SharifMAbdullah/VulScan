from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import os

def get_cvss_color(score):
    """
    Returns a color based on the CVSS score range.
    """
    if score <= 3.9:
        return colors.green
    elif score <= 6.9:
        return colors.yellow
    elif score <= 8.9:
        return colors.orange
    else:
        return colors.red

def generate_vulnerability_report(results, output_pdf="vulnerability_report.pdf"):
    """
    Generates a detailed PDF report with function vulnerabilities.
    """
    doc = SimpleDocTemplate(output_pdf, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    # Extract project name from first file
    project_name = os.path.basename(results[0]["file"]) if results else "Unknown Project"

    # Title
    title = Paragraph("<b>VULNERABILITY REPORT</b>", styles["Title"])
    elements.append(title)
    elements.append(Spacer(1, 12))

    # Project details
    project_table = Table([
        ["PROJECT NAME:", project_name],
        ["REPORT DATE:", "30 Jan, 2024"]
    ], colWidths=[150, 350])

    project_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.black),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("GRID", (0, 0), (-1, -1), 1, colors.black)
    ]))

    elements.append(project_table)
    elements.append(Spacer(1, 20))

    for result in results:
        file_name = result["file"]

        # File Header
        file_header = Table([
            [Paragraph(f'<b>FILE NAME : {file_name.upper()}</b>', styles["Normal"])]
        ], colWidths=[500])

        file_header.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.black),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("PADDING", (0, 0), (-1, -1), 6)
        ]))

        elements.append(file_header)
        elements.append(Spacer(1, 10))

        for function_data in result.get("functions", []):
            function_name = function_data["function"]
            cvss_score = function_data["cvss_score"].get("base_score", 0)
            cvss_color = get_cvss_color(cvss_score)

            # Function Header
            function_header = Table([
                [Paragraph(f'<b>{function_name.upper()}</b>', styles["Normal"]), 
                 Paragraph(f'<b>BASE_SCORE: {cvss_score}</b>', styles["Normal"])]
            ], colWidths=[350, 150])

            function_header.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.black),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("BACKGROUND", (1, 0), (1, -1), cvss_color),
                ("TEXTCOLOR", (1, 0), (1, -1), colors.white),
                ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ]))

            elements.append(function_header)
            elements.append(Spacer(1, 5))

            # Metrics Table
            metrics = function_data["cvss_score"].get("metrics", {})
            metrics_table_data = [["Metric", "Value"]] + [[k, v] for k, v in metrics.items()]

            metrics_table = Table(metrics_table_data, colWidths=[200, 300])
            metrics_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.black),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ("PADDING", (0, 0), (-1, -1), 5)
            ]))

            elements.append(metrics_table)
            elements.append(Spacer(1, 10))

            # Fixes Section
            fixes = function_data.get("fixes", [])
            if fixes:
                fixes_paragraph = Paragraph("<b>FIXES</b>", styles["Heading2"])
                elements.append(fixes_paragraph)

                for fix in fixes:
                    elements.append(Paragraph(fix, styles["Normal"]))
                elements.append(Spacer(1, 10))

            # Summary Section
            summary = function_data.get("summary", "No summary available")
            summary_paragraph = Paragraph(f"<b>SUMMARY</b><br/>{summary}", styles["Normal"])
            elements.append(summary_paragraph)
            elements.append(Spacer(1, 20))

    # Build PDF
    doc.build(elements)
    print(f"PDF generated: {output_pdf}")