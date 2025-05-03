"""
Helper utilities for PDF report generation with enhanced styling.
This module provides professional-grade PDF report generation capabilities
with consistent branding, dynamic layouts, and modern visual elements.
"""

import os
import io
from datetime import datetime
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend for headless operation
import matplotlib.pyplot as plt

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4, portrait, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                             TableStyle, PageBreak, Image, ListFlowable, 
                             ListItem, KeepTogether, CondPageBreak, Flowable)
from reportlab.platypus.flowables import HRFlowable, TopPadder
from reportlab.pdfgen import canvas
from reportlab.graphics.shapes import Drawing, Line, Rect
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.charts.textlabels import Label

# NET4 Corporate theme colors
NET4_COLORS = {
    'primary': colors.HexColor('#0063B2'),       # Deep blue
    'secondary': colors.HexColor('#004A86'),     # Darker blue
    'accent': colors.HexColor('#FF9500'),        # Bright orange
    'text': colors.HexColor('#333333'),          # Dark gray
    'text_light': colors.HexColor('#666666'),    # Medium gray
    'background': colors.white,                  # White
    'background_alt': colors.HexColor('#F5F7FA'),# Light blue-gray
    'panel': colors.HexColor('#F8F9FA'),         # Panel background
    'grid': colors.HexColor('#DDDDDD'),          # Light gray
    'success': colors.HexColor('#28A745'),       # Green
    'warning': colors.HexColor('#FFC107'),       # Yellow
    'danger': colors.HexColor('#DC3545'),        # Red
    'info': colors.HexColor('#17A2B8'),          # Teal
    'highlight': colors.HexColor('#E94560'),     # Highlight pink
    
    # Chart colors for consistent palette
    'chart_blue': colors.HexColor('#0063B2'),
    'chart_teal': colors.HexColor('#17A2B8'),
    'chart_green': colors.HexColor('#28A745'),
    'chart_orange': colors.HexColor('#FF9500'),
    'chart_red': colors.HexColor('#DC3545'),
    'chart_purple': colors.HexColor('#6F42C1'),
    'chart_pink': colors.HexColor('#E94560'),
    'chart_yellow': colors.HexColor('#FFC107'),
}

# Standard chart color sequence
CHART_COLORS = [
    NET4_COLORS['chart_blue'], 
    NET4_COLORS['chart_orange'],
    NET4_COLORS['chart_green'], 
    NET4_COLORS['chart_red'],
    NET4_COLORS['chart_purple'], 
    NET4_COLORS['chart_teal'],
    NET4_COLORS['chart_yellow'], 
    NET4_COLORS['chart_pink'],
]

def create_net4_styles():
    """
    Create professional NET4-branded paragraph styles for reports
    
    Returns:
        Dictionary of styled ParagraphStyle objects
    """
    # Start with empty styles dictionary (not modifying getSampleStyleSheet)
    styles = {}
    
    # Title styles
    styles['Title'] = ParagraphStyle(
        'Title',
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        alignment=TA_CENTER,
        textColor=NET4_COLORS['primary'],
        spaceAfter=15,
        spaceBefore=10
    )
    
    styles['Subtitle'] = ParagraphStyle(
        'Subtitle',
        fontName='Helvetica',
        fontSize=16,
        leading=20,
        alignment=TA_CENTER,
        textColor=NET4_COLORS['secondary'],
        spaceAfter=20,
        spaceBefore=0
    )
    
    # Heading styles
    styles['Heading1'] = ParagraphStyle(
        'Heading1',
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        spaceAfter=12,
        spaceBefore=16,
        textColor=NET4_COLORS['primary']
    )
    
    styles['Heading2'] = ParagraphStyle(
        'Heading2',
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        spaceAfter=10,
        spaceBefore=12,
        textColor=NET4_COLORS['secondary']
    )
    
    styles['Heading3'] = ParagraphStyle(
        'Heading3',
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        spaceAfter=8,
        spaceBefore=10,
        textColor=NET4_COLORS['secondary']
    )
    
    # Section title with optional accent bar
    styles['SectionTitle'] = ParagraphStyle(
        'SectionTitle',
        fontName='Helvetica-Bold',
        fontSize=16,
        leading=20,
        spaceBefore=15,
        spaceAfter=10,
        textColor=NET4_COLORS['primary'],
        leftIndent=0,
        borderWidth=0
    )
    
    # Text styles
    styles['Normal'] = ParagraphStyle(
        'Normal',
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        spaceAfter=8,
        textColor=NET4_COLORS['text']
    )
    
    styles['Body'] = ParagraphStyle(
        'Body',
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        leftIndent=0.25*inch,
        rightIndent=0.25*inch,
        spaceBefore=6,
        spaceAfter=6,
        textColor=NET4_COLORS['text']
    )
    
    # Caption text for images and tables
    styles['Caption'] = ParagraphStyle(
        'Caption',
        fontName='Helvetica-Oblique',
        fontSize=9,
        leading=12,
        alignment=TA_CENTER,
        textColor=NET4_COLORS['text_light']
    )
    
    # Bullet point style
    styles['Bullet'] = ParagraphStyle(
        'Bullet',
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        leftIndent=20,
        firstLineIndent=0,
        spaceBefore=2,
        spaceAfter=2,
        bulletIndent=10,
        bulletFontName='Symbol',
        bulletFontSize=10,
        textColor=NET4_COLORS['text']
    )
    
    # Code style
    styles['Code'] = ParagraphStyle(
        'Code',
        fontName='Courier',
        fontSize=9,
        leading=12,
        textColor=NET4_COLORS['text'],
        backColor=NET4_COLORS['background_alt'],
        borderPadding=5
    )
    
    # Table header style
    styles['TableHeader'] = ParagraphStyle(
        'TableHeader',
        fontName='Helvetica-Bold',
        fontSize=10,
        alignment=TA_CENTER,
        textColor=colors.white
    )
    
    # Status styles for important alerts or notices
    styles['InfoBox'] = ParagraphStyle(
        'InfoBox',
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=NET4_COLORS['info'],
        backColor=colors.HexColor('#E1F5FE'),  # Very light blue
        borderColor=NET4_COLORS['info'],
        borderWidth=1,
        borderPadding=6,
        borderRadius=5
    )
    
    styles['WarningBox'] = ParagraphStyle(
        'WarningBox',
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=NET4_COLORS['warning'],
        backColor=colors.HexColor('#FFF8E1'),  # Very light yellow
        borderColor=NET4_COLORS['warning'],
        borderWidth=1,
        borderPadding=6,
        borderRadius=5
    )
    
    styles['DangerBox'] = ParagraphStyle(
        'DangerBox',
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=NET4_COLORS['danger'],
        backColor=colors.HexColor('#FFEBEE'),  # Very light red
        borderColor=NET4_COLORS['danger'],
        borderWidth=1,
        borderPadding=6,
        borderRadius=5
    )
    
    # Metric data style
    styles['MetricValue'] = ParagraphStyle(
        'MetricValue',
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        alignment=TA_CENTER,
        textColor=NET4_COLORS['primary']
    )
    
    styles['MetricLabel'] = ParagraphStyle(
        'MetricLabel', 
        fontName='Helvetica',
        fontSize=10,
        leading=12,
        alignment=TA_CENTER,
        textColor=NET4_COLORS['text_light']
    )
    
    return styles

def create_table_style(header=True, zebra=True, border=True):
    """Create a professionally styled table
    
    Args:
        header: Include header styling
        zebra: Include alternating row colors
        border: Include outer border
        
    Returns:
        TableStyle object with professional styling
    """
    style_commands = [
        # Padding and alignment
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]
    
    # Add border styling if requested
    if border:
        style_commands.extend([
            ('BOX', (0, 0), (-1, -1), 1, NET4_COLORS['grid']),
            ('GRID', (0, 0), (-1, -1), 0.5, NET4_COLORS['grid']),
        ])
    
    # Add header styling if requested
    if header:
        style_commands.extend([
            ('BACKGROUND', (0, 0), (-1, 0), NET4_COLORS['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            # Add a thicker line below header
            ('LINEBELOW', (0, 0), (-1, 0), 1.5, NET4_COLORS['primary']),
        ])
    
    # Add zebra striping if requested
    if zebra:
        style_commands.append(
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, NET4_COLORS['background_alt']])
        )
    
    return TableStyle(style_commands)

def add_header_footer(canvas, doc, report_title="Network Forensics Report", logo_path=None):
    """Add professional header and footer to each page
    
    Args:
        canvas: ReportLab canvas object
        doc: ReportLab document object
        report_title: Title to display in the header
        logo_path: Path to logo image file (optional)
    """
    canvas.saveState()
    page_width, page_height = doc.pagesize
    
    # Add header with line
    canvas.setStrokeColor(NET4_COLORS['primary'])
    canvas.setFillColor(NET4_COLORS['primary'])
    canvas.setLineWidth(2)
    canvas.line(0.5*inch, page_height - 0.6*inch, page_width - 0.5*inch, page_height - 0.6*inch)
    
    # Add logo if available, otherwise text branding
    if logo_path and os.path.exists(logo_path):
        # Calculate logo height to maintain aspect ratio with max height of 0.4 inch
        from PIL import Image as PILImage
        with PILImage.open(logo_path) as img:
            width, height = img.size
            aspect = width / height
            logo_height = 0.4 * inch
            logo_width = logo_height * aspect
        
        # Add logo to header
        canvas.drawImage(logo_path, 0.5*inch, page_height - 0.5*inch - logo_height, 
                       width=logo_width, height=logo_height)
    else:
        # Text branding
        canvas.setFont('Helvetica-Bold', 10)
        canvas.drawString(0.5*inch, page_height - 0.5*inch, "NET4")
    
    # Add report title to header
    canvas.setFont('Helvetica', 9)
    canvas.setFillColor(NET4_COLORS['text'])
    canvas.drawRightString(page_width - 0.5*inch, page_height - 0.5*inch, report_title)
    
    # Add footer with line
    canvas.setStrokeColor(NET4_COLORS['primary'])
    canvas.setLineWidth(1)
    canvas.line(0.5*inch, 0.5*inch, page_width - 0.5*inch, 0.5*inch)
    
    # Add page number with more prominent styling
    canvas.setFont('Helvetica-Bold', 9)
    canvas.setFillColor(NET4_COLORS['primary'])
    current_page = canvas.getPageNumber()
    page_str = f"Page {current_page}"
    canvas.drawRightString(page_width - 0.5*inch, 0.25*inch, page_str)
    
    # Add branding to footer
    canvas.setFont('Helvetica-Bold', 10)
    canvas.drawString(0.5*inch, 0.25*inch, "NET4 Forensics")
    
    # Add date to center of footer
    canvas.setFont('Helvetica', 8)
    current_date = datetime.now().strftime("%Y-%m-%d")
    date_width = canvas.stringWidth(current_date, 'Helvetica', 8)
    canvas.setFillColor(NET4_COLORS['text_light'])
    canvas.drawString((page_width - date_width) / 2, 0.25*inch, current_date)
    
    canvas.restoreState()

def create_title_page(story, title="Network Forensics Report", subtitle=None, 
                     logo_path=None, session_info=None):
    """Create a professionally designed title page
    
    Args:
        story: ReportLab story list to append elements to
        title: Report title
        subtitle: Optional subtitle
        logo_path: Path to logo image
        session_info: List of label/value tuples for session information
    """
    styles = create_net4_styles()
    
    # Add logo if available
    if logo_path and os.path.exists(logo_path):
        # Use ReportLab's Image element
        img = Image(logo_path, width=2.5*inch, height=2.5*inch)
        img.hAlign = 'CENTER'  # Center the image
        story.append(img)
        story.append(Spacer(1, 0.5*inch))
    else:
        # If no logo, create space at the top
        story.append(Spacer(1, 1*inch))
    
    # Add a decorative line
    story.append(HRFlowable(width="100%", thickness=3, color=NET4_COLORS['primary'], 
                          spaceBefore=10, spaceAfter=20))
    
    # Add title with custom styling
    title_style = ParagraphStyle(
        'CoverTitle', 
        fontName='Helvetica-Bold',
        fontSize=28,
        leading=36,
        alignment=TA_CENTER,
        textColor=NET4_COLORS['primary'],
        spaceAfter=20
    )
    story.append(Paragraph(title, title_style))
    
    # Add subtitle if provided
    if subtitle:
        subtitle_style = ParagraphStyle(
            'CoverSubtitle',
            fontName='Helvetica',
            fontSize=18,
            leading=22,
            alignment=TA_CENTER,
            textColor=NET4_COLORS['secondary'],
            spaceAfter=30
        )
        story.append(Paragraph(subtitle, subtitle_style))
    
    # Add another decorative line
    story.append(HRFlowable(width="80%", thickness=1, color=NET4_COLORS['primary'], 
                           spaceBefore=10, spaceAfter=30, hAlign='CENTER'))
    
    # Add session info in a styled table if provided
    if session_info and isinstance(session_info, list):
        # Create visually appealing info table with clear structure
        data = []
        for label, value in session_info:
            data.append([label, value])
        
        col_widths = [2*inch, 3.5*inch]
        info_table = Table(data, colWidths=col_widths)
        
        table_style = TableStyle([
            # Styling for labels (left column)
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (0, -1), 11),
            ('TEXTCOLOR', (0, 0), (0, -1), NET4_COLORS['secondary']),
            
            # Styling for values (right column)
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (1, 0), (1, -1), 11),
            ('TEXTCOLOR', (1, 0), (1, -1), NET4_COLORS['text']),
            
            # Background and borders
            ('BACKGROUND', (0, 0), (0, -1), NET4_COLORS['background_alt']),
            ('GRID', (0, 0), (-1, -1), 0.5, NET4_COLORS['grid']),
            
            # Spacing
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            
            # Alignment
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ])
        
        info_table.setStyle(table_style)
        story.append(info_table)
    
    # Add company info or watermark at bottom of page
    story.append(Spacer(1, 1.5*inch))
    
    company_style = ParagraphStyle(
        'Company',
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=15,
        alignment=TA_CENTER,
        textColor=NET4_COLORS['primary']
    )
    story.append(Paragraph("NET4 Network Forensics Platform", company_style))
    
    # Add date
    date_style = ParagraphStyle(
        'Date',
        fontName='Helvetica',
        fontSize=10,
        leading=12,
        alignment=TA_CENTER,
        textColor=NET4_COLORS['text_light']
    )
    
    current_date = datetime.now().strftime("%B %d, %Y")
    story.append(Paragraph(current_date, date_style))
    
    # End title page
    story.append(PageBreak())

def create_section(title, content=None):
    """Create a styled section with title and optional content
    
    Args:
        title: Section title
        content: Optional content list to include in the section
        
    Returns:
        List of ReportLab elements comprising the section
    """
    styles = create_net4_styles()
    elements = []
    
    # Create section header with accent line
    elements.append(HRFlowable(
        width='40%', 
        thickness=2, 
        color=NET4_COLORS['primary'],
        spaceBefore=15, 
        spaceAfter=5, 
        hAlign='LEFT'
    ))
    
    elements.append(Paragraph(title, styles['SectionTitle']))
    
    # Add content if provided
    if content and isinstance(content, list):
        elements.extend(content)
    
    return elements

def create_info_box(content, box_type='info'):
    """Create a styled information, warning, or error box
    
    Args:
        content: The text content (string or Paragraph)
        box_type: 'info', 'warning', 'danger', or 'success'
        
    Returns:
        A styled Table element containing the info box
    """
    styles = create_net4_styles()
    
    # Determine styling based on box type
    if box_type == 'warning':
        icon = "⚠️ "
        bg_color = colors.HexColor('#FFF8E1')  # Light yellow
        border_color = NET4_COLORS['warning']
        style_key = 'WarningBox'
    elif box_type == 'danger':
        icon = "❌ "
        bg_color = colors.HexColor('#FFEBEE')  # Light red
        border_color = NET4_COLORS['danger']
        style_key = 'DangerBox'
    elif box_type == 'success':
        icon = "✅ "
        bg_color = colors.HexColor('#E8F5E9')  # Light green
        border_color = NET4_COLORS['success']
        style_key = 'InfoBox'
    else:  # 'info' is default
        icon = "ℹ️ "
        bg_color = colors.HexColor('#E1F5FE')  # Light blue
        border_color = NET4_COLORS['info']
        style_key = 'InfoBox'
    
    # Create content with icon
    if isinstance(content, str):
        content = icon + content
        content_element = Paragraph(content, styles[style_key])
    else:
        # Assume it's already a Paragraph or other flowable
        content_element = content
    
    # Create box as a table with one cell for consistent borders
    box = Table([[content_element]], colWidths=[5.5*inch])
    
    # Apply styling
    box_style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), bg_color),
        ('BOX', (0, 0), (-1, -1), 1, border_color),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
    ])
    
    box.setStyle(box_style)
    return box

def create_chart_pie(data, title=None, width=4*inch, height=3*inch, labels=True):
    """Create a pie chart for reports
    
    Args:
        data: List of (label, value) tuples
        title: Optional chart title
        width, height: Dimensions
        labels: Whether to show labels
        
    Returns:
        ReportLab Drawing containing the chart
    """
    # Create drawing
    drawing = Drawing(width, height)
    
    # Create chart
    pie = Pie()
    pie.x = width / 2
    pie.y = height / 2 - 25  # Lower to make room for title
    pie.width = min(width - 50, height - 50) * 0.8
    pie.height = min(width - 50, height - 50) * 0.8
    
    # Set data
    labels_list = [item[0] for item in data]
    values = [item[1] for item in data]
    
    pie.data = values
    pie.labels = labels_list if labels else None
    
    # Set colors from chart colors list
    pie.slices.strokeWidth = 0.5
    pie.slices.strokeColor = colors.white
    
    # Apply colors from the palette
    for i in range(len(data)):
        color_index = i % len(CHART_COLORS)
        pie.slices[i].fillColor = CHART_COLORS[color_index]
    
    # Add chart to drawing
    drawing.add(pie)
    
    # Add title if provided
    if title:
        title_label = Label()
        title_label.setOrigin(width/2, height - 10)
        title_label.boxAnchor = 'n'
        title_label.textAnchor = 'middle'
        title_label.setText(title)
        title_label.fontName = 'Helvetica-Bold'
        title_label.fontSize = 12
        title_label.fillColor = NET4_COLORS['text']
        drawing.add(title_label)
    
    return drawing

def create_chart_bar(data, title=None, width=5*inch, height=3*inch, 
                   x_label=None, y_label=None, horizontal=False):
    """Create a bar chart for reports
    
    Args:
        data: List of (label, value) tuples or dictionary mapping labels to values
        title: Optional chart title
        width, height: Dimensions
        x_label, y_label: Axis labels
        horizontal: Whether to create a horizontal bar chart
        
    Returns:
        ReportLab Drawing containing the chart
    """
    # Convert data to format expected by ReportLab
    if isinstance(data, dict):
        # Convert dictionary to list of tuples
        data = [(label, value) for label, value in data.items()]
    
    # Sort data by value for better visualization
    if horizontal:
        # For horizontal, sort ascending
        data.sort(key=lambda x: x[1])
    else:
        # For vertical, sort descending
        data.sort(key=lambda x: x[1], reverse=True)
    
    # Extract labels and values
    labels = [item[0] for item in data]
    values = [item[1] for item in data]
    
    # Create drawing
    drawing = Drawing(width, height)
    
    # Create chart
    chart = VerticalBarChart()
    chart.x = 50  # Make room for y-axis labels
    chart.y = 50  # Make room for x-axis labels
    chart.width = width - 75
    chart.height = height - 100  # Make room for title and labels
    
    # Set data and categories
    chart.data = [values]
    chart.categoryAxis.categoryNames = labels
    
    # Set axis labels if provided
    if x_label:
        chart.categoryAxis.labels.boxAnchor = 's'
        chart.categoryAxis.labels.angle = 0
        chart.categoryAxis.title = x_label
        chart.categoryAxis.titlePos = 'end'
    
    if y_label:
        chart.valueAxis.title = y_label
        chart.valueAxis.titlePos = 'middle'
    
    # Style the bars
    chart.bars[0].fillColor = NET4_COLORS['chart_blue']
    chart.bars[0].strokeColor = None
    
    # Style the chart
    chart.categoryAxis.labels.fontName = 'Helvetica'
    chart.categoryAxis.labels.fontSize = 8
    chart.valueAxis.labels.fontName = 'Helvetica'
    chart.valueAxis.labels.fontSize = 8
    chart.valueAxis.visibleGrid = True
    chart.valueAxis.gridStrokeColor = NET4_COLORS['grid']
    chart.valueAxis.gridStrokeWidth = 0.5
    
    # Add chart to drawing
    drawing.add(chart)
    
    # Add title if provided
    if title:
        title_label = Label()
        title_label.setOrigin(width/2, height - 10)
        title_label.boxAnchor = 'n'
        title_label.textAnchor = 'middle'
        title_label.setText(title)
        title_label.fontName = 'Helvetica-Bold'
        title_label.fontSize = 12
        title_label.fillColor = NET4_COLORS['text']
        drawing.add(title_label)
    
    return drawing

def create_metric_box(label, value, trend=None, width=2*inch, height=1.5*inch):
    """Create a metric box for dashboards in reports
    
    Args:
        label: Metric label
        value: Metric value
        trend: Optional trend indicator (percentage, with sign)
        width, height: Dimensions of the box
        
    Returns:
        A ReportLab Table containing the metric display
    """
    styles = create_net4_styles()
    
    # Create components
    label_p = Paragraph(label, styles['MetricLabel'])
    value_p = Paragraph(str(value), styles['MetricValue'])
    
    # Create trend component if provided
    if trend is not None:
        # Format trend and determine color
        try:
            trend_value = float(trend)
            if trend_value > 0:
                trend_text = f"+{trend_value:.1f}%"
                trend_color = NET4_COLORS['success']
            elif trend_value < 0:
                trend_text = f"{trend_value:.1f}%"
                trend_color = NET4_COLORS['danger']
            else:
                trend_text = "0.0%"
                trend_color = NET4_COLORS['text_light']
        except (ValueError, TypeError):
            # If trend can't be converted to float, use as is
            trend_text = str(trend)
            trend_color = NET4_COLORS['text_light']
        
        # Create trend paragraph with appropriate styling
        trend_style = ParagraphStyle(
            'TrendStyle',
            parent=styles['MetricLabel'],
            textColor=trend_color,
            fontSize=9
        )
        trend_p = Paragraph(trend_text, trend_style)
        
        # Arrange in table with label, value, and trend
        data = [[label_p], [value_p], [trend_p]]
    else:
        # Arrange in table with just label and value
        data = [[label_p], [value_p]]
    
    # Create table with fixed dimensions
    table = Table(data, colWidths=[width], rowHeights=None)
    
    # Style the table
    table_style = TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BACKGROUND', (0, 0), (-1, -1), NET4_COLORS['background_alt']),
        ('BOX', (0, 0), (-1, -1), 1, NET4_COLORS['grid']),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ])
    
    table.setStyle(table_style)
    return table

def create_metric_grid(metrics, columns=3):
    """Create a grid of metric boxes
    
    Args:
        metrics: List of (label, value, trend) tuples
        columns: Number of columns in the grid
        
    Returns:
        A ReportLab Table containing the metric grid
    """
    # Calculate number of rows needed
    rows = (len(metrics) + columns - 1) // columns
    
    # Create table data structure
    data = [[None for _ in range(columns)] for _ in range(rows)]
    
    # Populate with metric boxes
    for i, metric in enumerate(metrics):
        row = i // columns
        col = i % columns
        
        # Create metric box based on whether trend is provided
        if len(metric) == 3:
            label, value, trend = metric
            box = create_metric_box(label, value, trend)
        else:
            label, value = metric
            box = create_metric_box(label, value)
        
        data[row][col] = box
    
    # Fill empty cells
    for row in range(rows):
        for col in range(columns):
            if data[row][col] is None:
                data[row][col] = ''
    
    # Calculate column widths (equal distribution)
    available_width = 6.5 * inch  # Standard page width minus margins
    col_width = available_width / columns
    
    # Create table
    table = Table(data, colWidths=[col_width] * columns)
    
    # Style the table - just space between cells, no borders
    table_style = TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ])
    
    table.setStyle(table_style)
    return table

# Utility function to get matplotlib charts as ReportLab Images
def matplotlib_to_image(plt_figure, width=6*inch, height=4*inch, dpi=100):
    """Convert a matplotlib figure to a ReportLab Image
    
    Args:
        plt_figure: matplotlib Figure object
        width, height: Dimensions for the resulting image
        dpi: Resolution for the image
        
    Returns:
        ReportLab Image containing the matplotlib chart
    """
    buf = io.BytesIO()
    plt_figure.savefig(buf, format='png', dpi=dpi, bbox_inches='tight')
    buf.seek(0)
    
    return Image(buf, width=width, height=height)

# Custom flowable for horizontal separator with label
class LabeledHRule(Flowable):
    """A horizontal rule with an optional centered label"""
    
    def __init__(self, width, label=None, thickness=1, color=None, 
               font_name='Helvetica-Bold', font_size=10, font_color=None,
               space_before=5, space_after=5):
        Flowable.__init__(self)
        self.width = width
        self.label = label
        self.thickness = thickness
        self.color = color or colors.black
        self.font_name = font_name
        self.font_size = font_size
        self.font_color = font_color or self.color
        self.space_before = space_before
        self.space_after = space_after
        
    def wrap(self, *args):
        # Height is font size (if there's a label) plus some padding
        height = 0
        if self.label:
            height = self.font_size + 4
        return self.width, height + self.space_before + self.space_after
        
    def draw(self):
        # Draw horizontal rule
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(self.thickness)
        
        y_pos = self.space_before
        
        if self.label:
            # If there's a label, draw it centered
            self.canv.setFont(self.font_name, self.font_size)
            self.canv.setFillColor(self.font_color)
            
            # Measure text width
            text_width = self.canv.stringWidth(self.label, self.font_name, self.font_size)
            
            # Calculate positions
            space_width = 10  # Space between line and text
            line1_width = (self.width - text_width - 2 * space_width) / 2
            
            # Draw lines on either side of text
            self.canv.line(0, y_pos, line1_width, y_pos)
            self.canv.line(line1_width + space_width + text_width + space_width, 
                         y_pos, self.width, y_pos)
            
            # Draw text
            self.canv.drawString(line1_width + space_width, 
                               y_pos - self.font_size/3, self.label)
        else:
            # Just draw a simple line
            self.canv.line(0, y_pos, self.width, y_pos)