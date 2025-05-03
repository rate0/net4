"""
Professional report styling themes for Net4 reports.
This module provides sophisticated color schemes, layouts, and visual elements.
"""

import os
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle, PageBreak, Image

# Professional color schemes
class ReportTheme:
    """Base theme class with professional color schemes"""
    
    # Theme variants
    THEMES = {
        'corporate': {
            'primary': colors.HexColor('#0063B2'),       # Deep blue
            'secondary': colors.HexColor('#004A86'),     # Darker blue
            'accent': colors.HexColor('#FF9500'),        # Bright orange
            'text': colors.HexColor('#333333'),          # Dark gray
            'text_light': colors.HexColor('#666666'),    # Medium gray
            'background': colors.HexColor('#FFFFFF'),    # White
            'background_alt': colors.HexColor('#F5F7FA'),# Light blue-gray
            'grid': colors.HexColor('#DDDDDD'),          # Light gray
            'success': colors.HexColor('#28A745'),       # Green
            'warning': colors.HexColor('#FFC107'),       # Yellow
            'danger': colors.HexColor('#DC3545'),        # Red
            'info': colors.HexColor('#17A2B8')           # Teal
        },
        'modern': {
            'primary': colors.HexColor('#6200EA'),       # Deep purple
            'secondary': colors.HexColor('#3700B3'),     # Darker purple
            'accent': colors.HexColor('#03DAC6'),        # Teal
            'text': colors.HexColor('#333333'),          # Dark gray
            'text_light': colors.HexColor('#666666'),    # Medium gray
            'background': colors.HexColor('#FFFFFF'),    # White
            'background_alt': colors.HexColor('#F8F9FA'),# Light gray
            'grid': colors.HexColor('#EEEEEE'),          # Lighter gray
            'success': colors.HexColor('#00C853'),       # Green
            'warning': colors.HexColor('#FFD600'),       # Yellow
            'danger': colors.HexColor('#FF1744'),        # Red
            'info': colors.HexColor('#00B0FF')           # Light blue
        },
        'cyber': {
            'primary': colors.HexColor('#1A1A2E'),       # Dark blue-black
            'secondary': colors.HexColor('#16213E'),     # Dark blue
            'accent': colors.HexColor('#0F3460'),        # Medium blue
            'text': colors.HexColor('#E1E1E1'),          # Light gray (for dark theme)
            'text_light': colors.HexColor('#BBBBBB'),    # Medium gray
            'background': colors.HexColor('#121212'),    # Very dark gray
            'background_alt': colors.HexColor('#1E1E1E'),# Dark gray
            'grid': colors.HexColor('#333333'),          # Medium gray
            'success': colors.HexColor('#4CAF50'),       # Green
            'warning': colors.HexColor('#FB8C00'),       # Orange
            'danger': colors.HexColor('#E53935'),        # Red
            'info': colors.HexColor('#2196F3'),          # Blue
            'highlight': colors.HexColor('#E94560')      # Pink highlight
        }
    }
    
    def __init__(self, theme_name='corporate'):
        """Initialize with selected theme colors"""
        self.name = theme_name
        if theme_name not in self.THEMES:
            theme_name = 'corporate'  # Default to corporate theme
        
        # Set theme colors
        theme = self.THEMES[theme_name]
        for key, value in theme.items():
            setattr(self, key, value)
    
    def create_styles(self):
        """Create professional paragraph styles based on theme colors"""
        styles = getSampleStyleSheet()
        
        # Title style
        title_style = ParagraphStyle(
            'Title',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=24,
            leading=30,
            alignment=1,  # Center alignment
            textColor=self.primary,
            spaceAfter=15
        )
        
        # Heading styles
        heading1_style = ParagraphStyle(
            'Heading1',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=18,
            leading=22,
            spaceAfter=14,
            spaceBefore=14,
            textColor=self.primary
        )
        
        heading2_style = ParagraphStyle(
            'Heading2',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            spaceAfter=10,
            spaceBefore=12,
            textColor=self.secondary
        )
        
        heading3_style = ParagraphStyle(
            'Heading3',
            parent=styles['Heading3'],
            fontName='Helvetica-Bold',
            fontSize=12,
            leading=16,
            spaceAfter=8,
            spaceBefore=10,
            textColor=self.secondary
        )
        
        # Section title with optional accent bar
        section_title_style = ParagraphStyle(
            'SectionTitle',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=16,
            leading=20,
            spaceBefore=15,
            spaceAfter=10,
            textColor=self.primary,
            leftIndent=0,
            borderWidth=0
        )
        
        # Normal text style
        normal_style = ParagraphStyle(
            'Normal',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            leading=14,
            spaceAfter=8,
            textColor=self.text
        )
        
        # Body text with indentation
        body_style = ParagraphStyle(
            'Body',
            parent=normal_style,
            leftIndent=0.25*inch,
            rightIndent=0.25*inch,
            spaceBefore=6,
            spaceAfter=6
        )
        
        # Caption text for images and tables
        caption_style = ParagraphStyle(
            'Caption',
            parent=normal_style,
            fontName='Helvetica-Oblique',
            fontSize=9,
            textColor=self.text_light,
            alignment=1  # Center alignment
        )
        
        # Bullet point style
        bullet_style = ParagraphStyle(
            'Bullet',
            parent=normal_style,
            leftIndent=20,
            firstLineIndent=0,
            spaceBefore=2,
            spaceAfter=2,
            bulletIndent=10,
            bulletFontName='Symbol',
            bulletFontSize=10
        )
        
        # Code style
        code_style = ParagraphStyle(
            'Code',
            fontName='Courier',
            fontSize=9,
            leading=12,
            textColor=self.text,
            backColor=self.background_alt,
            borderPadding=5
        )
        
        # Table header style
        table_header_style = ParagraphStyle(
            'TableHeader',
            parent=normal_style,
            fontName='Helvetica-Bold',
            fontSize=10,
            textColor=colors.white,
            alignment=1  # Center
        )
        
        # Status styles for important alerts or notices
        status_info_style = ParagraphStyle(
            'StatusInfo',
            parent=normal_style,
            textColor=self.info,
            backColor=colors.HexColor('#E1F5FE'),  # Very light blue
            borderColor=self.info,
            borderWidth=1,
            borderPadding=6,
            borderRadius=5
        )
        
        status_warning_style = ParagraphStyle(
            'StatusWarning',
            parent=normal_style,
            textColor=self.warning,
            backColor=colors.HexColor('#FFF8E1'),  # Very light yellow
            borderColor=self.warning,
            borderWidth=1,
            borderPadding=6,
            borderRadius=5
        )
        
        status_danger_style = ParagraphStyle(
            'StatusDanger',
            parent=normal_style,
            textColor=self.danger,
            backColor=colors.HexColor('#FFEBEE'),  # Very light red
            borderColor=self.danger,
            borderWidth=1,
            borderPadding=6,
            borderRadius=5
        )
        
        # Add all styles to the stylesheet
        custom_styles = {
            'Title': title_style,
            'Heading1': heading1_style,
            'Heading2': heading2_style,
            'Heading3': heading3_style,
            'SectionTitle': section_title_style,
            'Normal': normal_style,
            'Body': body_style,
            'Caption': caption_style,
            'Bullet': bullet_style,
            'Code': code_style,
            'TableHeader': table_header_style,
            'StatusInfo': status_info_style,
            'StatusWarning': status_warning_style,
            'StatusDanger': status_danger_style
        }
        
        # Create new stylesheet with our custom styles
        for name, style in custom_styles.items():
            if name in styles:
                styles[name] = style
            else:
                styles.add(style)
        
        return styles
    
    def create_table_style(self, header=True, zebra=True):
        """Create a professional table style with theme colors"""
        style_commands = [
            # Padding and alignment
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            
            # Border styling
            ('BOX', (0, 0), (-1, -1), 1, self.grid),
            ('GRID', (0, 0), (-1, -1), 0.5, self.grid),
            
            # Data row styling
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('TEXTCOLOR', (0, 1), (-1, -1), self.text),
        ]
        
        # Add header styling if requested
        if header:
            style_commands.extend([
                ('BACKGROUND', (0, 0), (-1, 0), self.primary),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ])
        
        # Add zebra striping if requested
        if zebra:
            style_commands.append(
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.background_alt])
            )
        
        return TableStyle(style_commands)
    
    def create_info_box_style(self, box_type='info'):
        """Create a styled info box using theme colors"""
        if box_type == 'warning':
            bg_color = colors.HexColor('#FFF8E1')  # Light yellow
            border_color = self.warning
        elif box_type == 'danger':
            bg_color = colors.HexColor('#FFEBEE')  # Light red
            border_color = self.danger
        elif box_type == 'success':
            bg_color = colors.HexColor('#E8F5E9')  # Light green
            border_color = self.success
        else:  # info is default
            bg_color = colors.HexColor('#E1F5FE')  # Light blue
            border_color = self.info
            
        style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), bg_color),
            ('BOX', (0, 0), (-1, -1), 1, border_color),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ])
        
        return style

# Helper functions for common report elements
def create_header_footer(canvas, doc, theme=ReportTheme(), report_title="Network Forensics Report"):
    """Add professional header and footer to pages"""
    canvas.saveState()
    page_width, page_height = doc.pagesize
    
    # Add header with branding
    canvas.setStrokeColor(theme.primary)
    canvas.setFillColor(theme.primary)
    canvas.setLineWidth(2)
    canvas.line(0.5*inch, page_height - 0.6*inch, page_width - 0.5*inch, page_height - 0.6*inch)
    
    # Add logo or branding text to header
    canvas.setFont('Helvetica-Bold', 10)
    canvas.drawString(0.5*inch, page_height - 0.5*inch, "NET4")
    
    # Add report title to header
    canvas.setFont('Helvetica', 9)
    canvas.setFillColor(theme.text)
    canvas.drawRightString(page_width - 0.5*inch, page_height - 0.5*inch, report_title)
    
    # Add footer with page number and branding
    canvas.setStrokeColor(theme.primary)
    canvas.setLineWidth(1)
    canvas.line(0.5*inch, 0.5*inch, page_width - 0.5*inch, 0.5*inch)
    
    # Add page number
    canvas.setFont('Helvetica', 9)
    canvas.setFillColor(theme.primary)
    current_page = canvas.getPageNumber()
    page_str = f"Page {current_page}"
    canvas.drawRightString(page_width - 0.5*inch, 0.25*inch, page_str)
    
    # Add branding to footer
    canvas.setFont('Helvetica-Bold', 10)
    canvas.drawString(0.5*inch, 0.25*inch, "NET4 Forensics")
    
    # Add date to center of footer
    canvas.setFont('Helvetica', 8)
    from datetime import datetime
    current_date = datetime.now().strftime("%Y-%m-%d")
    date_width = canvas.stringWidth(current_date, 'Helvetica', 8)
    canvas.setFillColor(theme.text_light)
    canvas.drawString((page_width - date_width) / 2, 0.25*inch, current_date)
    
    canvas.restoreState()

def create_title_page(story, theme=ReportTheme(), title="Network Forensics Analysis Report", 
                    subtitle=None, logo_path=None, session_info=None):
    """Create an attractive title page with logo and session info"""
    # Add logo if available
    if logo_path and os.path.exists(logo_path):
        logo = Image(logo_path, width=2*inch, height=2*inch)
        story.append(logo)
        story.append(Spacer(1, 0.5*inch))
    
    # Add a decorative line
    from reportlab.platypus.flowables import HRFlowable
    story.append(HRFlowable(width="100%", thickness=3, color=theme.primary, 
                          spaceBefore=10, spaceAfter=20))
    
    # Add title with custom styling
    title_style = ParagraphStyle(
        'CoverTitle', 
        fontName='Helvetica-Bold',
        fontSize=28,
        leading=36,
        alignment=1,
        textColor=theme.primary,
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
            alignment=1,
            textColor=theme.secondary,
            spaceAfter=30
        )
        story.append(Paragraph(subtitle, subtitle_style))
    
    # Add another decorative line
    story.append(HRFlowable(width="80%", thickness=1, color=theme.primary, 
                           spaceBefore=10, spaceAfter=30, hAlign='CENTER'))
    
    # Add session info in a styled table if provided
    if session_info and isinstance(session_info, list):
        # Create visually appealing info table
        data = []
        for label, value in session_info:
            data.append([label, value])
        
        col_widths = [2*inch, 3.5*inch]
        info_table = Table(data, colWidths=col_widths)
        
        table_style = TableStyle([
            # Styling for labels (left column)
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (0, -1), 11),
            ('TEXTCOLOR', (0, 0), (0, -1), theme.secondary),
            
            # Styling for values (right column)
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (1, 0), (1, -1), 11),
            ('TEXTCOLOR', (1, 0), (1, -1), theme.text),
            
            # Background and borders
            ('BACKGROUND', (0, 0), (0, -1), theme.background_alt),
            ('GRID', (0, 0), (-1, -1), 0.5, theme.grid),
            
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
    from reportlab.platypus.flowables import Spacer
    story.append(Spacer(1, 1.5*inch))
    
    company_style = ParagraphStyle(
        'Company',
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=15,
        alignment=1,
        textColor=theme.primary
    )
    story.append(Paragraph("NET4 Forensics Platform", company_style))
    
    # Add date
    date_style = ParagraphStyle(
        'Date',
        fontName='Helvetica',
        fontSize=10,
        leading=12,
        alignment=1,
        textColor=theme.text_light
    )
    from datetime import datetime
    current_date = datetime.now().strftime("%B %d, %Y")
    story.append(Paragraph(current_date, date_style))
    
    # End title page
    story.append(PageBreak())

def create_section_header(title, theme=ReportTheme()):
    """Create a styled section header with accent color"""
    # Create styled paragraph for section title
    section_style = ParagraphStyle(
        'SectionHeader',
        fontName='Helvetica-Bold',
        fontSize=16,
        leading=20,
        textColor=theme.primary,
        spaceBefore=15,
        spaceAfter=5
    )
    
    header = Paragraph(title, section_style)
    
    # Create accent line
    from reportlab.platypus.flowables import HRFlowable
    accent_line = HRFlowable(
        width="40%", 
        thickness=2, 
        color=theme.primary,
        spaceBefore=0, 
        spaceAfter=10, 
        hAlign='LEFT'
    )
    
    return [header, accent_line]

def create_info_box(content, box_type='info', theme=ReportTheme()):
    """Create a styled info/warning/error box"""
    # Determine icon and styling based on box type
    if box_type == 'warning':
        icon = "⚠️ "
        box_style = theme.create_info_box_style('warning')
    elif box_type == 'danger':
        icon = "❌ "
        box_style = theme.create_info_box_style('danger')
    elif box_type == 'success':
        icon = "✅ "
        box_style = theme.create_info_box_style('success')
    else:  # info is default
        icon = "ℹ️ "
        box_style = theme.create_info_box_style('info')
    
    # Create content with icon
    if isinstance(content, str):
        content = icon + content
        
    # Create box as a table with one cell
    box = Table([[Paragraph(content, theme.create_styles()['Normal'])]], 
               colWidths=[5.5*inch])
    box.setStyle(box_style)
    
    return box

def create_data_table(data, colWidths=None, theme=ReportTheme(), header=True):
    """Create a professional styled data table"""
    # Validate data
    if not data or not isinstance(data, list):
        return None
    
    # Determine column widths if not provided
    if not colWidths:
        # Calculate roughly equal widths
        available_width = 6 * inch  # Assuming standard page width with margins
        colWidths = [available_width / len(data[0])] * len(data[0])
    
    # Create table
    table = Table(data, colWidths=colWidths)
    
    # Apply styling
    table.setStyle(theme.create_table_style(header=header, zebra=True))
    
    return table