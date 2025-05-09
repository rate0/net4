import os
import io
import time
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable, TextIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                             TableStyle, PageBreak, Image, ListFlowable,
                             ListItem)
from reportlab.platypus.flowables import HRFlowable
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')

from ...models.session import Session
from ...utils.logger import Logger
from ...utils.config import Config
from .pdf_helpers import (
    add_header_footer, create_title_page, create_net4_styles,
    create_table_style, create_section, create_info_box,
    create_chart_pie, create_chart_bar, create_metric_grid,
    matplotlib_to_image, NET4_COLORS
)


class ReportGenerator:
    """
    Generates detailed reports from session data in various formats.
    """
    
    def __init__(self, config: Config):
        """
        Initialize report generator
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.logger = Logger().get_logger()
        self.stop_processing = False
    
    def generate_pdf_report(
        self, 
        session: Session,
        output_path: str,
        sections: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[str, float], None]] = None
    ) -> bool:
        """
        Generate a PDF report
        
        Args:
            session: Analysis session
            output_path: Output file path
            sections: Report sections to include (default: all)
            progress_callback: Callback for progress updates
            
        Returns:
            True if successful
        """
        if progress_callback:
            progress_callback("Preparing report data", 0.1)
        
        # Default sections
        if sections is None:
            sections = [
                "summary", "traffic_overview", "entities", 
                "anomalies", "threats", "timeline"
            ]
        
        try:
            # Create PDF document with custom header/footer
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(
                buffer, 
                pagesize=letter,
                rightMargin=0.5*inch,
                leftMargin=0.5*inch,
                topMargin=0.75*inch,  # Increased top margin for header
                bottomMargin=0.75*inch  # Increased bottom margin for footer
            )
            
            # Use the enhanced theme styles from pdf_helpers module
            styles = create_net4_styles()
            
            # Get theme from config
            theme = self.config.get("reporting.theme", "corporate")
            
            # Story (elements to add to document)
            story = []
            
            # Add report elements based on selected sections
            
            # Title page
            if progress_callback:
                progress_callback("Generating title page", 0.15)
            
            self._add_title_page(story, session, styles)
            story.append(PageBreak())
            
            # Table of contents
            if progress_callback:
                progress_callback("Generating table of contents", 0.2)
            
            self._add_table_of_contents(story, sections, styles)
            story.append(PageBreak())
            
            # Executive summary
            if "summary" in sections:
                if progress_callback:
                    progress_callback("Generating executive summary", 0.25)
                
                self._add_executive_summary(story, session, styles)
                story.append(PageBreak())
            
            # Traffic overview
            if "traffic_overview" in sections:
                if progress_callback:
                    progress_callback("Generating traffic overview", 0.35)
                
                self._add_traffic_overview(story, session, styles)
                story.append(PageBreak())
            
            # Network entities
            if "entities" in sections:
                if progress_callback:
                    progress_callback("Generating network entities section", 0.45)
                
                self._add_network_entities(story, session, styles)
                story.append(PageBreak())
            
            # Detected anomalies
            if "anomalies" in sections:
                if progress_callback:
                    progress_callback("Generating anomalies section", 0.55)
                
                self._add_anomalies(story, session, styles)
                story.append(PageBreak())
            
            # Threat intelligence
            if "threats" in sections:
                if progress_callback:
                    progress_callback("Generating threat intelligence section", 0.65)
                
                self._add_threat_intelligence(story, session, styles)
                story.append(PageBreak())
            
            # Timeline
            if "timeline" in sections:
                if progress_callback:
                    progress_callback("Generating timeline section", 0.75)
                
                self._add_timeline(story, session, styles)
                story.append(PageBreak())
            
            # Build document with custom header and footer
            if progress_callback:
                progress_callback("Building PDF document", 0.85)
            
            # Get logo path and report title
            logo_path = self.config.get("reporting.logo_path")
            if logo_path and not os.path.isabs(logo_path):
                # Resolve relative path
                logo_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
                                      os.path.dirname(__file__)))), logo_path)
            
            report_title = "Network Forensic Analysis Report"
            
            # Build document with custom header/footer
            doc.build(
                story,
                onFirstPage=lambda canvas, doc: add_header_footer(canvas, doc, report_title, logo_path),
                onLaterPages=lambda canvas, doc: add_header_footer(canvas, doc, report_title, logo_path)
            )
            
            # Save to file
            with open(output_path, 'wb') as f:
                f.write(buffer.getvalue())
            
            if progress_callback:
                progress_callback("Report generated successfully", 1.0)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error generating PDF report: {str(e)}")
            if progress_callback:
                progress_callback(f"Error: {str(e)}", 1.0)
            return False
    
    def generate_pdf_report_async(
        self, 
        session: Session,
        output_path: str,
        sections: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[str, float], None]] = None,
        completion_callback: Optional[Callable[[bool], None]] = None
    ) -> threading.Thread:
        """
        Generate a PDF report asynchronously
        
        Args:
            session: Analysis session
            output_path: Output file path
            sections: Report sections to include
            progress_callback: Callback for progress updates
            completion_callback: Callback when generation completes
            
        Returns:
            Thread object for the report generation task
        """
        def task():
            try:
                result = self.generate_pdf_report(
                    session, output_path, sections, progress_callback
                )
                if completion_callback:
                    completion_callback(result)
            except Exception as e:
                self.logger.error(f"Async report generation error: {str(e)}")
                if completion_callback:
                    completion_callback(False)
        
        thread = threading.Thread(target=task)
        thread.daemon = True
        thread.start()
        return thread
    
    def generate_text_report(
        self, 
        session: Session,
        output_file: TextIO,
        sections: Optional[List[str]] = None
    ) -> bool:
        """
        Generate a plain text report
        
        Args:
            session: Analysis session
            output_file: Output file object
            sections: Report sections to include (default: all)
            
        Returns:
            True if successful
        """
        # Default sections
        if sections is None:
            sections = [
                "summary", "traffic_overview", "entities", 
                "anomalies", "threats", "timeline"
            ]
        
        try:
            # Title and metadata
            output_file.write(f"=================================================\n")
            output_file.write(f"NETWORK FORENSIC ANALYSIS REPORT\n")
            output_file.write(f"=================================================\n\n")
            
            output_file.write(f"Session: {session.name if hasattr(session, 'name') else 'Unknown'}\n")
            output_file.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            output_file.write(f"Analyst: {self.config.get('reporting.analyst_name', 'Not specified')}\n\n")
            
            # Table of contents
            output_file.write("TABLE OF CONTENTS\n")
            output_file.write("-----------------\n")
            
            if "summary" in sections:
                output_file.write("1. Executive Summary\n")
            if "traffic_overview" in sections:
                output_file.write("2. Traffic Overview\n")
            if "entities" in sections:
                output_file.write("3. Network Entities\n")
            if "anomalies" in sections:
                output_file.write("4. Detected Anomalies\n")
            if "threats" in sections:
                output_file.write("5. Threat Intelligence\n")
            if "timeline" in sections:
                output_file.write("6. Event Timeline\n")
            
            output_file.write("\n\n")
            
            # Executive summary
            if "summary" in sections:
                output_file.write("1. EXECUTIVE SUMMARY\n")
                output_file.write("====================\n\n")
                
                # Session metadata
                session_name = session.name if hasattr(session, 'name') else 'Unknown'
                created_at = session.created_at if hasattr(session, 'created_at') else datetime.now()
                last_modified = session.last_modified if hasattr(session, 'last_modified') else datetime.now()
                
                output_file.write(f"Analysis Session: {session_name}\n")
                output_file.write(f"Created: {created_at.strftime('%Y-%m-%d %H:%M:%S')}\n")
                output_file.write(f"Last Modified: {last_modified.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Files
                files = getattr(session, 'files', {})
                output_file.write(f"Analyzed Files: {len(files)}\n")
                for file_id, file_info in files.items():
                    if isinstance(file_info, dict):
                        name = file_info.get('name', 'Unknown')
                        file_type = file_info.get('type', 'Unknown')
                        output_file.write(f"- {name} ({file_type})\n")
                
                output_file.write("\n")
                
                # Traffic summary
                metadata = getattr(session, 'metadata', {}) or {}
                packet_count = metadata.get("packet_count", 0)
                start_time = metadata.get("start_time")
                end_time = metadata.get("end_time")
                
                output_file.write(f"Captured Packets: {packet_count}\n")
                
                if start_time and end_time:
                    output_file.write(f"Capture Time Range: {start_time.strftime('%Y-%m-%d %H:%M:%S')} to {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    duration = (end_time - start_time).total_seconds()
                    output_file.write(f"Capture Duration: {self._format_duration(duration)}\n")
                
                output_file.write("\n")
                
                # Key findings from AI insights
                ai_insights = getattr(session, 'ai_insights', []) or []
                if ai_insights:
                    output_file.write("Key Findings:\n")
                    for insight in ai_insights:
                        if isinstance(insight, dict) and insight.get("type") == "overview":
                            key_observations = insight.get("key_observations", [])
                            for i, observation in enumerate(key_observations[:5]):
                                output_file.write(f"- {observation}\n")
                
                output_file.write("\n\n")
            
            # Traffic overview
            if "traffic_overview" in sections:
                output_file.write("2. TRAFFIC OVERVIEW\n")
                output_file.write("===================\n\n")
                
                # Protocol distribution
                metadata = getattr(session, 'metadata', {}) or {}
                protocols = metadata.get("protocols", [])
                if protocols:
                    output_file.write("Protocol Distribution:\n")
                    for protocol in protocols:
                        output_file.write(f"- {protocol}\n")
                
                output_file.write("\n")
                
                # Connection statistics
                connections = getattr(session, 'connections', []) or []
                output_file.write(f"Total Connections: {len(connections)}\n")
                
                # Count unique IPs
                src_ips = set()
                dst_ips = set()
                for conn in connections:
                    if isinstance(conn, dict):
                        if "src_ip" in conn:
                            src_ips.add(conn["src_ip"])
                        if "dst_ip" in conn:
                            dst_ips.add(conn["dst_ip"])
                
                output_file.write(f"Unique Source IPs: {len(src_ips)}\n")
                output_file.write(f"Unique Destination IPs: {len(dst_ips)}\n")
                
                output_file.write("\n\n")
            
            # Network entities
            if "entities" in sections:
                output_file.write("3. NETWORK ENTITIES\n")
                output_file.write("===================\n\n")
                
                # Group entities by type
                network_entities = getattr(session, 'network_entities', {}) or {}
                entity_types = {}
                for entity_id, entity in network_entities.items():
                    if not hasattr(entity, 'type'):
                        continue
                    entity_type = entity.type
                    if entity_type not in entity_types:
                        entity_types[entity_type] = []
                    entity_types[entity_type].append(entity)
                
                # Report by type
                for entity_type, entities in entity_types.items():
                    output_file.write(f"{entity_type.upper()} Entities ({len(entities)}):\n")
                    output_file.write("-" * (len(entity_type) + 11 + len(str(len(entities))) + 2) + "\n")
                    
                    # Sort by threat level
                    def threat_level_value(e):
                        if not hasattr(e, 'threat_level'):
                            return 0
                        return self._threat_level_value(e.threat_level)
                    
                    entities.sort(key=threat_level_value, reverse=True)
                    
                    # Report top entities (limit to 20)
                    for entity in entities[:20]:
                        if not hasattr(entity, 'value') or not hasattr(entity, 'threat_level'):
                            continue
                            
                        threat_indicator = ""
                        if entity.threat_level == "malicious":
                            threat_indicator = "[MALICIOUS] "
                        elif entity.threat_level == "suspicious":
                            threat_indicator = "[SUSPICIOUS] "
                        
                        output_file.write(f"- {threat_indicator}{entity.value}\n")
                    
                    if len(entities) > 20:
                        output_file.write(f"  ... and {len(entities) - 20} more\n")
                    
                    output_file.write("\n")
                
                output_file.write("\n")
            
            # Detected anomalies
            if "anomalies" in sections:
                output_file.write("4. DETECTED ANOMALIES\n")
                output_file.write("=====================\n\n")
                
                anomalies = getattr(session, 'anomalies', []) or []
                if anomalies:
                    # Group anomalies by type
                    anomaly_types = {}
                    for anomaly in anomalies:
                        if not isinstance(anomaly, dict):
                            continue
                        anom_type = anomaly.get("type", "unknown")
                        if anom_type not in anomaly_types:
                            anomaly_types[anom_type] = []
                        anomaly_types[anom_type].append(anomaly)
                    
                    # Report by type
                    for anom_type, type_anomalies in anomaly_types.items():
                        output_file.write(f"{anom_type.upper()} Anomalies ({len(type_anomalies)}):\n")
                        output_file.write("-" * (len(anom_type) + 12 + len(str(len(type_anomalies))) + 2) + "\n")
                        
                        # Sort by severity
                        type_anomalies.sort(key=lambda a: self._severity_value(a.get("severity", "unknown")), reverse=True)
                        
                        # Report top anomalies (limit to 10 per type)
                        for anomaly in type_anomalies[:10]:
                            severity = anomaly.get("severity", "unknown").upper()
                            description = anomaly.get("description", "No description available")
                            output_file.write(f"- [{severity}] {description}\n")
                        
                        if len(type_anomalies) > 10:
                            output_file.write(f"  ... and {len(type_anomalies) - 10} more\n")
                        
                        output_file.write("\n")
                else:
                    output_file.write("No anomalies detected in this session.\n\n")
                
                output_file.write("\n")
            
            # Threat intelligence
            if "threats" in sections:
                output_file.write("5. THREAT INTELLIGENCE\n")
                output_file.write("======================\n\n")
                
                threat_intelligence = getattr(session, 'threat_intelligence', {}) or {}
                network_entities = getattr(session, 'network_entities', {}) or {}
                
                if threat_intelligence:
                    # Group by verdict
                    verdicts = {
                        "malicious": [],
                        "suspicious": [],
                        "clean": [],
                        "unknown": []
                    }
                    
                    for entity_id, ti_data in threat_intelligence.items():
                        if entity_id in network_entities:
                            entity = network_entities[entity_id]
                            if not hasattr(ti_data, 'verdict'):
                                continue
                                
                            verdict = ti_data.verdict
                            if verdict in verdicts:
                                verdicts[verdict].append((entity, ti_data))
                    
                    # Report malicious entities
                    if verdicts["malicious"]:
                        output_file.write(f"Malicious Entities ({len(verdicts['malicious'])}):\n")
                        output_file.write("-" * (len("Malicious Entities") + 3 + len(str(len(verdicts['malicious']))) + 2) + "\n")
                        
                        for entity, ti_data in verdicts["malicious"]:
                            if not hasattr(entity, 'type') or not hasattr(entity, 'value'):
                                continue
                                
                            output_file.write(f"- [{entity.type.upper()}] {entity.value}\n")
                            
                            if hasattr(ti_data, 'risk_score'):
                                output_file.write(f"  Risk Score: {ti_data.risk_score:.2f}\n")
                                
                            if hasattr(ti_data, 'summary'):
                                output_file.write(f"  Summary: {ti_data.summary}\n")
                                
                            output_file.write("\n")
                    
                    # Report suspicious entities
                    if verdicts["suspicious"]:
                        output_file.write(f"Suspicious Entities ({len(verdicts['suspicious'])}):\n")
                        output_file.write("-" * (len("Suspicious Entities") + 3 + len(str(len(verdicts['suspicious']))) + 2) + "\n")
                        
                        for entity, ti_data in verdicts["suspicious"]:
                            if not hasattr(entity, 'type') or not hasattr(entity, 'value'):
                                continue
                                
                            output_file.write(f"- [{entity.type.upper()}] {entity.value}\n")
                            
                            if hasattr(ti_data, 'risk_score'):
                                output_file.write(f"  Risk Score: {ti_data.risk_score:.2f}\n")
                                
                            if hasattr(ti_data, 'summary'):
                                output_file.write(f"  Summary: {ti_data.summary}\n")
                                
                            output_file.write("\n")
                else:
                    output_file.write("No threat intelligence data available for this session.\n\n")
                
                output_file.write("\n")
            
            # Timeline
            if "timeline" in sections:
                output_file.write("6. EVENT TIMELINE\n")
                output_file.write("=================\n\n")
                
                timeline_events = getattr(session, 'timeline_events', []) or []
                if timeline_events:
                    # Sort events by timestamp
                    events = []
                    for event in timeline_events:
                        if isinstance(event, dict) and "timestamp" in event:
                            events.append(event)
                    
                    events.sort(key=lambda e: e.get("timestamp", datetime.min))
                    
                    # Create a timeline
                    for i, event in enumerate(events[:50]):  # Limit to first 50 events
                        timestamp = event.get("timestamp")
                        if timestamp:
                            time_str = timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                        else:
                            time_str = "Unknown time"
                        
                        event_type = event.get("type", "unknown")
                        
                        if event_type == "packet" and "parsed_data" in event:
                            parsed = event.get("parsed_data", {})
                            src_ip = parsed.get("src_ip", "unknown")
                            dst_ip = parsed.get("dst_ip", "unknown")
                            protocol = parsed.get("protocol", "unknown")
                            
                            output_file.write(f"[{time_str}] PACKET: {src_ip} -> {dst_ip} ({protocol})\n")
                        
                        elif event_type == "log_entry" and "parsed_data" in event:
                            parsed = event.get("parsed_data", {})
                            source = event.get("source", "unknown")
                            
                            output_file.write(f"[{time_str}] LOG ({source}): ")
                            
                            if "message" in parsed:
                                output_file.write(f"{parsed['message'][:100]}...\n")
                            else:
                                output_file.write(f"{str(parsed)[:100]}...\n")
                        
                        else:
                            output_file.write(f"[{time_str}] {event_type.upper()}: {str(event)[:100]}...\n")
                    
                    if len(events) > 50:
                        output_file.write(f"\n... and {len(events) - 50} more events\n")
                else:
                    output_file.write("No timeline events available for this session.\n")
                
                output_file.write("\n")
            
            output_file.write("\n=== END OF REPORT ===\n")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error generating text report: {str(e)}")
            return False
    
    def stop(self) -> None:
        """Stop ongoing report generation"""
        self.stop_processing = True
    
    def _add_title_page(
        self, 
        story: List, 
        session: Session, 
        styles
    ) -> None:
        """
        Add title page to report
        
        Args:
            story: Report story to add elements to
            session: Analysis session
            styles: Document styles
        """
        # Get logo path and ensure it's resolved correctly
        logo_path = self.config.get("reporting.logo_path")
        if logo_path:
            # Handle relative paths by making them absolute
            if not os.path.isabs(logo_path):
                logo_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
                                        os.path.dirname(__file__)))), logo_path)
        
        # Session info with null checks
        session_name = getattr(session, 'name', 'Unknown Session')
        created_at = getattr(session, 'created_at', datetime.now())
        
        session_info = [
            ["Session Name:", session_name],
            ["Created:", created_at.strftime("%Y-%m-%d %H:%M:%S")],
            ["Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
        ]
        
        company_name = self.config.get("reporting.company_name")
        if company_name:
            session_info.append(["Organization:", company_name])
        
        analyst_name = self.config.get("reporting.analyst_name")
        if analyst_name:
            session_info.append(["Analyst:", analyst_name])
        
        # Add information about analyzed files
        files = getattr(session, 'files', {}) or {}
        file_count = len(files)
        if file_count > 0:
            session_info.append(["Files Analyzed:", str(file_count)])
        
        # Use the enhanced title page creation function
        subtitle = f"Analysis Session: {session_name}"
        create_title_page(
            story, 
            title="Network Forensic Analysis Report", 
            subtitle=subtitle,
            logo_path=logo_path,
            session_info=session_info
        )
    
    def _add_table_of_contents(
        self, 
        story: List, 
        sections: List[str], 
        styles
    ) -> None:
        """
        Add table of contents
        
        Args:
            story: Report story to add elements to
            sections: Report sections to include
            styles: Document styles
        """
        story.append(Paragraph("Table of Contents", styles["Heading1"]))
        story.append(Spacer(1, 0.2*inch))
        
        toc_data = []
        
        if "summary" in sections:
            toc_data.append(["1. Executive Summary", "3"])
        
        if "traffic_overview" in sections:
            toc_data.append(["2. Traffic Overview", "4"])
        
        if "entities" in sections:
            toc_data.append(["3. Network Entities", "5"])
        
        if "anomalies" in sections:
            toc_data.append(["4. Detected Anomalies", "6"])
        
        if "threats" in sections:
            toc_data.append(["5. Threat Intelligence", "7"])
        
        if "timeline" in sections:
            toc_data.append(["6. Event Timeline", "8"])
        
        # Create table
        toc_table = Table(toc_data, colWidths=[5*inch, 0.5*inch])
        toc_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('ALIGN', (-1, 0), (-1, -1), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ]))
        
        story.append(toc_table)
    
    def _add_executive_summary(
        self, 
        story: List, 
        session: Session, 
        styles
    ) -> None:
        """
        Add executive summary section
        
        Args:
            story: Report story to add elements to
            session: Analysis session
            styles: Document styles
        """
        story.append(Paragraph("1. Executive Summary", styles["Heading1"]))
        story.append(Spacer(1, 0.2*inch))
        
        # Session metadata
        story.append(Paragraph("Session Information", styles["Heading2"]))
        story.append(Spacer(1, 0.1*inch))
        
        # Traffic summary with null checks
        metadata = getattr(session, 'metadata', {}) or {}
        packet_count = metadata.get("packet_count", 0)
        start_time = metadata.get("start_time")
        end_time = metadata.get("end_time")
        duration = metadata.get("duration", 0)
        
        summary_items = []
        
        summary_items.append(f"Captured Packets: {packet_count}")
        
        if start_time and end_time:
            summary_items.append(f"Capture Time Range: {start_time.strftime('%Y-%m-%d %H:%M:%S')} to {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
            summary_items.append(f"Capture Duration: {self._format_duration(duration)}")
        
        # Entity counts with null checks
        network_entities = getattr(session, 'network_entities', {}) or {}
        ip_count = 0
        domain_count = 0
        
        for entity_id, entity in network_entities.items():
            if hasattr(entity, 'type'):
                if entity.type == "ip":
                    ip_count += 1
                elif entity.type == "domain":
                    domain_count += 1
        
        summary_items.append(f"Unique IP Addresses: {ip_count}")
        summary_items.append(f"Unique Domains: {domain_count}")
        
        # Anomaly counts with null checks
        anomalies = getattr(session, 'anomalies', []) or []
        if anomalies:
            anomaly_count = len(anomalies)
            high_severity = 0
            
            for anomaly in anomalies:
                if isinstance(anomaly, dict) and anomaly.get("severity") == "high":
                    high_severity += 1
            
            summary_items.append(f"Detected Anomalies: {anomaly_count} ({high_severity} high severity)")
        
        # Threat intelligence with null checks
        malicious_count = 0
        suspicious_count = 0
        
        for entity_id, entity in network_entities.items():
            if hasattr(entity, 'threat_level'):
                if entity.threat_level == "malicious":
                    malicious_count += 1
                elif entity.threat_level == "suspicious":
                    suspicious_count += 1
        
        if malicious_count > 0 or suspicious_count > 0:
            summary_items.append(f"Malicious Entities: {malicious_count}")
            summary_items.append(f"Suspicious Entities: {suspicious_count}")
        
        # Add summary items as bullet points
        for item in summary_items:
            story.append(Paragraph(f"• {item}", styles["Normal"]))
        
        story.append(Spacer(1, 0.2*inch))
        
        # Key findings from AI insights with null checks
        story.append(Paragraph("Key Findings", styles["Heading2"]))
        story.append(Spacer(1, 0.1*inch))
        
        ai_insights = getattr(session, 'ai_insights', []) or []
        if ai_insights:
            key_items = []
            
            # Look for overview insights
            for insight in ai_insights:
                if isinstance(insight, dict) and insight.get("type") == "overview":
                    # Get key observations
                    key_observations = insight.get("key_observations", [])
                    for observation in key_observations[:5]:  # Limit to 5
                        key_items.append(observation)
                    
                    # Get security concerns
                    security_concerns = insight.get("security_concerns", [])
                    for concern in security_concerns[:3]:  # Limit to 3
                        key_items.append(f"Security Concern: {concern}")
                    
                    break
            
            # If no overview insight, use the first insight
            if not key_items and ai_insights:
                insight = ai_insights[0]
                if isinstance(insight, dict):
                    for k, v in insight.items():
                        if isinstance(v, list) and k != "timestamp" and k != "model":
                            for item in v[:3]:  # Limit to 3
                                key_items.append(f"{k.replace('_', ' ').title()}: {item}")
                            break
            
            # Add key items as bullet points
            for item in key_items:
                story.append(Paragraph(f"• {item}", styles["Normal"]))
        else:
            story.append(Paragraph("No AI insights available for this session.", styles["Normal"]))
        
        story.append(Spacer(1, 0.2*inch))
        
        # Add protocol distribution chart if we have protocols
        metadata = getattr(session, 'metadata', {}) or {}
        protocols = metadata.get("protocols", [])
        if protocols:
            story.append(Paragraph("Protocol Distribution", styles["Heading2"]))
            story.append(Spacer(1, 0.1*inch))
            
            # Create and add chart
            try:
                # Count protocols in packets with null checks
                protocol_counts = {}
                packets = getattr(session, 'packets', []) or []
                
                for packet in packets:
                    if isinstance(packet, dict):
                        protocol = packet.get("protocol")
                        if protocol:
                            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
                
                if protocol_counts:
                    # Create pie chart - FIX: Increased figure size for better layout
                    plt.figure(figsize=(8, 6))
                    plt.pie(protocol_counts.values(), labels=protocol_counts.keys(), autopct='%1.1f%%')
                    plt.axis('equal')
                    plt.title('Protocol Distribution')
                    
                    # Add more padding to ensure tight layout works
                    plt.tight_layout(pad=3.0)
                    
                    # Save to buffer
                    img_buffer = io.BytesIO()
                    plt.savefig(img_buffer, format='png', bbox_inches='tight')
                    img_buffer.seek(0)
                    plt.close()
                    
                    # Add to story
                    img = Image(img_buffer, width=4*inch, height=3*inch)
                    story.append(img)
            except Exception as e:
                self.logger.error(f"Error creating protocol chart: {str(e)}")
                story.append(Paragraph("Error creating protocol chart.", styles["Normal"]))
    
    def _add_traffic_overview(
        self, 
        story: List, 
        session: Session, 
        styles
    ) -> None:
        """
        Add traffic overview section
        
        Args:
            story: Report story to add elements to
            session: Analysis session
            styles: Document styles
        """
        story.append(Paragraph("2. Traffic Overview", styles["Heading1"]))
        story.append(Spacer(1, 0.2*inch))
        
        # Traffic summary with null checks
        metadata = getattr(session, 'metadata', {}) or {}
        packet_count = metadata.get("packet_count", 0)
        start_time = metadata.get("start_time")
        end_time = metadata.get("end_time")
        duration = metadata.get("duration", 0)
        
        summary_items = []
        
        summary_items.append(f"Captured Packets: {packet_count}")
        
        if start_time and end_time:
            summary_items.append(f"Capture Time Range: {self._safe_format_timestamp(start_time)} to {self._safe_format_timestamp(end_time)}")
            summary_items.append(f"Capture Duration: {self._format_duration(duration)}")
        
        # Connection statistics
        story.append(Paragraph("Connection Statistics", styles["Heading2"]))
        story.append(Spacer(1, 0.1*inch))
        
        # Count unique IPs with null checks
        connections = getattr(session, 'connections', []) or []
        src_ips = set()
        dst_ips = set()
        
        for conn in connections:
            if isinstance(conn, dict):
                if "src_ip" in conn:
                    src_ips.add(conn["src_ip"])
                if "dst_ip" in conn:
                    dst_ips.add(conn["dst_ip"])
        
        # Count connections by protocol with null checks
        protocols = {}
        for conn in connections:
            if isinstance(conn, dict):
                protocol = conn.get("protocol", "Unknown")
                protocols[protocol] = protocols.get(protocol, 0) + 1
        
        # Create statistics table
        stats_data = [
            ["Metric", "Value"],
            ["Total Connections", str(len(connections))],
            ["Unique Source IPs", str(len(src_ips))],
            ["Unique Destination IPs", str(len(dst_ips))],
            ["Connection Protocols", ", ".join(f"{p} ({c})" for p, c in protocols.items())]
        ]
        
        stats_table = Table(stats_data, colWidths=[2*inch, 3.5*inch])
        stats_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(stats_table)
        story.append(Spacer(1, 0.2*inch))
        
        # Top talkers
        story.append(Paragraph("Top Talkers", styles["Heading2"]))
        story.append(Spacer(1, 0.1*inch))
        
        # Calculate top source IPs by connection count
        src_ip_counts = {}
        for conn in connections:
            if isinstance(conn, dict):
                src_ip = conn.get("src_ip")
                if src_ip:
                    src_ip_counts[src_ip] = src_ip_counts.get(src_ip, 0) + 1
        
        # Sort and get top 10
        top_sources = sorted(src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Calculate top destination IPs by connection count
        dst_ip_counts = {}
        for conn in connections:
            if isinstance(conn, dict):
                dst_ip = conn.get("dst_ip")
                if dst_ip:
                    dst_ip_counts[dst_ip] = dst_ip_counts.get(dst_ip, 0) + 1
        
        # Sort and get top 10
        top_destinations = sorted(dst_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Create top talkers table
        talkers_data = [["Source IP", "Connections", "Destination IP", "Connections"]]
        
        # Combine top sources and destinations
        for i in range(max(len(top_sources), len(top_destinations))):
            row = []
            
            if i < len(top_sources):
                row.extend([top_sources[i][0], str(top_sources[i][1])])
            else:
                row.extend(["", ""])
            
            if i < len(top_destinations):
                row.extend([top_destinations[i][0], str(top_destinations[i][1])])
            else:
                row.extend(["", ""])
            
            talkers_data.append(row)
        
        talkers_table = Table(talkers_data, colWidths=[1.5*inch, 1*inch, 1.5*inch, 1*inch])
        talkers_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('ALIGN', (3, 0), (3, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(talkers_table)
        story.append(Spacer(1, 0.2*inch))
        
        # Packet time distribution chart with null checks
        packets = getattr(session, 'packets', []) or []
        if packets and len(packets) > 10:
            story.append(Paragraph("Packet Time Distribution", styles["Heading2"]))
            story.append(Spacer(1, 0.1*inch))
            
            try:
                # Get timestamps
                timestamps = []
                for packet in packets:
                    if isinstance(packet, dict):
                        timestamp = packet.get("timestamp")
                        if timestamp:
                            timestamps.append(timestamp)
                
                if timestamps:
                    # Create histogram - FIX: Increased figure size and adjusted layout
                    plt.figure(figsize=(9, 4))
                    plt.hist(timestamps, bins=30, alpha=0.7, color='blue')
                    plt.xlabel('Time')
                    plt.ylabel('Packet Count')
                    plt.title('Packet Time Distribution')
                    
                    # Rotate x-axis labels and ensure they don't overlap
                    plt.xticks(rotation=45)
                    
                    # Add more padding for tight layout
                    plt.tight_layout(pad=3.0)
                    
                    # Save to buffer with extra space around the plot
                    img_buffer = io.BytesIO()
                    plt.savefig(img_buffer, format='png', bbox_inches='tight')
                    img_buffer.seek(0)
                    plt.close()
                    
                    # Add to story
                    img = Image(img_buffer, width=6*inch, height=3*inch)
                    story.append(img)
            except Exception as e:
                self.logger.error(f"Error creating time distribution chart: {str(e)}")
                story.append(Paragraph("Error creating time distribution chart.", styles["Normal"]))
    
    def _add_network_entities(
        self, 
        story: List, 
        session: Session, 
        styles
    ) -> None:
        """
        Add network entities section
        
        Args:
            story: Report story to add elements to
            session: Analysis session
            styles: Document styles
        """
        story.append(Paragraph("3. Network Entities", styles["Heading1"]))
        story.append(Spacer(1, 0.2*inch))
        
        # Group entities by type with null checks
        network_entities = getattr(session, 'network_entities', {}) or {}
        entity_types = {}
        
        for entity_id, entity in network_entities.items():
            if not hasattr(entity, 'type'):
                continue
                
            entity_type = entity.type
            if entity_type not in entity_types:
                entity_types[entity_type] = []
            entity_types[entity_type].append(entity)
        
        # Entity counts
        story.append(Paragraph("Entity Counts", styles["Heading2"]))
        story.append(Spacer(1, 0.1*inch))
        
        # Entity count table
        count_data = [["Entity Type", "Count", "Malicious", "Suspicious"]]
        
        for entity_type, entities in entity_types.items():
            # Count with null checks
            malicious = 0
            suspicious = 0
            
            for entity in entities:
                if hasattr(entity, 'threat_level'):
                    if entity.threat_level == "malicious":
                        malicious += 1
                    elif entity.threat_level == "suspicious":
                        suspicious += 1
            
            count_data.append([
                entity_type.capitalize(),
                str(len(entities)),
                str(malicious),
                str(suspicious)
            ])
        
        # Handle empty entity types
        if len(count_data) == 1:
            count_data.append(["No entities", "0", "0", "0"])
        
        count_table = Table(count_data, colWidths=[1.5*inch, 1*inch, 1*inch, 1*inch])
        count_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(count_table)
        story.append(Spacer(1, 0.2*inch))
        
        # Report malicious entities with null checks
        malicious_entities = []
        for entity_id, entity in network_entities.items():
            if hasattr(entity, 'threat_level') and entity.threat_level == "malicious":
                malicious_entities.append(entity)
        
        if malicious_entities:
            story.append(Paragraph("Malicious Entities", styles["Heading2"]))
            story.append(Spacer(1, 0.1*inch))
            
            mal_data = [["Type", "Value", "Confidence", "Tags"]]
            
            for entity in malicious_entities[:20]:  # Limit to 20
                if not hasattr(entity, 'type') or not hasattr(entity, 'value'):
                    continue
                    
                # Safe confidence access
                confidence = 0
                if hasattr(entity, 'confidence'):
                    confidence = entity.confidence
                
                # Get threat intel data if available
                tags = []
                threat_intelligence = getattr(session, 'threat_intelligence', {}) or {}
                
                if hasattr(entity, 'id') and entity.id in threat_intelligence:
                    ti_data = threat_intelligence[entity.id]
                    if hasattr(ti_data, 'tags'):
                        tags = ti_data.tags[:3]  # Limit to 3 tags
                
                mal_data.append([
                    entity.type.capitalize(),
                    entity.value,
                    f"{confidence:.2f}",
                    ", ".join(tags)
                ])
            
            if len(mal_data) == 1:
                mal_data.append(["N/A", "N/A", "N/A", "N/A"])
                
            mal_table = Table(mal_data, colWidths=[1*inch, 2.5*inch, 1*inch, 1.5*inch])
            mal_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('ALIGN', (2, 0), (2, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            story.append(mal_table)
            
            if len(malicious_entities) > 20:
                story.append(Paragraph(f"... and {len(malicious_entities) - 20} more", styles["Normal"]))
            
            story.append(Spacer(1, 0.2*inch))
        
        # Report suspicious entities with null checks
        suspicious_entities = []
        for entity_id, entity in network_entities.items():
            if hasattr(entity, 'threat_level') and entity.threat_level == "suspicious":
                suspicious_entities.append(entity)
        
        if suspicious_entities:
            story.append(Paragraph("Suspicious Entities", styles["Heading2"]))
            story.append(Spacer(1, 0.1*inch))
            
            sus_data = [["Type", "Value", "Confidence", "Tags"]]
            
            for entity in suspicious_entities[:20]:  # Limit to 20
                if not hasattr(entity, 'type') or not hasattr(entity, 'value'):
                    continue
                    
                # Safe confidence access
                confidence = 0
                if hasattr(entity, 'confidence'):
                    confidence = entity.confidence
                
                # Get threat intel data if available
                tags = []
                threat_intelligence = getattr(session, 'threat_intelligence', {}) or {}
                
                if hasattr(entity, 'id') and entity.id in threat_intelligence:
                    ti_data = threat_intelligence[entity.id]
                    if hasattr(ti_data, 'tags'):
                        tags = ti_data.tags[:3]  # Limit to 3 tags
                
                sus_data.append([
                    entity.type.capitalize(),
                    entity.value,
                    f"{confidence:.2f}",
                    ", ".join(tags)
                ])
            
            if len(sus_data) == 1:
                sus_data.append(["N/A", "N/A", "N/A", "N/A"])
                
            sus_table = Table(sus_data, colWidths=[1*inch, 2.5*inch, 1*inch, 1.5*inch])
            sus_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('ALIGN', (2, 0), (2, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            story.append(sus_table)
            
            if len(suspicious_entities) > 20:
                story.append(Paragraph(f"... and {len(suspicious_entities) - 20} more", styles["Normal"]))
            
            story.append(Spacer(1, 0.2*inch))
    
    def _add_anomalies(
        self, 
        story: List, 
        session: Session, 
        styles
    ) -> None:
        """
        Add anomalies section
        
        Args:
            story: Report story to add elements to
            session: Analysis session
            styles: Document styles
        """
        story.append(Paragraph("4. Detected Anomalies", styles["Heading1"]))
        story.append(Spacer(1, 0.2*inch))
        
        anomalies = getattr(session, 'anomalies', []) or []
        if not anomalies:
            story.append(Paragraph("No anomalies detected in this session.", styles["Normal"]))
            return
        
        # Group anomalies by type
        anomaly_types = {}
        for anomaly in anomalies:
            if not isinstance(anomaly, dict):
                continue
                
            anom_type = anomaly.get("type", "unknown")
            if anom_type not in anomaly_types:
                anomaly_types[anom_type] = []
            anomaly_types[anom_type].append(anomaly)
        
        # Anomaly counts
        story.append(Paragraph("Anomaly Counts", styles["Heading2"]))
        story.append(Spacer(1, 0.1*inch))
        
        # Count table
        count_data = [["Anomaly Type", "Count", "High", "Medium", "Low"]]
        
        for anom_type, type_anomalies in anomaly_types.items():
            high = sum(1 for a in type_anomalies if isinstance(a, dict) and a.get("severity") == "high")
            medium = sum(1 for a in type_anomalies if isinstance(a, dict) and a.get("severity") == "medium")
            low = sum(1 for a in type_anomalies if isinstance(a, dict) and a.get("severity") == "low")
            
            count_data.append([
                anom_type.replace("_", " ").title(),
                str(len(type_anomalies)),
                str(high),
                str(medium),
                str(low)
            ])
        
        # Handle empty anomaly types
        if len(count_data) == 1:
            count_data.append(["No anomalies", "0", "0", "0", "0"])
            
        count_table = Table(count_data, colWidths=[2*inch, 0.8*inch, 0.8*inch, 0.8*inch, 0.8*inch])
        count_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(count_table)
        story.append(Spacer(1, 0.2*inch))
        
        # High severity anomalies
        high_anomalies = [a for a in anomalies if isinstance(a, dict) and a.get("severity") == "high"]
        
        if high_anomalies:
            story.append(Paragraph("High Severity Anomalies", styles["Heading2"]))
            story.append(Spacer(1, 0.1*inch))
            
            for i, anomaly in enumerate(high_anomalies):
                # Safe access to anomaly properties
                anom_type = anomaly.get("type", "unknown").replace("_", " ").title()
                subtype = anomaly.get("subtype", "").replace("_", " ").title()
                timestamp = anomaly.get("timestamp")
                description = anomaly.get("description", "No description available")
                
                # Format title
                if subtype:
                    title = f"{anom_type}: {subtype}"
                else:
                    title = anom_type
                
                if timestamp:
                    title += f" ({timestamp.strftime('%Y-%m-%d %H:%M:%S')})"
                
                story.append(Paragraph(title, styles["Heading3"]))
                story.append(Paragraph(description, styles["Normal"]))
                
                # Add relevant details
                details = []
                
                # Make sure anomaly is a dictionary
                if isinstance(anomaly, dict):
                    # IP addresses
                    if "source_ip" in anomaly:
                        details.append(f"Source IP: {anomaly['source_ip']}")
                    
                    if "destination_ip" in anomaly:
                        details.append(f"Destination IP: {anomaly['destination_ip']}")
                    
                    # Ports
                    if "port" in anomaly:
                        details.append(f"Port: {anomaly['port']}")
                    
                    if "dst_port" in anomaly:
                        details.append(f"Destination Port: {anomaly['dst_port']}")
                    
                    # Other common fields
                    if "connection_count" in anomaly:
                        details.append(f"Connection Count: {anomaly['connection_count']}")
                    
                    if "packet_count" in anomaly:
                        details.append(f"Packet Count: {anomaly['packet_count']}")
                    
                    if "total_bytes" in anomaly:
                        total_bytes = anomaly['total_bytes']
                        if isinstance(total_bytes, int):
                            details.append(f"Total Bytes: {self._format_bytes(total_bytes)}")
                        else:
                            details.append(f"Total Bytes: {total_bytes}")
                
                # Add details as bullet points
                if details:
                    for detail in details:
                        story.append(Paragraph(f"• {detail}", styles["Normal"]))
                
                # Add separator between anomalies
                if i < len(high_anomalies) - 1:
                    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey, spaceBefore=10, spaceAfter=10))
            
            story.append(Spacer(1, 0.2*inch))
        
        # Other anomalies (summarized)
        other_anomalies = [a for a in anomalies if isinstance(a, dict) and a.get("severity") != "high"]
        
        if other_anomalies:
            story.append(Paragraph("Other Anomalies (Summary)", styles["Heading2"]))
            story.append(Spacer(1, 0.1*inch))
            
            other_data = [["Type", "Severity", "Description"]]
            
            for anomaly in other_anomalies[:20]:  # Limit to 20
                # Safe access with defaults
                anom_type = anomaly.get("type", "unknown").replace("_", " ").title()
                subtype = anomaly.get("subtype", "").replace("_", " ")
                
                if subtype:
                    anom_type += f" ({subtype})"
                
                description = anomaly.get("description", "No description")
                if len(description) > 80:
                    description = description[:77] + "..."
                
                other_data.append([
                    anom_type,
                    anomaly.get("severity", "unknown").title(),
                    description
                ])
            
            if len(other_data) == 1:
                other_data.append(["N/A", "N/A", "N/A"])
                
            other_table = Table(other_data, colWidths=[1.5*inch, 1*inch, 3.5*inch])
            other_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            story.append(other_table)
            
            if len(other_anomalies) > 20:
                story.append(Paragraph(f"... and {len(other_anomalies) - 20} more", styles["Normal"]))
    
    def _add_threat_intelligence(
        self, 
        story: List, 
        session: Session, 
        styles
    ) -> None:
        """
        Add threat intelligence section
        
        Args:
            story: Report story to add elements to
            session: Analysis session
            styles: Document styles
        """
        story.append(Paragraph("5. Threat Intelligence", styles["Heading1"]))
        story.append(Spacer(1, 0.2*inch))
        
        # Check for threat intelligence data
        threat_intelligence = getattr(session, 'threat_intelligence', {}) or {}
        if not threat_intelligence:
            story.append(Paragraph("No threat intelligence data available for this session.", styles["Normal"]))
            return
        
        # Check for network entities
        network_entities = getattr(session, 'network_entities', {}) or {}
        if not network_entities:
            story.append(Paragraph("No network entities available for threat intelligence.", styles["Normal"]))
            return
        
        # Group by verdict with thorough null checks
        verdicts = {
            "malicious": [],
            "suspicious": [],
            "clean": [],
            "unknown": []
        }
        
        for entity_id, ti_data in threat_intelligence.items():
            if entity_id in network_entities and hasattr(ti_data, 'verdict'):
                entity = network_entities[entity_id]
                verdict = ti_data.verdict
                if verdict in verdicts:
                    verdicts[verdict].append((entity, ti_data))
        
        # Summary counts
        story.append(Paragraph("Threat Summary", styles["Heading2"]))
        story.append(Spacer(1, 0.1*inch))
        
        # Count by type with thorough null checks
        entity_types = {
            "ip": {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0},
            "domain": {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0},
            "url": {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0},
            "hash": {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0},
            "other": {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0}
        }
        
        for verdict, entities in verdicts.items():
            for entity, _ in entities:
                if not hasattr(entity, 'type'):
                    continue
                    
                entity_type = entity.type
                if entity_type not in entity_types:
                    entity_type = "other"
                
                if verdict in entity_types[entity_type]:
                    entity_types[entity_type][verdict] += 1
        
        # Create summary table
        summary_data = [["Entity Type", "Malicious", "Suspicious", "Clean", "Unknown"]]
        
        for entity_type, counts in entity_types.items():
            # Skip if no entities of this type
            if sum(counts.values()) == 0:
                continue
                
            summary_data.append([
                entity_type.capitalize(),
                str(counts["malicious"]),
                str(counts["suspicious"]),
                str(counts["clean"]),
                str(counts["unknown"])
            ])
        
        # Handle empty entity types
        if len(summary_data) == 1:
            summary_data.append(["No entities", "0", "0", "0", "0"])
            
        summary_table = Table(summary_data, colWidths=[1.2*inch, 1.2*inch, 1.2*inch, 1.2*inch, 1.2*inch])
        summary_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 0.2*inch))
        
        # Malicious entities with thorough null checks
        if verdicts["malicious"]:
            story.append(Paragraph("Malicious Entities", styles["Heading2"]))
            story.append(Spacer(1, 0.1*inch))
            
            # Sort by risk score
            def get_risk_score(item):
                entity, ti_data = item
                if hasattr(ti_data, 'risk_score'):
                    return ti_data.risk_score
                return 0
            
            verdicts["malicious"].sort(key=get_risk_score, reverse=True)
            
            for i, (entity, ti_data) in enumerate(verdicts["malicious"][:10]):  # Limit to 10
                if not hasattr(entity, 'type') or not hasattr(entity, 'value'):
                    continue
                    
                entity_title = f"{entity.type.capitalize()}: {entity.value}"
                story.append(Paragraph(entity_title, styles["Heading3"]))
                
                # Add summary
                summary = "No summary available"
                if hasattr(ti_data, 'summary'):
                    summary = ti_data.summary
                story.append(Paragraph(summary, styles["Normal"]))
                
                # Create details table
                details_data = []
                
                if hasattr(ti_data, 'risk_score'):
                    details_data.append(["Risk Score", f"{ti_data.risk_score:.2f}"])
                
                # Add detection stats if available
                sources = getattr(ti_data, 'sources', {}) or {}
                vt_data = sources.get("virustotal", {}) if isinstance(sources, dict) else {}
                
                if vt_data:
                    malicious = vt_data.get("malicious", 0)
                    total = vt_data.get("total", 0)
                    if total > 0:
                        details_data.append(["Detection Ratio", f"{malicious}/{total} ({malicious/total*100:.1f}%)"])
                
                # Add categories and tags
                categories = getattr(ti_data, 'categories', []) or []
                if categories:
                    cat_str = ", ".join(categories[:5])  # Limit to 5
                    if len(categories) > 5:
                        cat_str += f" +{len(categories) - 5} more"
                    details_data.append(["Categories", cat_str])
                
                tags = getattr(ti_data, 'tags', []) or []
                if tags:
                    tags_str = ", ".join(tags[:5])  # Limit to 5
                    if len(tags) > 5:
                        tags_str += f" +{len(tags) - 5} more"
                    details_data.append(["Tags", tags_str])
                
                # Add entity-specific details
                if entity.type == "ip" and isinstance(vt_data, dict):
                    if "country" in vt_data:
                        details_data.append(["Country", vt_data.get("country", "Unknown")])
                    if "asn" in vt_data and "as_owner" in vt_data:
                        details_data.append(["ASN", f"{vt_data.get('asn', '')} ({vt_data.get('as_owner', '')})"])
                
                if entity.type == "domain" and isinstance(vt_data, dict):
                    if "registrar" in vt_data:
                        details_data.append(["Registrar", vt_data.get("registrar", "Unknown")])
                
                if not details_data:
                    details_data.append(["No details", "No additional details available"])
                
                details_table = Table(details_data, colWidths=[1.5*inch, 4.5*inch])
                details_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                    ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ]))
                
                story.append(details_table)
                
                # Add separator between entities
                if i < len(verdicts["malicious"][:10]) - 1:
                    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey, spaceBefore=8, spaceAfter=8))
            
            # If more malicious entities, add a note
            if len(verdicts["malicious"]) > 10:
                story.append(Paragraph(f"... and {len(verdicts['malicious']) - 10} more malicious entities", styles["Normal"]))
            
            story.append(Spacer(1, 0.2*inch))
        
        # Suspicious entities (summarized) with thorough null checks
        if verdicts["suspicious"]:
            story.append(Paragraph("Suspicious Entities", styles["Heading2"]))
            story.append(Spacer(1, 0.1*inch))
            
            # Create summary table
            suspicious_data = [["Type", "Value", "Risk Score", "Summary"]]
            
            # Sort by risk score
            def get_risk_score(item):
                entity, ti_data = item
                if hasattr(ti_data, 'risk_score'):
                    return ti_data.risk_score
                return 0
            
            verdicts["suspicious"].sort(key=get_risk_score, reverse=True)
            
            for entity, ti_data in verdicts["suspicious"][:15]:  # Limit to 15
                if not hasattr(entity, 'type') or not hasattr(entity, 'value'):
                    continue
                
                # Get risk score safely
                risk_score = 0
                if hasattr(ti_data, 'risk_score'):
                    risk_score = ti_data.risk_score
                
                # Get summary safely
                summary = "No summary available"
                if hasattr(ti_data, 'summary'):
                    summary = ti_data.summary
                
                if len(summary) > 60:
                    summary = summary[:57] + "..."
                
                suspicious_data.append([
                    entity.type.capitalize(),
                    entity.value,
                    f"{risk_score:.2f}",
                    summary
                ])
            
            if len(suspicious_data) == 1:
                suspicious_data.append(["N/A", "N/A", "N/A", "N/A"])
                
            suspicious_table = Table(suspicious_data, colWidths=[0.8*inch, 1.7*inch, 0.8*inch, 2.7*inch])
            suspicious_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('ALIGN', (2, 0), (2, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            story.append(suspicious_table)
            
            # If more suspicious entities, add a note
            if len(verdicts["suspicious"]) > 15:
                story.append(Paragraph(f"... and {len(verdicts['suspicious']) - 15} more suspicious entities", styles["Normal"]))
    
    def _add_timeline(
        self, 
        story: List, 
        session: Session, 
        styles
    ) -> None:
        """
        Add timeline section
        
        Args:
            story: Report story to add elements to
            session: Analysis session
            styles: Document styles
        """
        story.append(Paragraph("6. Event Timeline", styles["Heading1"]))
        story.append(Spacer(1, 0.2*inch))
        
        # Get timeline events
        events = getattr(session, 'timeline_events', []) or []
        
        if events:
            # Sort by timestamp
            events.sort(key=lambda x: x.get("timestamp", datetime.min))
            
            # Create table for key events
            key_data = [["Time", "Event Type", "Description"]]
            
            for event in events[:20]:  # Limit to 20
                timestamp = event.get("timestamp")
                time_str = self._safe_format_timestamp(timestamp)
                
                event_type = event.get("type", "unknown").replace("_", " ").title()
                
                # Format by severity if available
                if "severity" in event:
                    severity = event.get("severity", "unknown")
                    if severity == "high":
                        event_type = f"[HIGH] {event_type}"
                    elif severity == "medium":
                        event_type = f"[MED] {event_type}"
                
                description = event.get("description", "No description")
                if len(description) > 60:
                    description = description[:57] + "..."
                
                key_data.append([time_str, event_type, description])
        
        if key_data == [["Time", "Event Type", "Description"]]:
            story.append(Paragraph("No key events identified.", styles["Normal"]))
        else:
            key_table = Table(key_data, colWidths=[1.5*inch, 1.5*inch, 3*inch])
            key_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            story.append(key_table)
            
            if len(key_data) > 20:
                story.append(Paragraph(f"... and {len(key_data) - 20} more key events", styles["Normal"]))
        
        story.append(Spacer(1, 0.2*inch))
        
        # Timeline overview
        story.append(Paragraph("Timeline Overview", styles["Heading2"]))
        story.append(Spacer(1, 0.1*inch))
        
        # Create timeline with event counts per period
        try:
            # Count events per hour with thorough null checks
            event_times = []
            for event in events:
                timestamp = event.get("timestamp")
                dt = self._ensure_datetime(timestamp)
                if dt:
                    event_times.append(dt)
            
            if event_times:
                # Create histogram - FIX: Increased figure size and margins
                plt.figure(figsize=(9, 4))
                plt.hist(event_times, bins=20, alpha=0.7, color='green')
                plt.xlabel('Time')
                plt.ylabel('Event Count')
                plt.title('Timeline Event Distribution')
                
                # Rotate labels to avoid overlapping
                plt.xticks(rotation=45)
                
                # Add more padding for tight layout
                plt.tight_layout(pad=3.0)
                
                # Save to buffer with extra space around the plot
                img_buffer = io.BytesIO()
                plt.savefig(img_buffer, format='png', bbox_inches='tight')
                img_buffer.seek(0)
                plt.close()
                
                # Add to story
                img = Image(img_buffer, width=6*inch, height=3*inch)
                story.append(img)
                
                story.append(Spacer(1, 0.1*inch))
                
                # Add timeline range text
                if event_times:
                    start_time = min(event_times)
                    end_time = max(event_times)
                    duration = (end_time - start_time).total_seconds()
                    
                    range_text = (f"Timeline spans from {start_time.strftime('%Y-%m-%d %H:%M:%S')} "
                                f"to {end_time.strftime('%Y-%m-%d %H:%M:%S')} "
                                f"({self._format_duration(duration)})")
                    
                    story.append(Paragraph(range_text, styles["Normal"]))
            else:
                story.append(Paragraph("No timeline events with valid timestamps available for distribution chart.", styles["Normal"]))
        except Exception as e:
            self.logger.error(f"Error creating timeline chart: {str(e)}")
            story.append(Paragraph(f"Error creating timeline chart: {str(e)}", styles["Normal"]))
    
    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human-readable string"""
        try:
            if bytes_value < 1024:
                return f"{bytes_value} B"
            elif bytes_value < 1024 * 1024:
                return f"{bytes_value / 1024:.2f} KB"
            elif bytes_value < 1024 * 1024 * 1024:
                return f"{bytes_value / (1024 * 1024):.2f} MB"
            else:
                return f"{bytes_value / (1024 * 1024 * 1024):.2f} GB"
        except (TypeError, ValueError):
            return str(bytes_value)
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in seconds to human-readable string"""
        try:
            if seconds < 60:
                return f"{seconds:.1f} seconds"
            elif seconds < 3600:
                minutes = seconds / 60
                return f"{minutes:.1f} minutes"
            elif seconds < 86400:
                hours = seconds / 3600
                return f"{hours:.1f} hours"
            else:
                days = seconds / 86400
                return f"{days:.1f} days"
        except (TypeError, ValueError):
            return str(seconds)
    
    def _threat_level_value(self, level: str) -> int:
        """Convert threat level to numeric value for sorting"""
        levels = {
            "malicious": 3,
            "suspicious": 2,
            "unknown": 1,
            "safe": 0
        }
        return levels.get(level, 0)
    
    def _severity_value(self, severity: str) -> int:
        """Convert severity level to numeric value for sorting"""
        levels = {
            "high": 3,
            "medium": 2,
            "low": 1,
            "unknown": 0
        }
        return levels.get(severity, 0)
    
    def _safe_format_timestamp(self, timestamp) -> str:
        """Safely format a timestamp that could be string or datetime"""
        if timestamp is None:
            return "Unknown"
        if isinstance(timestamp, datetime):
            return timestamp.strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(timestamp, str):
            try:
                # Try to parse ISO format string
                dt = datetime.fromisoformat(timestamp)
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                return str(timestamp)
        return str(timestamp)
    
    def _ensure_datetime(self, value):
        """Преобразует строку или datetime в datetime. Если не удается — возвращает None."""
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value)
            except Exception:
                pass
        return None