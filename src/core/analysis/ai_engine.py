import json
import threading
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime

import openai

from ...models.session import Session
from ...utils.logger import Logger
from ...utils.config import Config


# Custom JSON encoder to handle datetime objects
class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()  # Convert datetime to ISO format string
        return super().default(obj)


# Helper function to recursively convert datetime objects in dictionaries
def convert_datetime_in_dict(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, dict):
        return {k: convert_datetime_in_dict(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_datetime_in_dict(item) for item in obj]
    else:
        return obj


class AIEngine:
    """
    Provides AI-powered analysis of network data using OpenAI API.
    """
    
    def __init__(self, config: Config):
        """
        Initialize AI engine
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.logger = Logger().get_logger()
        
        api_key = self.config.get("api.openai.api_key")
        if api_key:
            self.client = openai.OpenAI(api_key=api_key)
        else:
            self.client = None
            self.logger.warning("OpenAI API key not configured")
        
        # Set default model to gpt-4o (with fallbacks available)
        self.model = self.config.get("api.openai.model", "gpt-4o")
        self.max_tokens = self.config.get("api.openai.max_tokens", 4000)
        self.timeout = self.config.get("api.openai.timeout", 60)
        
        # Define available models in order of preference
        self.available_models = [
            "gpt-4o",        # Best balance of capability and speed
            "o1",            # Advanced Claude model 
            "gpt-4.1-mini",  # Optimized GPT-4.1 model
            "gpt-4o-mini",   # Mini version of GPT-4o
            "o3-mini",       # Mini version of Claude's o3
            "gpt-4.1-nano",  # Smallest GPT-4.1 variant
            "o1-2024-12-17", # Dated version of Claude o1
            "o3-mini-2025-01-31", # Dated version of Claude o3-mini
            "gpt-4o-mini-2024-07-18" # Dated version of GPT-4o mini
        ]
    
    def set_api_key(self, api_key: str) -> None:
        """Set OpenAI API key"""
        self.config.set("api.openai.api_key", api_key)
        self.client = openai.OpenAI(api_key=api_key)
    
    def set_model(self, model: str) -> None:
        """Set OpenAI model to use"""
        self.config.set("api.openai.model", model)
        self.model = model
    
    def analyze_session(
        self, 
        session: Session,
        analysis_type: str = "overview",
        progress_callback: Optional[Callable[[str, float], None]] = None
    ) -> Dict[str, Any]:
        """
        Analyze session data using AI
        
        Args:
            session: Analysis session
            analysis_type: Type of analysis (overview, threats, anomalies, etc.)
            progress_callback: Callback for progress updates
            
        Returns:
            Dict containing analysis results
        """
        if not self.client:
            raise ValueError("OpenAI API key not configured")
        
        if progress_callback:
            progress_callback("Preparing data for AI analysis", 0.1)
        
        # Prepare session data for analysis
        analysis_data = self._prepare_session_data(session, analysis_type)
        
        # Convert datetime objects to strings to avoid JSON serialization issues
        analysis_data = convert_datetime_in_dict(analysis_data)
        
        if progress_callback:
            progress_callback("Sending data to OpenAI API", 0.3)
        
        # Build prompt for analysis
        prompt = self._build_analysis_prompt(analysis_data, analysis_type)
        
        try:
            # Call OpenAI API with smart fallback mechanism through available models
            response = None
            system_prompt = "You are a network forensic analyst assisting with the analysis of network traffic data. Provide detailed technical analysis, identify potential security threats, anomalies, and patterns. Your output should be structured in a clear format."
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
            
            # Try the specified model first
            tried_models = []
            model_to_try = self.model
            
            while response is None:
                if model_to_try in tried_models:
                    # Skip models we've already tried
                    continue
                    
                try:
                    self.logger.info(f"Attempting to use model: {model_to_try}")
                    response = self.client.chat.completions.create(
                        model=model_to_try,
                        messages=messages,
                        max_tokens=self.max_tokens,
                        temperature=0.2
                    )
                    # If successful, break the loop
                    break
                    
                except Exception as api_error:
                    tried_models.append(model_to_try)
                    self.logger.warning(f"Error with model {model_to_try}: {str(api_error)}")
                    
                    # Find the next model to try
                    next_model = None
                    
                    # First look in our preferred models list
                    for m in self.available_models:
                        if m not in tried_models:
                            next_model = m
                            break
                    
                    # If we've tried all preferred models, fall back to gpt-3.5-turbo as last resort
                    if next_model is None:
                        if "gpt-3.5-turbo" not in tried_models:
                            next_model = "gpt-3.5-turbo"
                        else:
                            # We've tried everything, give up
                            raise Exception("All available models failed to respond")
                    
                    model_to_try = next_model
                    self.logger.info(f"Falling back to model: {model_to_try}")
            
            # Log which model was ultimately used
            self.logger.info(f"Successfully used model: {model_to_try}")
            
            if progress_callback:
                progress_callback("Processing AI response", 0.7)
            
            # Parse response - FIXED: Handle non-JSON responses
            content = response.choices[0].message.content
            
            # Try to parse as JSON, fall back to text processing if that fails
            try:
                if content.startswith('{') and content.endswith('}'):
                    result = json.loads(content)
                else:
                    # Extract structured data from the text response
                    result = self._extract_structured_data(content, analysis_type)
            except json.JSONDecodeError:
                # Handle non-JSON responses by extracting structured data
                result = self._extract_structured_data(content, analysis_type)
            
            # Add timestamp and metadata
            result["timestamp"] = datetime.now().isoformat()
            result["analysis_type"] = analysis_type
            result["model"] = self.model
            
            # Add to session insights
            session.add_ai_insight(result)
            
            if progress_callback:
                progress_callback("Analysis complete", 1.0)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error calling OpenAI API: {str(e)}")
            if progress_callback:
                progress_callback(f"Error: {str(e)}", 1.0)
            raise
    
    def analyze_session_async(
        self, 
        session: Session,
        analysis_type: str = "overview",
        progress_callback: Optional[Callable[[str, float], None]] = None,
        completion_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> threading.Thread:
        """
        Analyze session data using AI asynchronously
        
        Args:
            session: Analysis session
            analysis_type: Type of analysis
            progress_callback: Callback for progress updates
            completion_callback: Callback when analysis completes
            
        Returns:
            Thread object for the analysis task
        """
        def task():
            try:
                result = self.analyze_session(session, analysis_type, progress_callback)
                # Convert datetime objects to strings for JSON serialization
                result_serializable = convert_datetime_in_dict(result)
                if completion_callback:
                    completion_callback(result_serializable)
            except Exception as e:
                self.logger.error(f"Async AI analysis error: {str(e)}")
                if completion_callback:
                    completion_callback({"error": str(e)})
        
        thread = threading.Thread(target=task, name="AIAnalysisThread")
        thread.daemon = True
        thread.start()
        return thread
    
    def get_network_summary(
        self,
        session: Session
    ) -> Dict[str, Any]:
        """
        Get a concise summary of the network data
        
        Args:
            session: Analysis session
            
        Returns:
            Dict containing summary information
        """
        # First check if we already have an overview analysis
        if hasattr(session, 'ai_insights'):
            for insight in session.ai_insights:
                if insight.get('analysis_type') == 'overview' and ('summary' in insight or 'raw_response' in insight):
                    return {
                        'summary': insight.get('summary', ''),
                        'key_observations': insight.get('key_observations', []),
                        'security_concerns': insight.get('security_concerns', []),
                        'recommended_actions': insight.get('recommended_actions', []),
                        'timestamp': insight.get('timestamp', datetime.now().isoformat())
                    }
        
        # If no existing overview, generate a quick summary from session metadata
        summary_data = {
            'summary': 'Session contains ' + self._generate_basic_summary(session),
            'key_observations': [],
            'security_concerns': [],
            'recommended_actions': [
                'Run AI analysis for detailed insights', 
                'Check entities with suspicious or malicious threat levels'
            ],
            'timestamp': datetime.now().isoformat()
        }
        
        return summary_data
    
    def _generate_basic_summary(self, session: Session) -> str:
        """Generate a basic summary from session data"""
        parts = []
        
        # Packet count
        packet_count = session.metadata.get("packet_count", 0) if hasattr(session, 'metadata') else 0
        if packet_count:
            parts.append(f"{packet_count} packets")
        
        # IP count
        ents_iter = self._iter_entities(session)
        ip_count = len([e for e in ents_iter if getattr(e, 'type', '') == "ip"])
        if ip_count:
            parts.append(f"{ip_count} IP addresses")
        
        # Domain count
        ents_iter = self._iter_entities(session)
        domain_count = len([e for e in ents_iter if getattr(e, 'type', '') == "domain"])
        if domain_count:
            parts.append(f"{domain_count} domains")
        
        # Connection count
        connection_count = len(session.connections) if hasattr(session, 'connections') else 0
        if connection_count:
            parts.append(f"{connection_count} connections")
        
        # Time range
        start_time = session.metadata.get("start_time", "") if hasattr(session, 'metadata') else ""
        end_time = session.metadata.get("end_time", "") if hasattr(session, 'metadata') else ""
        if start_time and end_time:
            parts.append(f"spanning from {start_time} to {end_time}")
        
        if not parts:
            return "no analyzed data yet"
        
        return ", ".join(parts)
    
    def ask_question(
        self, 
        session: Session,
        question: str,
        progress_callback: Optional[Callable[[str, float], None]] = None
    ) -> Dict[str, Any]:
        """
        Ask a specific question about the session data
        
        Args:
            session: Analysis session
            question: User question
            progress_callback: Callback for progress updates
            
        Returns:
            Dict containing AI response
        """
        if not self.client:
            raise ValueError("OpenAI API key not configured")
        
        if progress_callback:
            progress_callback("Preparing context for your question", 0.1)
        
        # Prepare relevant session data
        context_data = self._prepare_question_context(session, question)
        
        # Convert datetime objects to strings for JSON serialization
        context_data = convert_datetime_in_dict(context_data)
        
        if progress_callback:
            progress_callback("Sending question to AI", 0.3)
        
        # Build prompt with question
        prompt = f"""
        # Question
        {question}
        
        # Context Data
        {json.dumps(context_data, indent=2)}
        
        Analyze the provided network data and answer the question. Base your answer only on the provided data.
        Provide a detailed technical answer with evidence from the data.
        Structure your response in a clear, readable format.
        """
        
        try:
            # Call OpenAI API with smart fallback mechanism
            response = None
            system_prompt = "You are a network forensic analyst assisting with questions about network traffic data. Provide detailed technical answers based only on the provided data."
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
            
            # Try the specified model first
            tried_models = []
            model_to_try = self.model
            
            while response is None:
                if model_to_try in tried_models:
                    # Skip models we've already tried
                    continue
                    
                try:
                    self.logger.info(f"Question - Attempting to use model: {model_to_try}")
                    response = self.client.chat.completions.create(
                        model=model_to_try,
                        messages=messages,
                        max_tokens=self.max_tokens,
                        temperature=0.3
                    )
                    # If successful, break the loop
                    break
                    
                except Exception as api_error:
                    tried_models.append(model_to_try)
                    self.logger.warning(f"Question - Error with model {model_to_try}: {str(api_error)}")
                    
                    # Find the next model to try
                    next_model = None
                    
                    # First look in our preferred models list
                    for m in self.available_models:
                        if m not in tried_models:
                            next_model = m
                            break
                    
                    # If we've tried all preferred models, fall back to gpt-3.5-turbo as last resort
                    if next_model is None:
                        if "gpt-3.5-turbo" not in tried_models:
                            next_model = "gpt-3.5-turbo"
                        else:
                            # We've tried everything, give up
                            raise Exception("All available models failed to respond")
                    
                    model_to_try = next_model
                    self.logger.info(f"Question - Falling back to model: {model_to_try}")
            
            # Log which model was ultimately used
            self.logger.info(f"Question - Successfully used model: {model_to_try}")
            
            if progress_callback:
                progress_callback("Processing AI response", 0.7)
            
            # Format response
            answer = response.choices[0].message.content.strip()
            
            result = {
                "question": question,
                "answer": answer,
                "timestamp": datetime.now().isoformat(),
                "model": self.model
            }
            
            # Add to session insights
            session.add_ai_insight({
                "type": "question",
                "question": question,
                "answer": answer,
                "timestamp": datetime.now().isoformat()
            })
            
            if progress_callback:
                progress_callback("Answer ready", 1.0)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error calling OpenAI API for question: {str(e)}")
            if progress_callback:
                progress_callback(f"Error: {str(e)}", 1.0)
            raise
    
    def ask_question_async(
        self, 
        session: Session,
        question: str,
        progress_callback: Optional[Callable[[str, float], None]] = None,
        completion_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> threading.Thread:
        """
        Ask a question asynchronously
        
        Args:
            session: Analysis session
            question: User question
            progress_callback: Callback for progress updates
            completion_callback: Callback when complete
            
        Returns:
            Thread object for the task
        """
        def task():
            try:
                result = self.ask_question(session, question, progress_callback)
                # Convert datetime objects to strings for JSON serialization
                result_serializable = convert_datetime_in_dict(result)
                if completion_callback:
                    completion_callback(result_serializable)
            except Exception as e:
                self.logger.error(f"Async AI question error: {str(e)}")
                if completion_callback:
                    completion_callback({"error": str(e)})
        
        thread = threading.Thread(target=task, name="AIQuestionThread")
        thread.daemon = True
        thread.start()
        return thread
    
    def get_chat_history(
        self,
        session: Session,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Get chat history (questions and answers)
        
        Args:
            session: Analysis session
            limit: Maximum number of entries to return
            
        Returns:
            List of question/answer entries
        """
        if not hasattr(session, 'ai_insights'):
            return []
        
        # Filter insights to only include questions
        questions = [
            insight for insight in session.ai_insights
            if insight.get('type') == 'question'
        ]
        
        # Sort by timestamp (newest first)
        questions.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        # Return limited number
        return questions[:limit]
    
    def _extract_structured_data(self, content: str, analysis_type: str) -> Dict[str, Any]:
        """
        Extract structured data from text response
        
        Args:
            content: Text response from AI
            analysis_type: Type of analysis
            
        Returns:
            Structured data dictionary
        """
        result = {
            "raw_response": content
        }
        
        # Extract data based on analysis type
        if analysis_type == "overview":
            # Try to extract summary
            summary_start = content.find("Summary") if "Summary" in content else content.find("SUMMARY")
            if summary_start >= 0:
                summary_end = content.find("\n\n", summary_start)
                if summary_end >= 0:
                    summary = content[summary_start:summary_end].replace("Summary:", "").replace("SUMMARY:", "").strip()
                    result["summary"] = summary
            
            # Extract key observations
            observations = self._extract_section(content, "Key Observations", "Key Insights")
            if observations:
                result["key_observations"] = self._extract_list_items(observations)
            
            # Extract security concerns
            concerns = self._extract_section(content, "Security Concerns", "Recommended Actions")
            if concerns:
                result["security_concerns"] = self._extract_list_items(concerns)
            
            # Extract recommendations
            recommendations = self._extract_section(content, "Recommended Actions", None)
            if recommendations:
                result["recommended_actions"] = self._extract_list_items(recommendations)
                
        elif analysis_type == "threats":
            # Extract threat summary
            summary = self._extract_section(content, "Threat Summary", "Risk Level")
            if summary:
                result["threat_summary"] = summary.strip()
            
            # Extract risk level
            risk_level = self._extract_section(content, "Risk Level", "Suspicious Entities")
            if risk_level:
                result["risk_level"] = risk_level.strip()
            
            # Extract malicious indicators
            indicators = self._extract_section(content, "Malicious Indicators", "Recommended Actions")
            if indicators:
                result["malicious_indicators"] = self._extract_list_items(indicators)
        
        return result
    
    def _extract_section(self, content: str, section_start: str, section_end: str = None) -> str:
        """
        Extract a section from the content between start and end markers
        
        Args:
            content: Text content
            section_start: Section start marker
            section_end: Section end marker (None for end of content)
            
        Returns:
            Extracted section or empty string
        """
        start_idx = content.find(section_start)
        if start_idx == -1:
            return ""
        
        start_idx += len(section_start)
        
        if section_end:
            end_idx = content.find(section_end, start_idx)
            if end_idx == -1:
                section = content[start_idx:].strip()
            else:
                section = content[start_idx:end_idx].strip()
        else:
            section = content[start_idx:].strip()
        
        return section
    
    def _extract_list_items(self, content: str) -> List[str]:
        """
        Extract list items from content
        
        Args:
            content: Text content with list items
            
        Returns:
            List of extracted items
        """
        items = []
        for line in content.split("\n"):
            line = line.strip()
            if line.startswith("-") or line.startswith("*") or (line and line[0].isdigit() and line[1:3] in [". ", ") "]):
                item = line[line.find(" ")+1:].strip()
                if item:
                    items.append(item)
            elif line and not line.endswith(":"):
                items.append(line)
        return items
    
    def _prepare_session_data(
        self, 
        session: Session,
        analysis_type: str
    ) -> Dict[str, Any]:
        """
        Prepare session data for AI analysis
        
        Args:
            session: Analysis session
            analysis_type: Type of analysis
            
        Returns:
            Dict containing processed data for analysis
        """
        # Basic metadata
        data = {
            "metadata": {
                "session_name": session.name,
                "created_at": session.created_at.isoformat() if session.created_at else None,
                "file_count": len(session.files) if hasattr(session, 'files') else 0,
                "packet_count": session.metadata.get("packet_count", 0) if hasattr(session, 'metadata') else 0,
                "start_time": session.metadata.get("start_time", "") if hasattr(session, 'metadata') else "",
                "end_time": session.metadata.get("end_time", "") if hasattr(session, 'metadata') else "",
                "duration": session.metadata.get("duration", 0) if hasattr(session, 'metadata') else 0,
                "protocols": list(session.metadata.get("protocols", [])) if hasattr(session, 'metadata') else [],
            },
            "analysis_type": analysis_type
        }
        
        # Add relevant data based on analysis type
        if analysis_type == "overview":
            # General overview - include summary stats
            if hasattr(session, 'files'):
                data["files"] = list(session.files.values())[:5]  # Limit to first 5
            
            # Include network stats
            ents_iter = self._iter_entities(session)
            ip_count = len([e for e in ents_iter if getattr(e, 'type', '') == "ip"])
            ents_iter = self._iter_entities(session)
            domain_count = len([e for e in ents_iter if getattr(e, 'type', '') == "domain"])
            
            data["network_stats"] = {
                "connection_count": len(session.connections) if hasattr(session, 'connections') else 0,
                "ip_count": ip_count,
                "domain_count": domain_count,
                "connection_sample": session.connections[:20] if hasattr(session, 'connections') and len(session.connections) > 0 else []
            }
            
            # Include timeline summary
            if hasattr(session, 'timeline_events') and session.timeline_events:
                data["timeline_summary"] = {
                    "event_count": len(session.timeline_events),
                    "first_event": session.timeline_events[0] if len(session.timeline_events) > 0 else None,
                    "last_event": session.timeline_events[-1] if len(session.timeline_events) > 0 else None,
                }
            
        elif analysis_type == "threats":
            # Focus on potential threats
            if hasattr(session, 'network_entities'):
                suspicious_entities = [
                    e.to_dict() for e in self._iter_entities(session)
                    if e.threat_level in ["suspicious", "malicious"]
                ]
                
                data["threat_data"] = {
                    "suspicious_entities": suspicious_entities,
                    "threat_intelligence": {k: v.to_dict() for k, v in session.threat_intelligence.items()} if hasattr(session, 'threat_intelligence') else {},
                    "ip_sample": [
                        e.to_dict() for e in list(self._iter_entities(session))[:50]
                        if e.type == "ip"
                    ],
                    "domain_sample": [
                        e.to_dict() for e in list(self._iter_entities(session))[:50]
                        if e.type == "domain"
                    ],
                    "connection_sample": session.connections[:50] if hasattr(session, 'connections') and len(session.connections) > 0 else []
                }
            
        elif analysis_type == "anomalies":
            # Focus on anomalies
            data["anomaly_data"] = {
                "detected_anomalies": session.anomalies if hasattr(session, 'anomalies') else {},
                "connection_sample": session.connections[:100] if hasattr(session, 'connections') and len(session.connections) > 0 else [],
                "packet_sample": list(session.packets.values())[:100] if hasattr(session, 'packets') and session.packets else [],
                "timeline_sample": session.timeline_events[:100] if hasattr(session, 'timeline_events') and session.timeline_events else []
            }
            
        elif analysis_type == "traffic_patterns":
            # Focus on traffic patterns
            data["traffic_data"] = {
                "connection_sample": session.connections[:200] if hasattr(session, 'connections') and len(session.connections) > 0 else [],
                "protocol_distribution": session.metadata.get("protocols", []) if hasattr(session, 'metadata') else [],
                "network_entities": [
                    e.to_dict() for e in list(self._iter_entities(session))[:100]
                ] if hasattr(session, 'network_entities') else []
            }
        
        return data
    
    def _prepare_question_context(
        self, 
        session: Session,
        question: str
    ) -> Dict[str, Any]:
        """
        Prepare relevant context data for a specific question
        
        Args:
            session: Analysis session
            question: User question
            
        Returns:
            Dict containing context data relevant to the question
        """
        # Basic metadata
        context = {
            "metadata": {
                "session_name": session.name,
                "created_at": session.created_at.isoformat() if session.created_at else None,
                "file_count": len(session.files) if hasattr(session, 'files') else 0,
                "packet_count": session.metadata.get("packet_count", 0) if hasattr(session, 'metadata') else 0,
                "start_time": session.metadata.get("start_time", "") if hasattr(session, 'metadata') else "",
                "end_time": session.metadata.get("end_time", "") if hasattr(session, 'metadata') else "",
                "duration": session.metadata.get("duration", 0) if hasattr(session, 'metadata') else 0,
                "protocols": list(session.metadata.get("protocols", [])) if hasattr(session, 'metadata') else [],
            },
            "question": question
        }
        
        # Check for keywords to determine relevant data
        question_lower = question.lower()
        
        # Add IP-related data
        if any(kw in question_lower for kw in ["ip", "address", "host", "source", "destination"]):
            # Look for specific IP mentioned in question
            import re
            ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
            ip_matches = ip_pattern.findall(question)
            
            if ip_matches and hasattr(session, 'network_entities'):
                # Find specific information about mentioned IPs
                mentioned_ips = []
                for ip in ip_matches:
                    for entity in self._iter_entities(session):
                        if entity.type == "ip" and entity.value == ip:
                            mentioned_ips.append(entity.to_dict())
                            # Add connections involving this IP
                            if hasattr(session, 'connections'):
                                related_connections = [
                                    conn for conn in session.connections
                                    if conn["src_ip"] == ip or conn["dst_ip"] == ip
                                ][:50]  # Limit to 50
                                context["ip_connections"] = related_connections
                
                if mentioned_ips:
                    context["mentioned_ips"] = mentioned_ips
            elif hasattr(session, 'network_entities'):
                # No specific IPs mentioned, include sample of IPs
                ip_entities = [
                    e.to_dict() for e in list(self._iter_entities(session))[:50]
                    if e.type == "ip"
                ]
                context["ip_sample"] = ip_entities
        
        # Add domain-related data
        if any(kw in question_lower for kw in ["domain", "dns", "web", "site", "url"]) and hasattr(session, 'network_entities'):
            domain_entities = [
                e.to_dict() for e in list(self._iter_entities(session))[:50]
                if e.type == "domain"
            ]
            context["domain_sample"] = domain_entities
        
        # Add traffic-related data
        if any(kw in question_lower for kw in ["traffic", "connection", "flow", "communication"]) and hasattr(session, 'connections'):
            context["connections"] = session.connections[:100]
        
        # Add threat-related data
        if any(kw in question_lower for kw in ["threat", "malicious", "suspicious", "attack", "compromise"]) and hasattr(session, 'network_entities'):
            suspicious_entities = [
                e.to_dict() for e in self._iter_entities(session)
                if e.threat_level in ["suspicious", "malicious"]
            ]
            threat_data = {
                "suspicious_entities": suspicious_entities,
            }
            
            if hasattr(session, 'threat_intelligence'):
                threat_data["threat_intelligence"] = {k: v.to_dict() for k, v in session.threat_intelligence.items()}
                
            context["threat_data"] = threat_data
        
        # Add timeline data
        if any(kw in question_lower for kw in ["time", "when", "timeline", "event"]) and hasattr(session, 'timeline_events'):
            context["timeline"] = session.timeline_events[:100]
        
        # Add packet data
        if any(kw in question_lower for kw in ["packet", "payload", "data"]) and hasattr(session, 'packets'):
            context["packets"] = list(session.packets.values())[:50]
        
        return context
    
    def _build_analysis_prompt(
        self, 
        data: Dict[str, Any],
        analysis_type: str
    ) -> str:
        """
        Build prompt for AI analysis
        
        Args:
            data: Prepared session data
            analysis_type: Type of analysis
            
        Returns:
            Formatted prompt string
        """
        prompts = {
            "overview": """
                Analyze the provided network data and create a comprehensive overview of the traffic.
                
                Include the following in your analysis:
                1. Summary of the network traffic
                2. Key observations about the traffic patterns
                3. Identified network protocols and their distribution
                4. Notable network entities and their activities
                5. Any potential security concerns or anomalies
                
                Your response should be structured with clear section headings for:
                - Summary
                - Key Observations
                - Protocol Analysis
                - Notable Entities
                - Security Concerns
                - Recommended Actions
            """,
            
            "threats": """
                Analyze the provided network data for potential security threats and malicious activities.
                
                Include the following in your analysis:
                1. Identified suspicious or malicious entities
                2. Suspicious network connections or communications
                3. Potentially malicious traffic patterns
                4. Threat assessment and risk level
                5. Evidence supporting your findings
                
                Your response should be structured with clear section headings for:
                - Threat Summary
                - Risk Level
                - Suspicious Entities
                - Suspicious Connections 
                - Malicious Indicators
                - Recommended Actions
            """,
            
            "anomalies": """
                Analyze the provided network data for anomalies and unusual patterns.
                
                Include the following in your analysis:
                1. Identified anomalies and deviations from normal patterns
                2. Unusual traffic spikes or drops
                3. Irregular connection attempts or communications
                4. Statistical outliers in the network behavior
                5. Potential causes for the anomalies
                
                Your response should be structured with clear section headings for:
                - Anomaly Summary
                - Detected Anomalies
                - Traffic Irregularities
                - Outlier Analysis
                - Potential Causes
                - Recommended Actions
            """,
            
            "traffic_patterns": """
                Analyze the provided network data to identify and describe traffic patterns.
                
                Include the following in your analysis:
                1. Overall traffic flow patterns
                2. Common communication paths
                3. Frequency and timing of connections
                4. Protocol usage patterns
                5. Source and destination distribution
                
                Your response should be structured with clear section headings for:
                - Pattern Summary
                - Common Paths
                - Timing Analysis
                - Protocol Distribution
                - Network Hotspots
                - Data Flow Characteristics
            """
        }
        
        # Get prompt for requested analysis type, or use overview if not found
        prompt_template = prompts.get(analysis_type, prompts["overview"])
        
        # Build final prompt with serialized data using our custom encoder
        final_prompt = f"""
        # Network Forensic Analysis Request
        Analysis Type: {analysis_type}
        
        # Network Data
        {json.dumps(data, indent=2, cls=DateTimeEncoder)}
        
        {prompt_template}
        """
        
        return final_prompt

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _iter_entities(session: 'Session'):
        """Return an iterable over NetworkEntity objects regardless of how they are stored."""
        ents = getattr(session, 'network_entities', {})
        if isinstance(ents, dict):
            return ents.values()
        # Fallback if list-like
        return ents or []