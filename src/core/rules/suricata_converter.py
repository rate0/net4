import re
import os
import uuid
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

from .rule_engine import Rule
from ...utils.logger import Logger


class SuricataRuleConverter:
    """
    Converter for Suricata/Snort rules to Net4 rule format.
    """
    
    def __init__(self):
        """Initialize converter"""
        self.logger = Logger().get_logger()
        
        # Define regex patterns for parsing Suricata rules
        self._rule_pattern = re.compile(
            r'^(?P<action>[a-z]+)\s+'                    # Action (alert, drop, etc.)
            r'(?P<protocol>[a-z]+)\s+'                   # Protocol
            r'(?P<src_ip>[^:]+):?(?P<src_port>[^\s]*)\s+' # Src IP:port
            r'(?P<direction>->|<>|<-)\s+'               # Direction
            r'(?P<dst_ip>[^:]+):?(?P<dst_port>[^\s]*)\s+' # Dst IP:port
            r'\(\s*(?P<options>.*)\s*\)'                # Options in parentheses
        )
        
        # Mapping from Suricata options to Net4 conditions
        self._option_mappings = {
            'msg': 'name',
            'classtype': 'category',
            'sid': 'id'
        }
        
        # Mapping from Suricata severities to Net4 severities
        self._severity_mapping = {
            'low': 'low',
            'medium': 'medium',
            'high': 'high',
            'critical': 'high',
            '1': 'low',
            '2': 'low',
            '3': 'medium',
            '4': 'high',
            'informational': 'low',
            'warning': 'medium',
            'alert': 'high'
        }
        
        # Mapping from classtype to category and severity
        self._classtype_mapping = {
            'attempted-admin': {'category': 'admin', 'severity': 'high'},
            'attempted-user': {'category': 'admin', 'severity': 'medium'},
            'inappropriate-content': {'category': 'policy', 'severity': 'low'},
            'policy-violation': {'category': 'policy', 'severity': 'low'},
            'shellcode-detect': {'category': 'malware', 'severity': 'high'},
            'successful-admin': {'category': 'admin', 'severity': 'high'},
            'successful-user': {'category': 'admin', 'severity': 'medium'},
            'trojan-activity': {'category': 'malware', 'severity': 'high'},
            'unsuccessful-user': {'category': 'admin', 'severity': 'low'},
            'web-application-attack': {'category': 'web', 'severity': 'high'},
            'network-scan': {'category': 'reconnaissance', 'severity': 'medium'},
            'protocol-command-decode': {'category': 'protocol', 'severity': 'medium'},
            'string-detect': {'category': 'detection', 'severity': 'medium'}
        }
    
    def parse_rule_file(self, file_path: str) -> List[Rule]:
        """
        Parse Suricata/Snort rules file and convert to Net4 rules
        
        Args:
            file_path: Path to rules file
            
        Returns:
            List of converted rules
        """
        rules = []
        
        try:
            with open(file_path, 'r') as f:
                line_num = 0
                for line in f:
                    line_num += 1
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    
                    try:
                        rule = self.parse_rule(line)
                        if rule:
                            rules.append(rule)
                    except Exception as e:
                        self.logger.warning(f"Error parsing rule on line {line_num}: {e}")
            
            self.logger.info(f"Converted {len(rules)} rules from {file_path}")
            return rules
        
        except Exception as e:
            self.logger.error(f"Error reading rules file {file_path}: {e}")
            return []
    
    def parse_rule(self, rule_text: str) -> Optional[Rule]:
        """
        Parse a single Suricata/Snort rule and convert to a Net4 rule
        
        Args:
            rule_text: Rule text
            
        Returns:
            Converted rule or None if parsing failed
        """
        match = self._rule_pattern.match(rule_text)
        if not match:
            self.logger.warning(f"Rule format not recognized: {rule_text[:80]}...")
            return None
        
        parts = match.groupdict()
        options_text = parts['options']
        
        # Parse options
        options = self._parse_options(options_text)
        
        # Generate rule ID
        rule_id = options.get('sid', f"converted:{uuid.uuid4().hex[:8]}")
        if not rule_id.startswith(('suricata:', 'snort:')):
            rule_id = f"suricata:{rule_id}"
        
        # Get rule name
        name = options.get('msg', 'Converted Suricata Rule')
        
        # Extract content patterns for the description
        content_patterns = self._extract_content_patterns(options_text)
        description = name
        if content_patterns:
            description = f"{name} - Patterns: {', '.join(content_patterns)}"
        
        # Determine severity
        severity = 'medium'  # Default
        if 'severity' in options:
            severity = self._severity_mapping.get(options['severity'].lower(), 'medium')
        elif 'priority' in options:
            severity = self._severity_mapping.get(options['priority'], 'medium')
        elif 'classtype' in options and options['classtype'] in self._classtype_mapping:
            severity = self._classtype_mapping[options['classtype']]['severity']
        
        # Determine category
        category = 'custom'  # Default
        if 'classtype' in options:
            if options['classtype'] in self._classtype_mapping:
                category = self._classtype_mapping[options['classtype']]['category']
            else:
                category = options['classtype']
        
        # Extract tags
        tags = []
        if 'tag' in options:
            tags.extend([tag.strip() for tag in options['tag'].split(',')])
        if category:
            tags.append(category)
        
        # Build conditions
        conditions = self._build_conditions(parts, options)
        
        # Build actions
        actions = self._build_actions(parts['action'], options)
        
        # Create Net4 rule
        return Rule(
            rule_id=rule_id,
            name=name,
            description=description,
            severity=severity,
            conditions=conditions,
            actions=actions,
            enabled=True,
            category=category,
            tags=tags
        )
    
    def _parse_options(self, options_text: str) -> Dict[str, str]:
        """
        Parse rule options
        
        Args:
            options_text: Options part of the rule
            
        Returns:
            Dictionary of options
        """
        options = {}
        current_key = None
        current_value = ""
        in_quotes = False
        escape_next = False
        
        i = 0
        while i < len(options_text):
            char = options_text[i]
            
            # Handle escaping
            if escape_next:
                current_value += char
                escape_next = False
            elif char == '\\':
                escape_next = True
            # Handle quotes
            elif char == '"':
                in_quotes = not in_quotes
                current_value += char
            # Handle semicolon (delimiter) when not in quotes
            elif char == ';' and not in_quotes:
                if current_key is not None:
                    options[current_key] = current_value.strip()
                current_key = None
                current_value = ""
            # Handle colon (key-value separator) when not in quotes and no key yet
            elif char == ':' and not in_quotes and current_key is None:
                current_key = current_value.strip()
                current_value = ""
            # Otherwise add to current value
            else:
                current_value += char
            
            i += 1
        
        # Add last option if any
        if current_key is not None:
            options[current_key] = current_value.strip()
        
        return options
    
    def _extract_content_patterns(self, options_text: str) -> List[str]:
        """
        Extract content patterns from rule options
        
        Args:
            options_text: Options part of the rule
            
        Returns:
            List of content patterns
        """
        patterns = []
        
        # Find all "content:" options
        content_pattern = re.compile(r'content\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"')
        matches = content_pattern.finditer(options_text)
        
        for match in matches:
            content = match.group(1)
            # Unescape common escape sequences
            content = content.replace('\\r', '\r').replace('\\n', '\n').replace('\\t', '\t')
            content = content.replace('\\"', '"').replace('\\\\', '\\')
            patterns.append(content)
        
        return patterns
    
    def _build_conditions(self, parts: Dict[str, str], options: Dict[str, str]) -> Dict[str, Any]:
        """
        Build conditions for Net4 rule
        
        Args:
            parts: Rule parts from regex match
            options: Parsed options
            
        Returns:
            Conditions dictionary
        """
        conditions = {}
        
        # Add protocol
        protocol = parts['protocol'].upper()
        if protocol != 'ANY':
            conditions['protocol'] = protocol
        
        # Add source and destination IP and port
        if parts['src_ip'] and parts['src_ip'] != 'any':
            if parts['src_ip'].find('/') != -1:  # CIDR notation
                conditions['src_ip'] = {'ip_in_subnet': parts['src_ip']}
            else:
                conditions['src_ip'] = parts['src_ip']
        
        if parts['dst_ip'] and parts['dst_ip'] != 'any':
            if parts['dst_ip'].find('/') != -1:  # CIDR notation
                conditions['dst_ip'] = {'ip_in_subnet': parts['dst_ip']}
            else:
                conditions['dst_ip'] = parts['dst_ip']
        
        if parts['src_port'] and parts['src_port'] != 'any':
            try:
                conditions['src_port'] = int(parts['src_port'])
            except ValueError:
                # Handle port ranges like "1024:65535"
                if ':' in parts['src_port']:
                    start, end = parts['src_port'].split(':')
                    try:
                        conditions['src_port'] = {'gte': int(start), 'lte': int(end)}
                    except ValueError:
                        pass
        
        if parts['dst_port'] and parts['dst_port'] != 'any':
            try:
                conditions['dst_port'] = int(parts['dst_port'])
            except ValueError:
                # Handle port ranges like "1024:65535"
                if ':' in parts['dst_port']:
                    start, end = parts['dst_port'].split(':')
                    try:
                        conditions['dst_port'] = {'gte': int(start), 'lte': int(end)}
                    except ValueError:
                        pass
        
        # Handle content matches as regex patterns
        content_patterns = self._extract_content_patterns(options)
        if content_patterns:
            # Create regex from content patterns
            patterns = []
            for pattern in content_patterns:
                # Escape regex special chars
                escaped = re.escape(pattern)
                patterns.append(escaped)
            
            # Add to conditions
            if patterns:
                conditions['payload'] = {'regex': '|'.join(patterns)}
        
        # Handle specific HTTP conditions
        if 'http_uri' in options:
            conditions['http.uri'] = {'regex': re.escape(options['http_uri'])}
        
        if 'http_header' in options:
            conditions['http.header'] = {'regex': re.escape(options['http_header'])}
        
        return conditions
    
    def _build_actions(self, action: str, options: Dict[str, str]) -> Dict[str, Any]:
        """
        Build actions for Net4 rule
        
        Args:
            action: Rule action (alert, drop, etc.)
            options: Parsed options
            
        Returns:
            Actions dictionary
        """
        actions = {}
        
        # Add default action based on Suricata action
        if action == 'alert':
            actions['add_entity_tag'] = 'suricata_alert'
            actions['set_threat_level'] = 'suspicious'
        elif action == 'drop':
            actions['add_entity_tag'] = 'suricata_drop'
            actions['set_threat_level'] = 'malicious'
        
        # Add severity-based threat level
        severity = None
        if 'severity' in options:
            severity = options['severity'].lower()
        elif 'priority' in options:
            severity = options['priority']
        elif 'classtype' in options and options['classtype'] in self._classtype_mapping:
            severity = self._classtype_mapping[options['classtype']]['severity']
        
        if severity:
            if severity in ['high', 'critical', '4']:
                actions['set_threat_level'] = 'malicious'
            elif severity in ['medium', '3']:
                actions['set_threat_level'] = 'suspicious'
        
        # Add anomaly
        actions['add_anomaly'] = {
            'type': 'suricata_rule_match',
            'subtype': options.get('classtype', 'unknown')
        }
        
        return actions
    
    def save_rules(self, rules: List[Rule], output_dir: str) -> int:
        """
        Save converted rules to files
        
        Args:
            rules: List of rules to save
            output_dir: Directory to save rules to
            
        Returns:
            Number of rules saved
        """
        os.makedirs(output_dir, exist_ok=True)
        
        saved_count = 0
        for rule in rules:
            try:
                file_path = os.path.join(output_dir, f"{rule.id.replace(':', '_')}.yaml")
                
                # Import here to avoid circular imports
                import yaml
                
                with open(file_path, 'w') as f:
                    yaml.dump(rule.to_dict(), f, default_flow_style=False)
                
                saved_count += 1
                
            except Exception as e:
                self.logger.error(f"Error saving rule {rule.id}: {e}")
        
        return saved_count