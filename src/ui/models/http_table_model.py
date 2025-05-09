from typing import List, Dict, Any
from .generic_table_model import GenericTableModel


class HttpTableModel(GenericTableModel):
    """Table model for HTTP/HTTPS packets."""

    def __init__(self, headers: List[str], data: List[Dict[str, Any]] = None, parent=None):
        super().__init__(headers, data, parent)

    # for now inherits behaviour; can extend later for custom roles 