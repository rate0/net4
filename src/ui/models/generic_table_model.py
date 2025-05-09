from PyQt6.QtCore import Qt, QAbstractTableModel, QModelIndex, QVariant
from typing import List, Dict, Any


class GenericTableModel(QAbstractTableModel):
    """Lightweight table model to display list-of-dict data efficiently."""

    def __init__(self, headers: List[str], data: List[Dict[str, Any]] = None, parent=None):
        super().__init__(parent)
        self._headers = headers
        self._data = data or []

    # Qt API implementations
    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._data)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._headers)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return QVariant()
        row = self._data[index.row()]
        key = self._headers[index.column()]

        # Display role - primary text representation
        if role == Qt.ItemDataRole.DisplayRole:
            return str(row.get(key, ""))

        # Background role – apply simple conditional formatting for numeric 'Relevance' column
        if role == Qt.ItemDataRole.BackgroundRole and key.lower() in {"relevance", "score"}:
            try:
                value = float(row.get(key, 0))
                from PyQt6.QtGui import QColor
                if value >= 0.7:
                    return QColor("#2e7d32")  # green-ish
                elif value >= 0.4:
                    return QColor("#f9a825")  # amber-ish
                else:
                    return QColor("#616161")  # grey-ish
            except (ValueError, TypeError):
                pass  # non-numeric, ignore

        return QVariant()

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self._headers[section]
        return QVariant()

    # helper to refresh data
    def update(self, data: List[Dict[str, Any]]):
        self.beginResetModel()
        self._data = data
        self.endResetModel() 