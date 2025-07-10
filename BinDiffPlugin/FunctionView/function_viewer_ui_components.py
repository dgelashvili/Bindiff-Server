import os

from typing import List, Dict

from binaryninja import log_error
from binaryninja.interaction import show_message_box

try:
    from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout,
                                   QTableWidget, QTableWidgetItem,
                                   QPushButton, QLineEdit, QLabel,
                                   QHeaderView, QAbstractItemView)
    from PySide6.QtCore import Qt, QSortFilterProxyModel
    from PySide6.QtGui import QStandardItemModel, QStandardItem

    IMPORTED = True
except ImportError:
    IMPORTED = False
    log_error("Qt not available for custom UI")


class FunctionTableDialog:
    def __init__(self, bv, functions: List[Dict]):
        self.bv = bv
        self.functions = functions

    def show(self):
        if not IMPORTED:
            return

        try:
            dialog = QDialog()
            dialog.setWindowTitle(f"Functions - File: {os.path.basename(self.bv.file.filename)}")
            dialog.setModal(False)
            dialog.resize(900, 600)

            dialog.setLayout(self._build_layout())

            dialog.show()
            dialog.exec_()

        except Exception as e:
            show_message_box("Error", f"Error showing Qt dialog: {e}")

    def _build_layout(self):
        layout = QVBoxLayout()

        search_layout, search_box = self._build_search_box()
        layout.addLayout(search_layout)

        table = self._build_function_table()
        layout.addWidget(table)

        self._setup_listeners(table, search_box)

        return layout

    def _build_search_box(self):
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Search:"))

        search_box = QLineEdit()
        search_box.setPlaceholderText("Filter by function name prefix")
        search_layout.addWidget(search_box)

        return search_layout, search_box

    def _build_function_table(self):
        table = QTableWidget()
        table.setColumnCount(2)
        table.setHorizontalHeaderLabels(["Address", "Function Name"])
        table.setRowCount(len(self.functions))

        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setAlternatingRowColors(True)
        table.setSortingEnabled(True)

        for row, func in enumerate(self.functions):
            addr_item = QTableWidgetItem(f"0x{func['address']:08x}")
            addr_item.setData(Qt.UserRole, func['address'])
            table.setItem(row, 0, addr_item)

            name_item = QTableWidgetItem(func['name'])
            table.setItem(row, 1, name_item)

        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)

        return table

    def _setup_listeners(self, table, search_box):
        table.cellDoubleClicked.connect(lambda row, col: self._on_address_clicked(row, table))
        search_box.textChanged.connect(lambda text: self._filter_table(text, table))

    def _on_address_clicked(self, row, table):
        try:
            addr_item = table.item(row, 0)
            if addr_item:
                address = addr_item.data(Qt.UserRole)
                self.bv.navigate(self.bv.view, address)

        except Exception as e:
            show_message_box("Error", f"Could not navigate to address: {e}")

    def _filter_table(self, search_text, table):
        try:
            search_text = search_text.lower()

            for row in range(table.rowCount()):
                name_item = table.item(row, 1)
                if name_item:
                    function_name = name_item.text().lower()
                    table.setRowHidden(row, not function_name.startswith(search_text))

        except Exception as e:
            show_message_box("Error", f"Error filtering table: {e}")
