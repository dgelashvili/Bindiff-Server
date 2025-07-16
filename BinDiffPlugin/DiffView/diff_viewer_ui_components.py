import os

from typing import List, Dict, Tuple

from binaryninja import log_error
from binaryninja.interaction import show_message_box

try:
    from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout,
                                   QTableWidget, QTableWidgetItem,
                                   QLineEdit, QLabel, QGridLayout,
                                   QHeaderView, QAbstractItemView,
                                   QListWidget, QListWidgetItem,
                                   QStackedWidget, QWidget, QSplitter,
                                   QFrame, QScrollArea, QProgressBar)
    from PySide6.QtCore import Qt, QSortFilterProxyModel, QRect
    from PySide6.QtGui import QStandardItemModel, QStandardItem, QFont, QColor, QPainter, QPen, QBrush

    IMPORTED = True
except ImportError:
    IMPORTED = False
    log_error("Qt not available for custom UI")


def _get_bg_color(number):
    if number < 0.5:
        factor = number * 2
        return QColor(200, int(factor * 200), 50)
    else:
        factor = (number - 0.5) * 2
        return QColor(int((1 - factor) * 200), 200, 50)


def _get_title(title_text):
    title = QLabel(title_text)
    font = QFont()
    font.setBold(True)
    font.setPointSize(12)
    title.setFont(font)

    return title


def _build_search_box():
    search_layout = QHBoxLayout()
    search_layout.addWidget(QLabel("Search:"))

    search_box = QLineEdit()
    search_box.setPlaceholderText("Filter by function name prefix")
    search_layout.addWidget(search_box)

    return search_layout, search_box


class DiffResultDialog:
    def __init__(self, primary_bv, secondary_bv, diff_result: Tuple[List[Dict], List[Dict], List[Dict]]):
        self.primary_bv = primary_bv
        self.primary_filename = os.path.basename(self.primary_bv.file.filename)
        self.secondary_bv = secondary_bv
        self.secondary_filename = os.path.basename(self.secondary_bv.file.filename)
        self.matches, self.unmatched_primary, self.unmatched_secondary = diff_result

    def show(self):
        if not IMPORTED:
            return

        try:
            dialog = QDialog()
            dialog.setWindowTitle(f"Diff Results - {self.primary_filename} vs {self.secondary_filename}")
            dialog.setModal(False)
            dialog.resize(1250, 800)

            dialog.setLayout(self._build_main_layout())

            dialog.show()
            dialog.exec_()

        except Exception as e:
            show_message_box("Error", f"Error showing Qt dialog: {e}")

    def _build_main_layout(self):
        main_layout = QHBoxLayout()

        splitter = QSplitter(Qt.Horizontal)

        splitter.addWidget(self._build_sidebar())

        self.content_stack = QStackedWidget()
        self._build_content_views()
        splitter.addWidget(self.content_stack)

        splitter.setSizes([250, 1000])
        splitter.setStretchFactor(1, 1)

        main_layout.addWidget(splitter)

        return main_layout

    def _build_sidebar(self):
        sidebar_frame = QFrame()
        sidebar_frame.setFrameStyle(QFrame.StyledPanel)
        sidebar_frame.setMaximumWidth(250)

        layout = QVBoxLayout()
        layout.addWidget(_get_title("Options"))

        self.options_list = QListWidget()
        options = [
            "Overview",
            f"Matched Functions ({len(self.matches)})",
            f"Primary Unmatched ({len(self.unmatched_primary)})",
            f"Secondary Unmatched ({len(self.unmatched_secondary)})"
        ]
        for item_text in options:
            item = QListWidgetItem(item_text)
            self.options_list.addItem(QListWidgetItem(""))
            self.options_list.addItem(item)

        self.options_list.setCurrentRow(0)
        self.options_list.currentRowChanged.connect(self._on_nav_selection_changed)

        layout.addWidget(self.options_list, 1)

        sidebar_frame.setLayout(layout)

        return sidebar_frame

    def _build_content_views(self):
        overview_widget = self._build_overview_widget()
        self.content_stack.addWidget(overview_widget)

        matched_widget = self._build_matched_functions_widget()
        self.content_stack.addWidget(matched_widget)

        primary_unmatched_widget = self._build_unmatched_functions_widget(
            self.unmatched_primary, "Primary", self.primary_bv
        )
        self.content_stack.addWidget(primary_unmatched_widget)

        secondary_unmatched_widget = self._build_unmatched_functions_widget(
            self.unmatched_secondary, "Secondary", self.secondary_bv
        )
        self.content_stack.addWidget(secondary_unmatched_widget)

    def _build_overview_widget(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(_get_title(f"Diff Overview - {self.primary_filename} vs {self.secondary_filename}"))

        layout.addWidget(self._build_pie_chart_widget())

        charts_layout = QHBoxLayout()
        charts_layout.addWidget(self._build_similarity_chart_widget())
        charts_layout.addWidget(self._build_confidence_chart_widget())
        layout.addLayout(charts_layout)

        layout.addWidget(self._build_overall_stats_widget())

        layout.addStretch()

        widget.setLayout(layout)

        return widget

    def _build_pie_chart_widget(self):
        widget = QWidget()
        widget.setMinimumSize(500, 250)

        def paint_pie_chart(event):
            painter = QPainter(widget)
            painter.setRenderHint(QPainter.Antialiasing)

            rect = widget.rect()

            painter.setPen(QPen(QColor(255, 255, 255)))
            painter.setFont(QFont("Arial", 12, QFont.Bold))
            title_rect = QRect(0, 10, rect.width(), 30)
            painter.drawText(title_rect, Qt.AlignCenter, "Matched vs Unmatched Distribution")

            matches_count = len(self.matches)
            unmatched_primary_count = len(self.unmatched_primary)
            unmatched_secondary_count = len(self.unmatched_secondary)
            total = matches_count + unmatched_primary_count + unmatched_secondary_count

            colors = [QColor(0, 255, 0), QColor(219, 100, 100), QColor(223, 187, 88)]
            labels = ["Matched Functions", "Primary Unmatched Functions", "Secondary Unmatched Functions"]
            values = [matches_count, unmatched_primary_count, unmatched_secondary_count]

            pie_rect = QRect(30, 50, rect.height() - 80, rect.height() - 80)
            start_angle = 0
            for i, value in enumerate(values):
                angle = int((value / total) * 360 * 16)

                color = colors[i]
                painter.setBrush(QBrush(color))
                painter.setPen(QPen(color.darker(120), 2))

                painter.drawPie(pie_rect, start_angle, angle)
                start_angle += angle

            legend_x = pie_rect.right() + 30
            legend_y = pie_rect.top() + 10

            painter.setFont(QFont("Arial", 11))
            for i, (value, label) in enumerate(zip(values, labels)):
                color = colors[i]
                percentage = (value / total) * 100

                painter.setBrush(QBrush(color))
                painter.setPen(QPen(color.darker(120), 1))
                painter.drawRect(QRect(legend_x, legend_y + i * 50, 18, 18))

                painter.setPen(QPen(QColor(255, 255, 255)))
                painter.drawText(legend_x + 28, legend_y + i * 50 + 7, f"{label}")

                painter.setFont(QFont("Arial", 9))
                painter.drawText(legend_x + 28, legend_y + i * 50 + 21, f"{value} ({percentage:.1f}%)")
                painter.setFont(QFont("Arial", 11))

        widget.paintEvent = paint_pie_chart

        return widget

    def _build_similarity_chart_widget(self):
        frequencies = [0] * 10
        for match in self.matches:
            similarity = match['similarity']
            bucket = int(max((similarity * 100 + 5) // 10, 1) - 1)

            frequencies[bucket] += 1
        return self._build_chart_with_data(frequencies, "Similarity Distribution")

    def _build_confidence_chart_widget(self):
        frequencies = [0] * 10
        for match in self.matches:
            similarity = match['confidence']
            bucket = int(max((similarity * 100 + 5) // 10, 1) - 1)

            frequencies[bucket] += 1
        return self._build_chart_with_data(frequencies, "Confidence Distribution")

    def _build_chart_with_data(self, frequencies, text):
        widget = QWidget()
        widget.setMinimumSize(400, 250)

        def paint_histogram(event):
            painter = QPainter(widget)
            painter.setRenderHint(QPainter.Antialiasing)

            rect = widget.rect()
            margin = 50
            chart_rect = QRect(1.5 * margin, margin,
                               rect.width() - 2 * margin,
                               rect.height() - 2 * margin)

            total_frequency = len(self.matches)
            bar_width = chart_rect.width() / len(frequencies) * 0.8
            spacing = chart_rect.width() / len(frequencies) * 0.2

            painter.setPen(QPen(QColor(100, 100, 100), 2))
            painter.drawLine(chart_rect.left(), chart_rect.top(), chart_rect.left(), chart_rect.bottom())
            painter.drawLine(chart_rect.left(), chart_rect.bottom(), chart_rect.right(), chart_rect.bottom())

            painter.setFont(QFont("Arial", 9))
            for i in range(6):
                y_val = int((total_frequency / 5) * i)
                y_pos = chart_rect.bottom() - (i / 5) * chart_rect.height()

                painter.setPen(QPen(QColor(100, 100, 100), 2))
                painter.drawLine(chart_rect.left(), int(y_pos), chart_rect.right(), int(y_pos))

                painter.setPen(QPen(QColor(255, 255, 255)))
                painter.drawText(30, int(y_pos) + 3, str(y_val))

            labels = ["0.1", "0.2", "0.3", "0.4", "0.5", "0.6", "0.7", "0.8", "0.9", "1.0"]

            for i, frequency in enumerate(frequencies):
                color = QColor(25 * (10 - i), 25 * (i + 1), 0)

                x = chart_rect.left() + i * (bar_width + spacing) + spacing / 2
                normalized_height = (frequency / total_frequency) * chart_rect.height()
                y = chart_rect.bottom() - normalized_height

                painter.setBrush(QBrush(color))
                painter.setPen(QPen(color.darker(120), 1))
                painter.drawRect(int(x), int(y), int(bar_width), int(normalized_height))

                if frequency > 0:
                    painter.setPen(QPen(QColor(255, 255, 255)))
                    painter.setFont(QFont("Arial", 9, QFont.Bold))
                    value_rect = QRect(int(x), int(y) - 20, int(bar_width), 15)
                    painter.drawText(value_rect, Qt.AlignCenter, str(frequency))

                painter.setFont(QFont("Arial", 9))
                painter.setPen(QPen(QColor(255, 255, 255)))
                label_rect = QRect(int(x), chart_rect.bottom() + 5, int(bar_width), 20)
                painter.drawText(label_rect, Qt.AlignCenter, labels[i])

            painter.setFont(QFont("Arial", 11, QFont.Bold))
            x_title_rect = QRect(chart_rect.left(), rect.top() + 20, chart_rect.width(), 20)
            painter.drawText(x_title_rect, Qt.AlignCenter, text)

        widget.paintEvent = paint_histogram

        return widget

    def _build_overall_stats_widget(self):
        widget = QWidget()
        widget.setMinimumSize(600, 200)

        def paint_stats(event):
            painter = QPainter(widget)
            painter.setRenderHint(QPainter.Antialiasing)

            rect = widget.rect()

            similarities = [match['similarity'] for match in self.matches]
            confidences = [match['confidence'] for match in self.matches]

            sim_mean = sum(similarities) / len(similarities)
            sim_min = min(similarities)
            sim_max = max(similarities)
            sim_variance = sum((x - sim_mean) ** 2 for x in similarities) / len(similarities)
            sim_std = sim_variance ** 0.5

            conf_mean = sum(confidences) / len(confidences)
            conf_variance = sum((x - conf_mean) ** 2 for x in confidences) / len(confidences)
            conf_std = conf_variance ** 0.5

            high_quality = sum(1 for match in self.matches if match['similarity'] > 0.9 and match['confidence'] > 0.9)
            high_quality_percent = (high_quality / len(self.matches)) * 100

            painter.setBrush(QBrush(QColor(45, 45, 45)))
            painter.setPen(QPen(QColor(100, 100, 100), 1))
            painter.drawRoundedRect(rect.adjusted(10, 10, -10, -10), 8, 8)

            painter.setPen(QPen(QColor(255, 255, 255)))
            painter.setFont(QFont("Arial", 14, QFont.Bold))
            title_rect = QRect(20, 20, rect.width() - 40, 30)
            painter.drawText(title_rect, Qt.AlignCenter, "Overall Statistics")

            offset_x = [40, rect.width() // 2 + 40]
            start_y = 80
            line_height = 30

            painter.setFont(QFont("Arial", 11))

            stats_left = [
                ("Similarity Mean:", f"{sim_mean:.3f}"),
                ("Similarity Std Dev:", f"{sim_std:.3f}"),
                ("Similarity Range:", f"{sim_min:.3f} - {sim_max:.3f}"),
            ]

            stats_right = [
                ("Confidence Mean:", f"{conf_mean:.3f}"),
                ("Confidence Std Dev:", f"{conf_std:.3f}"),
                ("High Quality Matches:", f"{high_quality} ({high_quality_percent:.1f}%)"),
            ]

            stats = [stats_left, stats_right]

            for j, stat in enumerate(stats):
                for i, (label, value) in enumerate(stat):
                    y = start_y + i * line_height

                    painter.setPen(QPen(QColor(200, 200, 200)))
                    painter.drawText(offset_x[j], y, label)

                    painter.setPen(QPen(QColor(255, 255, 255)))
                    painter.drawText(offset_x[j] + 150, y, value)

            painter.setPen(QPen(QColor(100, 100, 100), 1))
            sep_x = rect.width() // 2
            painter.drawLine(sep_x, start_y - 20, sep_x, start_y + len(stats_left) * line_height)

        widget.paintEvent = paint_stats
        return widget

    def _build_matched_functions_widget(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(_get_title(f"Matched Functions ({len(self.matches)} in total)"))

        search_layout, search_box = _build_search_box()
        layout.addLayout(search_layout)

        table = self._build_matched_functions_table()
        layout.addWidget(table)

        search_box.textChanged.connect(lambda text: self._filter_table(text, table, [1, 3]))

        widget.setLayout(layout)

        return widget

    def _build_matched_functions_table(self):
        table = QTableWidget()
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels([
            "Primary Address", "Primary Name",
            "Secondary Address", "Secondary Name",
            "Similarity", "Confidence"
        ])
        table.setRowCount(len(self.matches))

        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setAlternatingRowColors(True)
        table.setSortingEnabled(True)

        for row, match in enumerate(self.matches):
            primary_addr_item = QTableWidgetItem(f"0x{match['address_primary']:08x}")
            primary_addr_item.setData(Qt.UserRole, match['address_primary'])
            table.setItem(row, 0, primary_addr_item)

            primary_name_item = QTableWidgetItem(match['name_primary'])
            table.setItem(row, 1, primary_name_item)

            secondary_addr_item = QTableWidgetItem(f"0x{match['address_secondary']:08x}")
            secondary_addr_item.setData(Qt.UserRole, match['address_secondary'])
            table.setItem(row, 2, secondary_addr_item)

            secondary_name_item = QTableWidgetItem(match['name_secondary'])
            table.setItem(row, 3, secondary_name_item)

            similarity_item = QTableWidgetItem(f"{match['similarity']:.3f}")
            similarity_item.setForeground(QColor(0, 0, 0))
            similarity_item.setBackground(_get_bg_color(match['similarity']))
            table.setItem(row, 4, similarity_item)

            confidence_item = QTableWidgetItem(f"{match['confidence']:.3f}")
            confidence_item.setForeground(QColor(0, 0, 0))
            confidence_item.setBackground(_get_bg_color(match['confidence']))
            table.setItem(row, 5, confidence_item)

        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)

        table.cellDoubleClicked.connect(lambda row, col: self._on_matched_function_clicked(row, table))

        return table

    def _build_unmatched_functions_widget(self, functions: List[Dict], file_type: str, bv):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(_get_title(f"{file_type} Unmatched Functions ({len(functions)} in total)"))

        search_layout, search_box = _build_search_box()
        layout.addLayout(search_layout)

        table = self._build_unmatched_functions_table(functions, bv)
        layout.addWidget(table)

        search_box.textChanged.connect(lambda text: self._filter_table(text, table, [1]))

        widget.setLayout(layout)

        return widget

    def _build_unmatched_functions_table(self, functions: List[Dict], bv):
        table = QTableWidget()
        table.setColumnCount(2)
        table.setHorizontalHeaderLabels(["Address", "Name"])
        table.setRowCount(len(functions))

        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setAlternatingRowColors(True)
        table.setSortingEnabled(True)

        for row, func in enumerate(functions):
            addr_item = QTableWidgetItem(f"0x{func['address']:08x}")
            addr_item.setData(Qt.UserRole, func['address'])
            table.setItem(row, 0, addr_item)

            name_item = QTableWidgetItem(func['name'])
            table.setItem(row, 1, name_item)

        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)

        table.cellDoubleClicked.connect(lambda row, col: self._on_unmatched_function_clicked(row, table, bv))

        return table

    def _on_nav_selection_changed(self, index):
        self.content_stack.setCurrentIndex(index / 2)

    def _on_matched_function_clicked(self, row, table):
        try:
            primary_addr_item = table.item(row, 0)
            if primary_addr_item:
                primary_address = primary_addr_item.data(Qt.UserRole)
                self.primary_bv.navigate(self.primary_bv.view, primary_address)
            secondary_addr_item = table.item(row, 2)
            if secondary_addr_item:
                secondary_address = secondary_addr_item.data(Qt.UserRole)
                self.secondary_bv.navigate(self.secondary_bv.view, secondary_address)

        except Exception as e:
            show_message_box("Error", f"Could not navigate to address: {e}")

    def _on_unmatched_function_clicked(self, row, table, bv):
        try:
            addr_item = table.item(row, 0)
            if addr_item:
                address = addr_item.data(Qt.UserRole)
                bv.navigate(bv.view, address)

        except Exception as e:
            show_message_box("Error", f"Could not navigate to address: {e}")

    def _filter_table(self, search_text, table, search_columns):
        try:
            search_text = search_text.lower()

            for row in range(table.rowCount()):
                should_show = False
                if not search_text:
                    should_show = True
                else:
                    for col in search_columns:
                        item = table.item(row, col)
                        if item:
                            item_text = item.text().lower()
                            if item_text.startswith(search_text):
                                should_show = True
                                break

                table.setRowHidden(row, not should_show)

        except Exception as e:
            show_message_box("Error", f"Error filtering table: {e}")
