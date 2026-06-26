# -*- coding: utf-8 -*-
import sys
import json
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QLineEdit, QPushButton, QLabel, QGroupBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QMessageBox
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor, QTextCursor


# ============================================================
# 1. Modbus RTU Parser Module (from Task 8)
# ============================================================

FUNC_NAMES = {
    0x01: "Чтение битов (Coils)",
    0x02: "Чтение дискретных входов",
    0x03: "Чтение регистров хранения",
    0x04: "Чтение входных регистров",
    0x05: "Запись одного бита",
    0x06: "Запись одного регистра",
    0x0F: "Запись нескольких битов",
    0x10: "Запись нескольких регистров",
}

EXCEPTION_NAMES = {
    0x01: "Недопустимая функция",
    0x02: "Недопустимый адрес данных",
    0x03: "Недопустимое значение данных",
    0x04: "Сбой ведомого устройства",
    0x05: "Подтверждение",
    0x06: "Ведомое устройство занято",
    0x08: "Ошибка четности памяти",
    0x0A: "Путь шлюза недоступен",
    0x0B: "Целевое устройство шлюза не ответило",
}


def crc16_modbus(data: bytes) -> int:
    """Calculate CRC16 (Modbus), polynomial 0xA001."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc


def parse_modbus_packet(hex_str: str) -> dict:
    """
    Parse Modbus RTU packet.
    Returns a dictionary with fields:
        - raw: original bytes
        - slave: device address
        - func: function code
        - is_error: whether it's an error response
        - exception_code: exception code (if any)
        - data: data bytes
        - data_hex: data in hex
        - data_decoded: decoded data (for register reads)
        - crc_received: received CRC
        - crc_calculated: calculated CRC
        - crc_ok: whether CRC matches
        - func_name: function name
        - length: packet length
    """
    clean = hex_str.replace(" ", "").replace("\n", "").replace("\t", "")
    raw = bytes.fromhex(clean)

    if len(raw) < 4:
        raise ValueError(f"Packet too short: {len(raw)} bytes (minimum 4)")

    result = {
        "raw": raw,
        "slave": raw[0],
        "func": raw[1],
        "is_error": bool(raw[1] & 0x80),
        "data": raw[2:-2],
        "crc_received": raw[-2] | (raw[-1] << 8),
        "length": len(raw),
    }

    result["crc_calculated"] = crc16_modbus(raw[:-2])
    result["crc_ok"] = (result["crc_received"] == result["crc_calculated"])

    if result["is_error"]:
        ex_code = raw[2] if len(raw) >= 3 else 0
        result["exception_code"] = ex_code
        result["func_name"] = f"ОШИБКА: {EXCEPTION_NAMES.get(ex_code, f'Неизвестный код {ex_code:02X}')}"
        result["data_hex"] = ""
        result["data_decoded"] = []
    else:
        result["func_name"] = FUNC_NAMES.get(raw[1], f"Неизвестная функция 0x{raw[1]:02X}")
        result["data_hex"] = result["data"].hex(" ").upper()
        result["exception_code"] = None

        data = result["data"]
        decoded = []
        if raw[1] in (0x03, 0x04) and len(data) >= 1:
            byte_count = data[0] if len(data) > 0 else 0
            values = data[1:]
            for i in range(0, len(values), 2):
                if i + 1 < len(values):
                    val = (values[i] << 8) | values[i + 1]
                    decoded.append(val)
            result["data_decoded"] = decoded
        elif raw[1] in (0x01, 0x02):
            byte_count = data[0] if len(data) > 0 else 0
            bits = []
            for byte in data[1:]:
                for bit in range(8):
                    bits.append((byte >> bit) & 1)
            result["data_decoded"] = bits[:byte_count * 8] if byte_count > 0 else bits
        else:
            result["data_decoded"] = []

    return result


def format_report(parsed: dict) -> str:
    """Generate human-readable report."""
    lines = []
    lines.append("=" * 60)
    lines.append("📋 ОТЧЁТ О РАЗБОРЕ MODBUS RTU")
    lines.append("=" * 60)

    lines.append(f"\n📦 Исходный пакет:    {parsed['raw'].hex(' ').upper()}")
    lines.append(f"📏 Длина пакета:      {parsed['length']} байт")

    lines.append(f"\n🔢 Адрес устройства:  {parsed['slave']} (0x{parsed['slave']:02X})")

    func = parsed['func']
    if parsed['is_error']:
        lines.append(f"⚠️  Код функции:      0x{func:02X} (ОТВЕТ С ОШИБКОЙ)")
        lines.append(f"   Код ошибки:       {parsed['exception_code']} - {EXCEPTION_NAMES.get(parsed['exception_code'], 'Неизвестный')}")
    else:
        lines.append(f"📌 Код функции:      0x{func:02X} ({parsed['func_name']})")

    if parsed['data_hex']:
        lines.append(f"\n📊 Данные:           {parsed['data_hex']}")
    else:
        lines.append(f"\n📊 Данные:           (нет)")

    if parsed['data_decoded']:
        lines.append(f"   Расшифровка:      {parsed['data_decoded']}")

    lines.append(f"\n🔐 CRC полученный:   0x{parsed['crc_received']:04X}")
    lines.append(f"   CRC вычисленный:   0x{parsed['crc_calculated']:04X}")
    lines.append(f"   Статус CRC:        {'✅ ВЕРНЫЙ' if parsed['crc_ok'] else '❌ ОШИБКА'}")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


# ============================================================
# 2. PyQt5 GUI Application
# ============================================================

class ModbusParserApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Парсер Modbus RTU — Анализатор ПЧ")
        self.setMinimumSize(700, 600)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # Header
        title = QLabel("🔌 Парсер Modbus RTU пакетов")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # Input field
        layout.addWidget(QLabel("Введите hex-пакет Modbus RTU:"))
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Пример: 01 03 00 7E 00 02 25 D0")
        self.input_field.setFont(QFont("Courier New", 11))
        self.input_field.returnPressed.connect(self.parse_packet)
        layout.addWidget(self.input_field)

        # Buttons
        btn_layout = QHBoxLayout()
        self.parse_btn = QPushButton("🔍 Разобрать")
        self.parse_btn.clicked.connect(self.parse_packet)
        self.parse_btn.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")

        self.clear_btn = QPushButton("🗑️ Очистить")
        self.clear_btn.clicked.connect(self.clear_all)

        self.copy_btn = QPushButton("📋 Копировать отчёт")
        self.copy_btn.clicked.connect(self.copy_report)

        self.example_btn = QPushButton("📌 Пример")
        self.example_btn.clicked.connect(self.load_example)

        btn_layout.addWidget(self.parse_btn)
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addWidget(self.copy_btn)
        btn_layout.addWidget(self.example_btn)
        layout.addLayout(btn_layout)

        # Separator
        layout.addWidget(QLabel("=" * 60))

        # Detail table
        layout.addWidget(QLabel("📊 Детальный разбор:"))
        self.table = QTableWidget()
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(["Поле", "Значение"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        layout.addWidget(self.table)

        # Report output
        layout.addWidget(QLabel("📄 Полный отчёт:"))
        self.output_field = QTextEdit()
        self.output_field.setFont(QFont("Courier New", 10))
        self.output_field.setReadOnly(True)
        layout.addWidget(self.output_field)

        # Status bar
        self.status_label = QLabel("Готов. Введите пакет и нажмите 'Разобрать'")
        self.status_label.setStyleSheet("background-color: #f0f0f0; padding: 5px;")
        layout.addWidget(self.status_label)

    def parse_packet(self):
        """Main parsing function."""
        hex_str = self.input_field.text().strip()

        if not hex_str:
            QMessageBox.warning(self, "Ошибка", "Введите hex-пакет для разбора!")
            return

        try:
            parsed = parse_modbus_packet(hex_str)
            self.display_results(parsed)
            self.status_label.setText(f"✅ Пакет разобран. CRC: {'ВЕРЕН' if parsed['crc_ok'] else 'ОШИБКА'}")
            self.status_label.setStyleSheet("background-color: #d4edda; padding: 5px;")
        except ValueError as e:
            QMessageBox.critical(self, "Ошибка разбора", str(e))
            self.status_label.setText(f"❌ Ошибка: {e}")
            self.status_label.setStyleSheet("background-color: #f8d7da; padding: 5px;")
        except Exception as e:
            QMessageBox.critical(self, "Неизвестная ошибка", str(e))
            self.status_label.setText(f"❌ Неизвестная ошибка: {e}")
            self.status_label.setStyleSheet("background-color: #f8d7da; padding: 5px;")

    def display_results(self, parsed: dict):
        """Display results in table and text field."""
        rows = [
            ("Адрес устройства", f"{parsed['slave']} (0x{parsed['slave']:02X})"),
            ("Код функции", f"0x{parsed['func']:02X} ({parsed['func_name']})"),
            ("Ответ с ошибкой", "Да" if parsed['is_error'] else "Нет"),
        ]

        if parsed['is_error']:
            rows.append(("Код ошибки", f"{parsed['exception_code']} - {EXCEPTION_NAMES.get(parsed['exception_code'], 'Неизвестный')}"))

        if parsed['data_hex']:
            rows.append(("Данные (hex)", parsed['data_hex']))

        if parsed['data_decoded']:
            rows.append(("Расшифрованные данные", str(parsed['data_decoded'])))

        rows.extend([
            ("CRC полученный", f"0x{parsed['crc_received']:04X}"),
            ("CRC вычисленный", f"0x{parsed['crc_calculated']:04X}"),
            ("Статус CRC", "✅ ВЕРНЫЙ" if parsed['crc_ok'] else "❌ ОШИБКА"),
            ("Длина пакета", f"{parsed['length']} байт"),
        ])

        self.table.setRowCount(len(rows))
        for i, (key, val) in enumerate(rows):
            self.table.setItem(i, 0, QTableWidgetItem(key))
            self.table.setItem(i, 1, QTableWidgetItem(str(val)))

        # Highlight CRC status
        crc_item = self.table.item(len(rows) - 2, 1)
        if crc_item:
            if parsed['crc_ok']:
                crc_item.setBackground(QColor(200, 255, 200))
            else:
                crc_item.setBackground(QColor(255, 200, 200))

        report = format_report(parsed)
        self.output_field.setText(report)

    def clear_all(self):
        """Clear all fields."""
        self.input_field.clear()
        self.table.setRowCount(0)
        self.output_field.clear()
        self.status_label.setText("Очищено. Введите новый пакет.")
        self.status_label.setStyleSheet("background-color: #f0f0f0; padding: 5px;")

    def copy_report(self):
        """Copy report to clipboard."""
        text = self.output_field.toPlainText()
        if text:
            clipboard = QApplication.clipboard()
            clipboard.setText(text)
            self.status_label.setText("📋 Отчёт скопирован в буфер обмена!")
            self.status_label.setStyleSheet("background-color: #d4edda; padding: 5px;")
        else:
            QMessageBox.information(self, "Информация", "Нет отчёта для копирования.")

    def load_example(self):
        """Load example packet."""
        self.input_field.setText("01 03 00 7E 00 02 25 D0")
        self.parse_packet()


# ============================================================
# 3. Run Application
# ============================================================

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ModbusParserApp()
    window.show()
    sys.exit(app.exec_())
