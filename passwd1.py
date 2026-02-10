import argparse
import secrets
import string
import sys

try:
	from PyQt6 import QtCore, QtWidgets
except Exception:
	QtCore = None
	QtWidgets = None


def generate_password(length: int) -> str:
	chars = string.ascii_letters + string.digits + string.punctuation
	return "".join(secrets.choice(chars) for _ in range(length))


def run_cli() -> int:
	length = int(input("Length: "))
	print(generate_password(length))
	return 0


class PasswordWindow(QtWidgets.QWidget):
	def __init__(self) -> None:
		super().__init__()
		self.setWindowTitle("Password Generator")
		self.setMinimumWidth(360)

		length_label = QtWidgets.QLabel("Length")
		self.length_input = QtWidgets.QSpinBox()
		self.length_input.setRange(4, 128)
		self.length_input.setValue(16)

		self.generate_button = QtWidgets.QPushButton("Generate")
		self.copy_button = QtWidgets.QPushButton("Copy")
		self.copy_button.setEnabled(False)

		self.output = QtWidgets.QLineEdit()
		self.output.setReadOnly(True)
		self.output.setPlaceholderText("Your password appears here")

		self.status = QtWidgets.QLabel("")
		self.status.setStyleSheet("color: #2d6a4f;")

		form = QtWidgets.QFormLayout()
		form.addRow(length_label, self.length_input)

		buttons = QtWidgets.QHBoxLayout()
		buttons.addWidget(self.generate_button)
		buttons.addWidget(self.copy_button)

		layout = QtWidgets.QVBoxLayout(self)
		layout.addLayout(form)
		layout.addWidget(self.output)
		layout.addLayout(buttons)
		layout.addWidget(self.status)

		self.generate_button.clicked.connect(self.on_generate)
		self.copy_button.clicked.connect(self.on_copy)
		self.length_input.valueChanged.connect(self.on_length_change)

	def on_generate(self) -> None:
		password = generate_password(self.length_input.value())
		self.output.setText(password)
		self.copy_button.setEnabled(True)
		self.status.setText("Generated")

	def on_copy(self) -> None:
		QtWidgets.QApplication.clipboard().setText(self.output.text())
		self.status.setText("Copied to clipboard")

	def on_length_change(self, value: int) -> None:
		if value < 8:
			self.status.setText("Short length")
		else:
			self.status.setText("")


def run_gui() -> int:
	if QtWidgets is None:
		print("PyQt6 is not installed. Run with --cli or install PyQt6.")
		return 1

	app = QtWidgets.QApplication(sys.argv)
	window = PasswordWindow()
	window.show()
	return app.exec()


def main() -> int:
	parser = argparse.ArgumentParser(description="Password generator")
	parser.add_argument("--cli", action="store_true", help="Run in CLI mode")
	args = parser.parse_args()

	if args.cli:
		return run_cli()
	return run_gui()


if __name__ == "__main__":
	raise SystemExit(main())
