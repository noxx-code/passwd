import argparse
import secrets
import string
import sys

try:
	from PyQt6 import QtCore, QtWidgets
except ImportError:
	QtCore = None
	QtWidgets = None


def generate_password(length: int, *, allow_punctuation: bool = True, require_classes: bool = False) -> str:
	"""Generate a cryptographically strong password.

	If ``require_classes`` is True the password will contain at least one
	character from each active class (lower, upper, digit, punctuation).
	"""
	lower = string.ascii_lowercase
	upper = string.ascii_uppercase
	digits = string.digits
	punct = string.punctuation if allow_punctuation else ""

	classes = [lower, upper, digits]
	if punct:
		classes.append(punct)

	if length <= 0:
		raise ValueError("length must be > 0")

	if require_classes:
		if length < len(classes):
			raise ValueError("length too small for required character classes")
		# ensure at least one from each class
		password_chars = [secrets.choice(c) for c in classes]
		all_chars = "".join(classes)
		password_chars += [secrets.choice(all_chars) for _ in range(length - len(password_chars))]
		secrets.SystemRandom().shuffle(password_chars)
		return "".join(password_chars)

	chars = string.ascii_letters + string.digits + punct
	return "".join(secrets.choice(chars) for _ in range(length))


def run_cli(args: argparse.Namespace) -> int:
	try:
		pwd = generate_password(args.length, allow_punctuation=not args.no_punct, require_classes=args.require_classes)
	except ValueError as exc:
		print(f"Error: {exc}")
		return 2
	print(pwd)
	return 0


if QtWidgets is not None:
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
	parser.add_argument("--length", type=int, default=16, help="Password length (default: 16)")
	parser.add_argument("--no-punct", action="store_true", help="Exclude punctuation characters")
	parser.add_argument("--require-classes", action="store_true", help="Require at least one char from each class (lower/upper/digit/punct)")
	args = parser.parse_args()

	if args.cli:
		return run_cli(args)
	return run_gui()


if __name__ == "__main__":
	raise SystemExit(main())
