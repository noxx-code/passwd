import argparse
import secrets
import string
import sys

try:
	from PyQt6 import QtCore, QtWidgets
except ImportError:
	QtCore = None
	QtWidgets = None


def generate_password(
	length: int,
	*,
	use_lower: bool = True,
	use_upper: bool = True,
	use_digits: bool = True,
	use_special: bool = True,
	use_brackets: bool = False,
	extra_chars: str = "",
	require_classes: bool = False,
) -> str:
	"""Generate a cryptographically strong password.

	If ``require_classes`` is True the password will contain at least one
	character from each active class (the classes the caller enabled).
	"""
	lower = string.ascii_lowercase if use_lower else ""
	upper = string.ascii_uppercase if use_upper else ""
	digits = string.digits if use_digits else ""

	# define bracket characters separately so callers can opt-in
	brackets = "[]{}()<>" if use_brackets else ""

	# string.punctuation contains brackets too; build special set excluding
	# brackets so we can control them independently
	special_all = string.punctuation
	if brackets:
		special = "".join(ch for ch in special_all if ch not in brackets)
	else:
		special = special_all if use_special else ""

	# If use_special is False we should not include punctuation except
	# what's explicitly provided in extra_chars or brackets (if enabled)
	if not use_special:
		special = ""

	classes = [s for s in (lower, upper, digits, special, brackets) if s]

	if length <= 0:
		raise ValueError("length must be > 0")

	if not classes and not extra_chars:
		raise ValueError("no character classes selected")

	# prepare the pool of all allowed characters
	all_chars = "".join(classes) + extra_chars

	if require_classes:
		# ensure at least one from each enabled class (extra_chars don't count)
		enabled_classes = [s for s in (lower, upper, digits, special, brackets) if s]
		if length < len(enabled_classes):
			raise ValueError("length too small for required character classes")
		password_chars = [secrets.choice(c) for c in enabled_classes]
		password_chars += [secrets.choice(all_chars) for _ in range(length - len(password_chars))]
		secrets.SystemRandom().shuffle(password_chars)
		return "".join(password_chars)

	return "".join(secrets.choice(all_chars) for _ in range(length))


def run_cli(args: argparse.Namespace) -> int:
	try:
		pwd = generate_password(
			args.length,
			use_lower=not args.no_lower,
			use_upper=not args.no_upper,
			use_digits=not args.no_digits,
			use_special=not args.no_special,
			use_brackets=args.brackets,
			extra_chars=args.extra_chars or "",
			require_classes=args.require_classes,
		)
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

			# character class options
			self.lower_cb = QtWidgets.QCheckBox("Lowercase (a–z)")
			self.lower_cb.setChecked(True)
			self.upper_cb = QtWidgets.QCheckBox("Uppercase (A–Z)")
			self.upper_cb.setChecked(True)
			self.digits_cb = QtWidgets.QCheckBox("Numbers (0–9)")
			self.digits_cb.setChecked(True)
			self.special_cb = QtWidgets.QCheckBox("Special characters")
			self.special_cb.setChecked(True)
			self.brackets_cb = QtWidgets.QCheckBox("Brackets")
			self.brackets_cb.setChecked(False)
			self.require_cb = QtWidgets.QCheckBox("Require at least one from each selected class")
			self.extra_input = QtWidgets.QLineEdit()
			self.extra_input.setPlaceholderText("Additional custom symbols")

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
			form.addRow(self.lower_cb)
			form.addRow(self.upper_cb)
			form.addRow(self.digits_cb)
			form.addRow(self.special_cb)
			form.addRow(self.brackets_cb)
			form.addRow("Extra characters", self.extra_input)
			form.addRow(self.require_cb)

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
			password = generate_password(
				self.length_input.value(),
				use_lower=self.lower_cb.isChecked(),
				use_upper=self.upper_cb.isChecked(),
				use_digits=self.digits_cb.isChecked(),
				use_special=self.special_cb.isChecked(),
				use_brackets=self.brackets_cb.isChecked(),
				extra_chars=self.extra_input.text(),
				require_classes=self.require_cb.isChecked(),
			)
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
	parser.add_argument("--no-lower", action="store_true", help="Exclude lowercase letters")
	parser.add_argument("--no-upper", action="store_true", help="Exclude uppercase letters")
	parser.add_argument("--no-digits", action="store_true", help="Exclude digits")
	parser.add_argument("--no-punct", "--no-special", action="store_true", dest="no_special", help="Exclude special/punctuation characters")
	parser.add_argument("--brackets", action="store_true", help="Include bracket characters (e.g. []{}())")
	parser.add_argument("--extra-chars", type=str, default="", help="Additional custom characters to include")
	parser.add_argument("--require-classes", action="store_true", help="Require at least one char from each selected class")
	args = parser.parse_args()

	if args.cli:
		return run_cli(args)
	return run_gui()


if __name__ == "__main__":
	raise SystemExit(main())