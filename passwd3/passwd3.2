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
	extra_chars: str = "",
	require_classes: bool = False,
	base_words: list[str] | None = None,
) -> str:
	"""Generate a cryptographically strong password.

	If ``require_classes`` is True the password will contain at least one
	character from each active class (the classes the caller enabled).
	"""
	lower = string.ascii_lowercase if use_lower else ""
	upper = string.ascii_uppercase if use_upper else ""
	digits = string.digits if use_digits else ""

	# special characters use string.punctuation when enabled
	special = string.punctuation if use_special else ""

	classes = [s for s in (lower, upper, digits, special) if s]

	if length <= 0:
		raise ValueError("length must be > 0")

	if not classes and not extra_chars:
		raise ValueError("no character classes selected")

	# prepare the pool of all allowed characters
	all_chars = "".join(classes) + extra_chars

	# Helper to determine which character classes are present in a string
	def classes_present(s: str) -> set[str]:
		present = set()
		if use_lower and any(ch in lower for ch in s):
			present.add("lower")
		if use_upper and any(ch in upper for ch in s):
			present.add("upper")
		if use_digits and any(ch in digits for ch in s):
			present.add("digits")
		if use_special and any(ch in special for ch in s):
			present.add("special")
		return present

	enabled_classes = [s for s in (lower, upper, digits, special) if s]

	if base_words:
		# normalize and filter empty words
		seeds = [w.strip() for w in base_words if w and w.strip()]
		if not seeds:
			seeds = []
		# ensure no single seed is longer than the requested length
		for w in seeds:
			if len(w) > length:
				raise ValueError("a base word is longer than the requested length")

		# If no seeds after filtering, fall back to normal generation
		if seeds:
			# Attempt to build a password that includes at least one seed
			sysrand = secrets.SystemRandom()
			attempts = 0
			while attempts < 1000:
				attempts += 1
				# choose how many seeds to include (1 .. len(seeds)) allowing occasional repetition
				k = sysrand.choice(range(1, len(seeds) + 1))
				chosen = [sysrand.choice(seeds) if sysrand.random() < 0.1 else sysrand.choice(seeds) for _ in range(k)]
				# randomize order
				sysrand.shuffle(chosen)
				# optional capitalization variations
				varied = []
				for w in chosen:
					r = sysrand.random()
					if r < 0.15:
						varied.append(w.upper())
					elif r < 0.35:
						varied.append(w.capitalize())
					else:
						varied.append(w)
				# insert random small separators between words (0..2 chars)
				parts: list[str] = []
				for i, w in enumerate(varied):
					parts.append(w)
					if i != len(varied) - 1:
						sep_len = sysrand.choice([0, 0, 1, 1, 2])
						if sep_len:
							parts.append("".join(secrets.choice(all_chars) for _ in range(sep_len)))

				base_str = "".join(parts)
				if len(base_str) > length:
					continue

				# Determine missing classes after base_str
				present = classes_present(base_str)
				needed = []
				if require_classes:
					if use_lower and "lower" not in present:
						needed.append(lower)
					if use_upper and "upper" not in present:
						needed.append(upper)
					if use_digits and "digits" not in present:
						needed.append(digits)
					if use_special and "special" not in present:
						needed.append(special)

				min_needed = len(needed)
				remaining = length - len(base_str)
				if remaining < min_needed:
					# not enough room to satisfy class requirements
					continue

				pwd_parts: list[str] = []
				# Decide where to put filler characters: before, between, after words
				# Start with the base parts structure and allow inserting additional fillers
				# Build initial segments by splitting base_str at the exact boundaries of chosen words
				# For simplicity keep base_str intact and insert filler before/after
				# Add one char from each needed class first
				fillers: list[str] = []
				for cls in needed:
					fillers.append(secrets.choice(cls))
				# fill remaining filler slots
				remaining_after_needed = remaining - len(fillers)
				for _ in range(remaining_after_needed):
					fillers.append(secrets.choice(all_chars))

				# distribute fillers: some before, some in middle, some after
				sysrand.shuffle(fillers)
				before = secrets.choice(range(0, len(fillers) + 1))
				after = len(fillers) - before
				final = "".join(fillers[:before]) + base_str + "".join(fillers[before:])

				# Final sanity: ensure require_classes satisfied
				if require_classes:
					final_present = classes_present(final)
					needed_now = []
					if use_lower and "lower" not in final_present:
						needed_now.append("lower")
					if use_upper and "upper" not in final_present:
						needed_now.append("upper")
					if use_digits and "digits" not in final_present:
						needed_now.append("digits")
					if use_special and "special" not in final_present:
						needed_now.append("special")
					if needed_now:
						# failed to include required classes, try again
						continue

				return final

			# If we exit loop without returning, fall back to error
			raise ValueError("unable to construct a password including the provided base words within length/constraints")

	# No base words, or seeds were empty — fall back to original behavior
	if require_classes:
		# ensure at least one from each enabled class (extra_chars don't count)
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
			extra_chars=args.extra_chars or "",
			require_classes=args.require_classes,
			base_words=[w.strip() for w in args.base.split(",")] if getattr(args, "base", None) else None,
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
            
			self.require_cb = QtWidgets.QCheckBox("Require at least one from each selected class")
			self.extra_input = QtWidgets.QLineEdit()
			self.extra_input.setPlaceholderText("Additional custom symbols")
			self.base_input = QtWidgets.QLineEdit()
			self.base_input.setPlaceholderText("comma separated words")

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
            
			form.addRow("Extra characters", self.extra_input)
			form.addRow("Base words", self.base_input)
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
				extra_chars=self.extra_input.text(),
					require_classes=self.require_cb.isChecked(),
					base_words=[w.strip() for w in self.base_input.text().split(",")] if self.base_input.text() else None,
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
	parser.add_argument("--extra-chars", type=str, default="", help="Additional custom characters to include")
	parser.add_argument("--require-classes", action="store_true", help="Require at least one char from each selected class")
	parser.add_argument("--base", type=str, default="", help="Base/seed words (comma separated). Example: --base \"one,458\"")
	args = parser.parse_args()

	if args.cli:
		return run_cli(args)
	return run_gui()


if __name__ == "__main__":
	raise SystemExit(main())
