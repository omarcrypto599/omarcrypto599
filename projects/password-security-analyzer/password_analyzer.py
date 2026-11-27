"""A local, educational password quality analyzer.

The entered password is analyzed in memory only. It is never stored or sent
over the network. This is a heuristic teaching tool, not a security guarantee.
"""

from getpass import getpass
import string


COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "123456789",
    "qwerty",
    "admin",
    "letmein",
    "welcome",
    "iloveyou",
    "abc123",
}

SEQUENTIAL_PATTERNS = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
)


def has_sequential_pattern(password: str, minimum: int = 4) -> bool:
    """Return True if a simple ascending sequence appears in the password."""
    candidate = password.lower()
    for sequence in SEQUENTIAL_PATTERNS:
        for start in range(len(sequence) - minimum + 1):
            fragment = sequence[start : start + minimum]
            if fragment in candidate:
                return True
            if fragment[::-1] in candidate:
                return True
    return False


def analyze_password(password: str) -> dict:
    """Analyze password quality and return a score, label, and feedback."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    feedback = []
    score = 0
    length = len(password)

    if length >= 16:
        score += 3
    elif length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    else:
        feedback.append("Use at least 12 characters; longer is generally better.")

    checks = {
        "lowercase": any(char.islower() for char in password),
        "uppercase": any(char.isupper() for char in password),
        "digit": any(char.isdigit() for char in password),
        "symbol": any(char in string.punctuation for char in password),
    }

    score += sum(checks.values())

    missing = [name for name, present in checks.items() if not present]
    if missing:
        feedback.append("Consider adding: " + ", ".join(missing) + ".")

    if password.lower() in COMMON_PASSWORDS:
        score = 0
        feedback.append("This password is very common. Choose a unique passphrase.")

    if len(password) >= 3 and len(set(password)) == 1:
        score = max(0, score - 3)
        feedback.append("Avoid passwords made from one repeated character.")

    if has_sequential_pattern(password):
        score = max(0, score - 2)
        feedback.append("Avoid predictable sequences such as abcde, 1234, or qwerty.")

    if length and len(set(password)) <= 2 and length >= 6:
        score = max(0, score - 1)
        feedback.append("Use a wider variety of characters.")

    score = max(0, min(score, 7))

    if score <= 2:
        rating = "Weak"
    elif score <= 4:
        rating = "Moderate"
    elif score <= 5:
        rating = "Good"
    else:
        rating = "Strong"

    if not feedback:
        feedback.append("No obvious basic weaknesses were detected by these checks.")

    return {
        "score": score,
        "max_score": 7,
        "rating": rating,
        "length": length,
        "checks": checks,
        "feedback": feedback,
    }


def main() -> None:
    print("\nPassword Security Analyzer")
    print("=" * 26)
    print("Your input is analyzed locally and is not saved.\n")

    password = getpass("Enter a test password: ")
    result = analyze_password(password)

    print("\nAnalysis")
    print("-" * 26)
    print(f"Rating: {result['rating']}")
    print(f"Score:  {result['score']}/{result['max_score']}")
    print(f"Length: {result['length']} characters")
    print("\nFeedback:")
    for item in result["feedback"]:
        print(f"- {item}")

    print("\nNote: This heuristic score is educational, not a security guarantee.")


if __name__ == "__main__":
    main()
