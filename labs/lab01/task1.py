import random

passwords = [
    "Security@2023",
    "pass",
    "MyStr0ng#Key",
    "root",
    "Advanc3d@Pass",
    "user",
    "Protec7!Pass",
    "1234",
    "Elite@Secur1ty",
    "admin123",
]

CRITERIA = {
    "min_length": 7,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

FORBIDDEN_PASSWORDS = {"pass", "root", "user", "1234", "admin123", "password"}


def simulate_password_reuse():
    """Імітує повторне використання паролів.

    Обирає 3 випадкові індекси зі списку та додає відповідні паролі
    дублікатами в кінець початкового списку.
    """
    global passwords
    reused_indexes = random.sample(range(len(passwords)), 3)
    for index in reused_indexes:
        passwords.append(passwords[index])


def check_criteria(password: str) -> dict:
    """Повертає, яким критеріям відповідає пароль."""
    return {
        "digit": any(char.isdigit() for char in password),
        "upper": any(char.isupper() for char in password),
        "special": any(not char.isalnum() for char in password),
    }


def evaluate_password(password: str, criteria: dict, forbidden: set, all_passwords: list) -> str:
    """Оцінює надійність одного пароля."""
    min_length = criteria["min_length"]

    # Заборонений
    if password in forbidden or len(password) < min_length:
        return "Заборонений"

    flags = check_criteria(password)
    satisfied_count = sum(flags.values())

    # Дуже сильний / Сильний
    if satisfied_count == 3:
        if len(password) >= min_length + 4:
            is_unique = all_passwords.count(password) == 1
            if is_unique:
                return "Дуже сильний"
            return "Сильний"
        return "Сильний"

    # Середній: відповідає довжині та деяким (але не всім) критеріям
    if satisfied_count >= 2:
        return "Середній"

    return "Слабкий"


def analyze_passwords(all_passwords: list, criteria: dict, forbidden: set) -> list:
    """Аналізує весь список паролів та повертає результати."""
    results = []
    for password in all_passwords:
        strength = evaluate_password(password, criteria, forbidden, all_passwords)
        results.append((password, strength))
    return results


def print_results_table(results: list) -> None:
    """Виводить результати аналізу у вигляді таблиці."""
    password_width = max(len(password) for password in passwords) + 2
    strength_width = 16

    header = f"{'Пароль':<{password_width}}{'Рівень надійності':<{strength_width}}"
    print(header)
    print("-" * len(header))
    for password, strength in results:
        print(f"{password:<{password_width}}{strength:<{strength_width}}")


def main() -> None:
    simulate_password_reuse()
    count = len(passwords)
    print(f"\nСписок паролів після імітації повторного використання ({count} шт.):")
    print(passwords)

    results = analyze_passwords(passwords, CRITERIA, FORBIDDEN_PASSWORDS)

    print("\nРезультати аналізу надійності паролів:\n")
    print_results_table(results)


if __name__ == "__main__":
    main()
