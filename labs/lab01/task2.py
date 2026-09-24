USERS = {
    "ciso_office": {
        "role": "ciso",
        "clearance": 4,
        "department": "Executive",
        "active": True,
    },
    "threat_hunter": {
        "role": "threat_analyst",
        "clearance": 3,
        "department": "Threat Intel",
        "active": True,
    },
    "junior_dev": {
        "role": "junior_developer",
        "clearance": 2,
        "department": "Development",
        "active": True,
    },
    "visitor_acc": {
        "role": "visitor",
        "clearance": 1,
        "department": "Guest",
        "active": True,
    },
    "legacy_sys": {
        "role": "legacy",
        "clearance": 2,
        "department": "Legacy",
        "active": False,
    },
}

RESOURCES = [
    ("threat_intelligence", 4),
    ("malware_samples", 3),
    ("coding_guidelines", 2),
    ("visitor_wifi", 1),
    ("strategic_plans", 4),
    ("demo_environment", 1),
    ("risk_assessments", 3),
    ("crypto_keys", 4),
    ("api_documentation", 2),
    ("guest_portal", 1),
]

SECURITY_LEVELS = ("Guest", "Employee", "Privileged", "Executive")

BLOCKED_USERS = {"legacy_sys", "malicious_user", "expired_guest"}


def print_resources(resources: list, security_levels: tuple) -> None:
    """Виводить список ресурсів із текстовою назвою рівня безпеки."""
    print("Ресурси системи:")
    for resource, level in resources:
        level_name = security_levels[level - 1]
        print(f"  - {resource:<22} | Рівень безпеки: {level_name}")


def check_access(username: str, resource_level: int, users: dict, blocked: set) -> tuple:
    """Перевіряє доступ користувача до ресурсу."""
    if username not in users:
        return False, "User not found"

    if username in blocked:
        return False, "User is blocked"

    user = users[username]

    if not user["active"]:
        return False, "Account inactive"

    if user["clearance"] < resource_level:
        return False, "Insufficient clearance"

    return True, None


def run_access_checks(users: dict, resources: list, blocked: set) -> list:
    """Виконує перевірку доступу кожного користувача до кожного ресурсу."""
    results = []
    for username in users:
        for resource_name, resource_level in resources:
            allowed, reason = check_access(username, resource_level, users, blocked)
            results.append((username, resource_name, allowed, reason))
    return results


def print_access_results(results: list) -> None:
    """Виводить результати перевірки доступу."""
    for username, resource_name, allowed, reason in results:
        status = "ALLOW" if allowed else f"DENY ({reason})"
        print(f"user={username:<16} resource={resource_name} -> {status}")


def main() -> None:
    print_resources(RESOURCES, SECURITY_LEVELS)

    print("\nРезультати перевірки доступу:\n")
    results = run_access_checks(USERS, RESOURCES, BLOCKED_USERS)
    print_access_results(results)


if __name__ == "__main__":
    main()
