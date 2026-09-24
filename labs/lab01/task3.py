import csv
import hashlib
import json
import os
from datetime import datetime

from shared.student import VARIANT_NUMBER

HASH_ALGORITHM = "sha512"
MIN_PASSWORD_LENGTH = 14
PERSONAL_SALT = str(VARIANT_NUMBER).zfill(5)

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_JSON_PATH = os.path.join(DATA_DIR, "log.json")


class ValidationError(Exception):
    """Виникає, коли пароль не відповідає мінімальним вимогам безпеки."""

def generate_hash(password: str, salt: str = "00000") -> str:
    """Повертає шістнадцятковий hash(password + salt) за алгоритмом sha512."""
    if not password or not salt:
        raise ValueError("Пароль та сіль не можуть бути порожніми.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(f"Пароль повинен містити щонайменше {MIN_PASSWORD_LENGTH} символів.")

    hasher = hashlib.new(HASH_ALGORITHM)
    hasher.update((password + salt).encode("utf-8"))
    return hasher.hexdigest()


USERS_TO_REGISTER = (
    ("admin_ciso", "Executiv3P@ssphrase!"),
    ("threat_hunt", "Th3reatIntel#Secure99"),
    ("junior_dev", "DevJunior$Cod3rPass1"),
    ("visitor_guest", "GuestVisit0r@Portal!"),
    ("legacy_op", "LegacyS3ystem#OldPass"),
    ("soc_analyst", "SOCanalyz3#Watching1"),
    ("net_admin", "N3tworkAdm!n#Secure2"),
    ("audit_lead", "Aud1tLead$Compl!ance"),
    ("short_pw", "Short1!"),
    ("empty_case", ""),
)


def create_user(username: str, password: str) -> tuple:
    """Створює запис користувача."""
    hash_value = generate_hash(password, PERSONAL_SALT)
    return username, hash_value


def create_users(users_list: tuple):
    """Реєструє список користувачів та записує їх у labs/lab01/data/users.csv."""
    if os.path.exists(USERS_CSV_PATH):
        print("File already exists")
        return
    os.makedirs(DATA_DIR, exist_ok=True)
    try:
        with open(USERS_CSV_PATH, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            for username, password in users_list:
                try:
                    record = create_user(username, password)
                    writer.writerow(record)
                except (ValidationError, ValueError) as error:
                    print(f"  [ПРОПУЩЕНО] {username}: {error}")
    except (FileNotFoundError, PermissionError, IOError) as error:
        print(f"Помилка запису файлу бази користувачів: {error}")


def read_users_db() -> list:
    """Зчитує базу користувачів з CSV-файлу."""
    users_db = []
    try:
        with open(USERS_CSV_PATH, "r", newline="", encoding="utf-8") as csv_file:
            reader = csv.reader(csv_file)
            for row in reader:
                if row:
                    users_db.append((row[0], row[1]))
    except FileNotFoundError as error:
        print(f"Файл бази користувачів не знайдено: {error}")
    except (PermissionError, IOError) as error:
        print(f"Помилка читання файлу бази користувачів: {error}")
    return users_db


def print_users_db(users_db: list) -> None:
    """Виводить базу користувачів у вигляді структурованої таблиці."""
    if not users_db:
        print("База користувачів порожня.")
        return
    username_width = max(len(username) for username, _ in USERS_TO_REGISTER) + 2
    print(f"{'Логін':<{username_width}}{'Хеш пароля'}")
    print("-" * (username_width + 40))
    for username, hash_value in users_db:
        print(f"{username:<{username_width}}{hash_value}")


def _append_log_entry(entry: dict) -> None:
    """Дописує одну подію у файл labs/lab01/data/log.json."""
    os.makedirs(DATA_DIR, exist_ok=True)
    try:
        if os.path.exists(LOG_JSON_PATH):
            with open(LOG_JSON_PATH, 'r') as log_file:
                try:
                    events = json.load(log_file)
                except json.JSONDecodeError:
                    events = []
        else:
            events = []

        events.append(entry)
        with open(LOG_JSON_PATH, "w") as log_file:
            json.dump(events, log_file, ensure_ascii=False, indent=2)
    except (FileNotFoundError, PermissionError, IOError) as error:
        print(f"Помилка запису журналу подій: {error}")


def log_event(func):
    """Декоратор, що логує кожну спробу входу у файл log.json."""
    def wrapper(*args, **kwargs):
        username = kwargs.get("username", args[0] if args else "unknown")
        success = False
        try:
            success = func(*args, **kwargs)
            return success
        finally:
            entry = {
                "event": "login",
                "user": username,
                "result": "success" if success else "failure",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "args": [str(a) for a in args],
                "kwargs": {key: str(value) for key, value in kwargs.items()},
            }
            _append_log_entry(entry)

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    """Перевіряє логін та пароль користувача з базою даних CSV."""
    if not username or not password:
        raise ValueError("Логін та пароль не можуть бути порожніми.")

    users_db = dict(read_users_db())
    if username not in users_db:
        return False

    expected_hash = users_db[username]
    actual_hash = generate_hash(password, PERSONAL_SALT)
    return actual_hash == expected_hash


def main() -> None:
    print(f"Алгоритм: {HASH_ALGORITHM} | Сіль: {PERSONAL_SALT}", end=" | ")
    print(f"Мін. довжина пароля: {MIN_PASSWORD_LENGTH}")
    print("=" * 67)

    print("\nРеєстрація користувачів у users.csv...")
    create_users(USERS_TO_REGISTER)

    print("\nВміст бази даних користувачів (users.csv):\n")
    users_db = read_users_db()
    print_users_db(users_db)

    print("\nПеревірка автентифікації (події логуються у log.json):")
    test_cases = [
        ("admin_ciso", "Executiv3P@ssphrase!"),
        ("admin_ciso", "WrongPassword123!!"),
        ("unknown_user", "SomePassword123!!"),
        ("empty_case", "")
    ]
    for username, password in test_cases:
        try:
            success = login(username= username, password = password)
            status = "успішна" if success else "неуспішна"
            print(f"  login({username}) -> {status}")
        except (ValueError, ValidationError) as error:
            print(f"  login({username}) -> помилка: {error}")

if __name__ == "__main__":
    main()
