import task1
import task2
import task3

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def print_section_header(title: str) -> None:
    print("\n" + "#" * 67)
    print(f"# {title}")
    print("#" * 67)


def main() -> None:
    print(f"Лабораторна робота №1 | Студент: {STUDENT_NAME}")
    print(f"Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")

    print_section_header("Завдання 1: Аналізатор надійності паролів")
    task1.main()

    print_section_header("Завдання 2: Система контролю доступу")
    task2.main()

    print_section_header("Завдання 3: Хешування, CSV-база та JSON-логування")
    task3.main()


if __name__ == "__main__":
    main()
