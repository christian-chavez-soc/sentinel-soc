"""
Sentinel Event Cursor

Maintains a persistent cursor for the last processed
Windows Security Event Log record.
"""

CURSOR_FILE = "C:\\AI\\sentinel\\cursor.txt"


def load_cursor():
    try:
        with open(CURSOR_FILE, "r") as f:
            return int(f.read().strip())
    except:
        return 0


def save_cursor(record_number):
    with open(CURSOR_FILE, "w") as f:
        f.write(str(record_number))
