from modules import host_expansion

test_event = {
    "username": "test_user",
    "logon_type": 3,
    "origin": "TEST_WORKSTATION",
    "time": "2026-03-03 21:20:00"
}

result = host_expansion.analyze(test_event)

print(result)
