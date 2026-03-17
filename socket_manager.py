from flask_socketio import SocketIO

socketio = SocketIO()
event_history = []

def send_event(data):
    print("DASHBOARD EVENT:", data)
    event_history.append(data)
    socketio.emit("new_event", data)
