from flask import Flask
from flask import jsonify, make_response, request

from time import sleep

import firebase_admin
from firebase_admin import credentials, auth

from flask_mqtt import Mqtt
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['MQTT_BROKER_URL'] = ''  # use the free broker from HIVEMQ
app.config['MQTT_BROKER_PORT'] = 0  # default port for non-tls connection
app.config['MQTT_USERNAME'] = ''  # set the username here if you need authentication for the broker
app.config['MQTT_PASSWORD'] = ''  # set the password here if the broker demands authentication
app.config['MQTT_KEEPALIVE'] = 5  # set the time interval for sending a ping to the broker to 5 seconds
app.config['MQTT_TLS_ENABLED'] = False  # set TLS to disabled for testing purposes

app.config['SQLALCHEMY_DATABASE_URI'] = ''
app.secret_key = ""

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

mqtt_client_instance = Mqtt()

cred = credentials.Certificate(r"C:\Users\PC\Desktop\smartassociate-hq-firebase-adminsdk-irp1a-f0ce840fae.json")
firebase_admin.initialize_app(cred)


mqtt_client_instance.init_app(app)

global CURRENT_TOPIC
global CURRENT_STATE

CURRENT_STATE = None
CURRENT_TOPIC = None


class Socket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_code = db.Column(db.String(80), unique=True, nullable=False)
    user_id = db.Column(db.String(120), unique=False, nullable=False)

db.create_all()

@app.route('/ping', methods=['POST'])
def ping():
    response = make_response(jsonify({"status": "ok"}), 200,)
    response.headers["Content-Type"] = "application/json"
    return response

@app.route('/status', methods=['POST'])
def get_status():
    global CURRENT_TOPIC
    global CURRENT_STATE

    request_data = request.get_json()
    decoded_token = []
    device_code = request_data["device_code"]

    try:
        decoded_token = auth.verify_id_token(request_data["token"], check_revoked=True)
        uid = decoded_token['uid']
        socket = Socket.query.filter_by(device_code=device_code).first()
        if socket != None:
            if socket.user_id == uid:
                topic_to_publish = "socket/" + device_code

                CURRENT_TOPIC = topic_to_publish
                mqtt_client_instance.subscribe(topic_to_publish)
                
                mqtt_client_instance.publish(topic_to_publish, "GET")
                while CURRENT_STATE == None:
                    continue

                retval = CURRENT_STATE

                CURRENT_STATE = None
                CURRENT_TOPIC = None
                
                mqtt_client_instance.unsubscribe(topic_to_publish)

                response = make_response(jsonify({"status": "ok", "device_status" : retval}), 200,)
                response.headers["Content-Type"] = "application/json"
                return response

    except auth.RevokedIdTokenError as e:
        print('ID token has been revoked')
    except auth.ExpiredIdTokenError as e:
        print('ID token is expired')
    except auth.InvalidIdTokenError as e:
        print('ID token is invalid')
    
    response = make_response(jsonify({"status": "error", "error_msg" : "unauthorized request"}), 401,)
    response.headers["Content-Type"] = "application/json"
    return response


@app.route('/state', methods=['POST'])
def set_status():
    global CURRENT_TOPIC
    global CURRENT_STATE

    request_data = request.get_json()
    decoded_token = []
    device_code = request_data["device_code"]
    state = request_data["state"]

    try:
        decoded_token = auth.verify_id_token(request_data["token"], check_revoked=True)
        uid = decoded_token['uid']
        socket = Socket.query.filter_by(device_code=device_code).first()
        if socket != None:
            if socket.user_id == uid:
                topic_to_publish = "socket/" + device_code

                CURRENT_TOPIC = topic_to_publish
                mqtt_client_instance.subscribe(topic_to_publish)
                
                mqtt_client_instance.publish(topic_to_publish, "SET " + state)
                while CURRENT_STATE == None:
                    continue

                retval = CURRENT_STATE

                CURRENT_STATE = None
                CURRENT_TOPIC = None
                
                mqtt_client_instance.unsubscribe(topic_to_publish)

                response = make_response(jsonify({"status": "ok", "device_status" : retval}), 200,)
                response.headers["Content-Type"] = "application/json"
                return response

    except auth.RevokedIdTokenError as e:
        print('ID token has been revoked')
    except auth.ExpiredIdTokenError as e:
        print('ID token is expired')
    except auth.InvalidIdTokenError as e:
        print('ID token is invalid')
    
    response = make_response(jsonify({"status": "error", "error_msg" : "unauthorized request"}), 401,)
    response.headers["Content-Type"] = "application/json"
    return response


@app.route('/register', methods=['POST'])
def register_device():
    request_data = request.get_json()
    decoded_token = []
    device_code = request_data["device_code"]

    try:
        decoded_token = auth.verify_id_token(request_data["token"], check_revoked=True)
        uid = decoded_token['uid']
        socket = Socket.query.filter_by(device_code=device_code).first()
        if socket != None:
            try:
                int(socket.user_id)
            except ValueError:
                response = make_response(jsonify({"status": "error", "error_msg" : "Device already registered"}), 200,)
                response.headers["Content-Type"] = "application/json"
                return response

            if int(socket.user_id) == 0:
                socket.user_id = uid
                db.session.add(socket)
                db.session.commit()
                
                response = make_response(jsonify({"status": "ok"}), 200,)
                response.headers["Content-Type"] = "application/json"
                return response
            else:
                response = make_response(jsonify({"status": "error", "error_msg" : "Device already registered"}), 200,)
                response.headers["Content-Type"] = "application/json"
                return response
        else:
            response = make_response(jsonify({"status": "error", "error_msg" : "Wrong device code"}), 200,)
            response.headers["Content-Type"] = "application/json"
            return response

    except auth.RevokedIdTokenError as e:
        print('ID token has been revoked')
    except auth.ExpiredIdTokenError as e:
        print('ID token is expired')
    except auth.InvalidIdTokenError as e:
        print('ID token is invalid')
    
    response = make_response(jsonify({"status": "error", "error_msg" : "unauthorized request"}), 401,)
    response.headers["Content-Type"] = "application/json"
    return response

@app.route('/load', methods=['POST'])
def load_devices():

    request_data = request.get_json()
    decoded_token = []

    try:
        decoded_token = auth.verify_id_token(request_data["token"], check_revoked=True)
        uid = decoded_token['uid']
        socket = Socket.query.filter_by(user_id=uid).first()
        if socket != None:
            print(str(socket.device_code))
            response = make_response(jsonify({"status": "ok", "device_code" : str(socket.device_code)}), 200,)
            response.headers["Content-Type"] = "application/json"
            return response
        else:
            response = make_response(jsonify({"status": "error", "error_msg" : "user has no registered sockets"}), 200,)
            response.headers["Content-Type"] = "application/json"
            return response

    except auth.RevokedIdTokenError as e:
        print('ID token has been revoked')
    except auth.ExpiredIdTokenError as e:
        print('ID token is expired')
    except auth.InvalidIdTokenError as e:
        print('ID token is invalid')
    
    response = make_response(jsonify({"status": "error", "error_msg" : "unauthorized request"}), 401,)
    response.headers["Content-Type"] = "application/json"
    return response



@mqtt_client_instance.on_message()
def handle_mqtt_message(client, userdata, message):
    data = dict(
        topic=message.topic,
        payload=message.payload.decode()
    )
    global CURRENT_STATE
    if data['topic'] == CURRENT_TOPIC:
        if data['payload'][0:9+1] == "DEVICE-GET":
            CURRENT_STATE = data['payload'][11]

        if data['payload'][0:9+1] == "DEVICE-SET":
            CURRENT_STATE = data['payload'][11]


if __name__ == '__main__':
    app.run(host="0.0.0.0", port="5000", debug=True)
