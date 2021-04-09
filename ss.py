from flask import Flask
from flask import jsonify, make_response, request

import firebase_admin
from firebase_admin import credentials, auth

cred = credentials.Certificate(r"C:\Users\PC\Desktop\smartassociate-hq-firebase-adminsdk-irp1a-f0ce840fae.json")
firebase_admin.initialize_app(cred)

app = Flask(__name__)

@app.route('/ping', methods=['POST'])
def ping():
    response = make_response(jsonify({"status": "ok"}), 200,)
    response.headers["Content-Type"] = "application/json"
    return response

@app.route('/status', methods=['POST'])
def get_status():
    request_data = request.get_json()
    decoded_token = []
    try:
        decoded_token = auth.verify_id_token(request_data["token"], check_revoked=True)
        uid = decoded_token['uid']
    except auth.RevokedIdTokenError as e:
        print('ID token has been revoked')
    except auth.ExpiredIdTokenError as e:
        print('ID token is expired')
    except auth.InvalidIdTokenError as e:
        print('ID token is invalid')
    
    return request_data["token"]


if __name__ == '__main__':
    app.run(debug=True)