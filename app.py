import os
import pathlib
import requests
from flask import Flask, session, abort, redirect, request
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

app = Flask() 
app.secret_key = "makecodeurhobby" #don't use this in production

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
print(client_secrets_file)
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", 
    "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)


def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()
    return wrapper



@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)



@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)
    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    print(id_info['email'])
    print(type(id_info))
    
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["email"] = id_info.get("email")


    return redirect("/protected_area")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/")
def index():
    return "Hello World <a href='/login'><button>Login</button></a>"

@app.route("/protected_area")
@login_is_required
def protected_area():
    return f"Hello {session['name']}!,  <br/> {session['email']}</br> <a href='/logout'><button>Logout</button></a>"


if __name__ == "__main__":
    app.run(debug=True)



"""
{'iss': 'https://accounts.google.com',
'azp': '746870155564-lqnq760fbp57eo4fknltldgfsrrae8kl.apps.googleusercontent.com', 
'aud': '746870155564-lqnq760fbp57eo4fknltldgfsrrae8kl.apps.googleusercontent.com', 
'sub': '106227981437322112381', 'email': 'brvcase@gmail.com', 
'email_verified': True, 
'at_hash': 'PauVEqaj6O_05-T88k4ZWw', 
'name': 'Ademola Adebowale', 
'picture': 'https://lh3.googleusercontent.com/a-/AOh14GgxWAh_TS-vZt_7og1AAmsvIJpH9G1rlrqP0Dkz=s96-c', 
'given_name': 'Ademola', 
'family_name': 'Adebowale', 
'locale': 'en', 
'iat': 1651692227, 
'exp': 1651695827}

"""