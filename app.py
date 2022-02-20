import os
import pathlib
import requests
from flask import Flask, session, abort, redirect, request
from google_auth_oauthlib. flow import Flow 
from pip._vendor import cachecontrol
import google.auth.transport.requests


app = Flask("Google Login App")

app.secret_key = "4\x1d\x93\x86\xd2I\x1e#;+g\xf7\x80\r\xd8\xe8SE\x8d\x1b\xb5\xf4"


GOOGLE_CLIENT_ID = "1014958715637-mpsqmhiioflu0a7krqkipmt7cuqb9cnb.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")


flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file, 
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback")

#create new decorator for protection against unauth users 
def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
           return abort(401) #Authorization required 
        else:
            return function()
    return wrapper         

# add routes
@app.route("/login")
def login():
    # authorization url + state get returned will be sent and sent back to make sure no piggbacking is happening 
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
   flow.fetch_token(authorization_response=request.url)

   if not session["state"] ==request.args["state"]:
       abort(500) #state does not match
       
       credentials = flow.credentials
       request_session = requests.session()
       cached_session = cachecontrol.CacheControl(request_session)
       token_request = google.auth.transport.requests.Request(session=cached_session)

       id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
       return id_info
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/")
def index():
    return "Test App <a href='/login'><button>Login</button></a>"

@app.route("/protected_area")
@login_is_required
def protected_area():
    return "Protected! <a href='/logout'><button>Logout</button></a>"



if __name__ == "__main__":
    app.run(debug=True)