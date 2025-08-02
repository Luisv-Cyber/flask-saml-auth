import os
import base64
import json
from flask import Blueprint, request, redirect, url_for, session, make_response
from onelogin.saml2.auth import OneLogin_Saml2_Auth

saml_blueprint = Blueprint('saml', __name__)

def init_saml_auth(req):
    saml_path = os.path.join(os.getcwd())

    # Load settings files
    with open(os.path.join(saml_path, 'settings.json'), 'r') as f:
        settings = json.load(f)

    with open(os.path.join(saml_path, 'advanced_settings.json'), 'r') as f:
        advanced_settings = json.load(f)

    # Load certificate content and inject into settings
    with open(os.path.join(saml_path, 'cert.pem'), 'r') as f:
        cert_content = f.read().replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "")

    with open(os.path.join(saml_path, 'key.pem'), 'r') as f:
        key_content = f.read()

    settings['sp']['x509cert'] = cert_content
    settings['sp']['privateKey'] = key_content

    # Merge settings
    merged_settings = {**settings, **advanced_settings}

    return OneLogin_Saml2_Auth(req, merged_settings)

def prepare_flask_request(request):
    """Prepare Flask request for SAML with ngrok override"""
    return {
        'https': 'on',
        'http_host': '6240c3f72b2d.ngrok-free.app',
        'server_port': '443',
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }
@saml_blueprint.route('/sso/login')
def sso_login():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return redirect(auth.login())

@saml_blueprint.route('/sso/acs', methods=['POST'])
def sso_acs():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    auth.process_response()

    errors = auth.get_errors()
    if not errors:
        session['samlUserdata'] = auth.get_attributes()
        session['samlNameId'] = auth.get_nameid()
        session['samlNameIdFormat'] = auth.get_nameid_format()
        session['samlSessionIndex'] = auth.get_session_index()
        return redirect(url_for('success'))
    else:
        error_msg = f"SAML Authentication failed: {', '.join(errors)}"
        return f"<h1>Authentication Error</h1><p>{error_msg}</p><p>Reason: {auth.get_last_error_reason()}</p>"

@saml_blueprint.route('/sso/sls', methods=['GET', 'POST'])
def sso_sls():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)

    def clear_session():
        session.clear()

    url = auth.process_slo(delete_session_cb=clear_session)
    errors = auth.get_errors()

    if not errors:
        return redirect(url if url else url_for('index'))
    else:
        return f"<h1>Logout Error</h1><p>{', '.join(errors)}</p>"

@saml_blueprint.route('/metadata')
def metadata():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    saml_settings = auth.get_settings()
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.check_sp_metadata(metadata)

    if not errors:
        response = make_response(metadata, 200)
        response.headers['Content-Type'] = 'text/xml'
        return response
    else:
        return f"<h1>Metadata Error</h1><p>{', '.join(errors)}</p>"
