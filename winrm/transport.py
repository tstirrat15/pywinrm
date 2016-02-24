from __future__ import unicode_literals
import requests
import requests_kerberos
from winrm.exceptions import BasicAuthDisabledError, InvalidCredentialsError, \
    WinRMError
from .authentication import KerberosAuth, MultiAuth, NtlmAuth

__all__ = ['Transport']


class Transport(object):

    def __init__(
            self, endpoint, username=None, password=None, realm=None,
            service=None, keytab=None, ca_trust_path=None, cert_pem=None,
            cert_key_pem=None, timeout=None):
        self.endpoint = endpoint
        self.username = username
        self.password = password
        self.realm = realm
        self.service = service
        self.keytab = keytab
        self.ca_trust_path = ca_trust_path
        self.cert_pem = cert_pem
        self.cert_key_pem = cert_key_pem
        self.timeout = timeout
        self.default_headers = {
            'Content-Type': 'application/soap+xml;charset=UTF-8',
            'User-Agent': 'Python WinRM client',
        }
        self.session = None

    def build_session(self):
        session = requests.Session()

        # Here's where it happens. If you don't HAVE_KERBEROS, it just....
        # doesn't even try it. Maybe break out the auth stuff into a separate
        # module?
        # also, it looks like it just crams all possible authentication
        # methods together. Why?
        session.auth = MultiAuth(session)
        for auth_scheme in ('Negotiate', 'Kerberos'):
            kerberos_auth = KerberosAuth(mutual_authentication=requests_kerberos.OPTIONAL, realm=self.realm, auth_scheme=auth_scheme)
            session.auth.add_auth(auth_scheme, kerberos_auth)

        for auth_scheme in ('Negotiate', 'NTLM'):
            ntlm_auth = NtlmAuth(self.username, self.password, session, auth_scheme)
            session.auth.add_auth(auth_scheme, ntlm_auth)

        if self.username and self.password:
            basic_auth = requests.auth.HTTPBasicAuth(self.username, self.password)
            session.auth.add_auth('Basic', basic_auth)

        if self.cert_pem:
            if self.cert_key_pem:
                session.cert = (self.cert_pem, self.cert_key_pem)
            else:
                session.cert = self.cert_pem

        session.headers.update(self.default_headers)

        return session

    def send_message(self, message):
        # TODO support kerberos session with message encryption

        if not self.session:
            self.session = self.build_session()
        request = requests.Request('POST', self.endpoint, data=message)
        prepared_request = self.session.prepare_request(request)
        try:
            response = self.session.send(prepared_request, verify=False, timeout=self.timeout)
            response.raise_for_status()
            # Version 1.1 of WinRM adds the namespaces in the document instead of the envelope so we have to
            # add them ourselves here. This should have no affect version 2.
            response_text = response.text
            return response_text
        except requests.HTTPError as ex:
            if ex.response.status_code == 401:
                server_auth = ex.response.headers['WWW-Authenticate'].lower()
                client_auth = list(self.session.auth.auth_map.keys())
                # Client can do only the Basic auth but server can not
                if 'basic' not in server_auth and len(client_auth) == 1 \
                        and client_auth[0] == 'basic':
                    raise BasicAuthDisabledError()
                # Both client and server can do a Basic auth
                if 'basic' in server_auth and 'basic' in client_auth:
                    raise InvalidCredentialsError()
            if ex.response:
                response_text = ex.response.content
            else:
                response_text = ''
            # Per http://msdn.microsoft.com/en-us/library/cc251676.aspx rule 3,
            # should handle this 500 error and retry receiving command output.
            if 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive' in message and 'Code="2150858793"' in response_text:
                # TODO raise TimeoutError here instead of just return text
                return response_text
            error_message = 'Bad HTTP response returned from server. Code {0}'.format(ex.response.status_code)
            # if ex.msg:
            #    error_message += ', {0}'.format(ex.msg)
            raise WinRMError('http', error_message)
