import requests
import weakref
import requests_kerberos
import re
from six.moves.urllib.parse import urlsplit, urlunsplit
from contextlib import contextmanager
from requests.adapters import HTTPAdapter
from requests.hooks import default_hooks


class KerberosAuth(requests_kerberos.HTTPKerberosAuth):
    '''
    Custom Kerberos authentication provider that allows specifying a realm.
    '''
    # why do I care about specifying a realm?

    def __init__(self, mutual_authentication=requests_kerberos.REQUIRED,
                 service='HTTP', realm=None, auth_scheme='Negotiate'):
        super(KerberosAuth, self).__init__(mutual_authentication, service)
        self.realm = realm
        self.auth_scheme = auth_scheme
        self.regex = re.compile(r'(?:.*,)*\s*%s\s*([^,]*),?'
                                % self.auth_scheme,
                                re.I)

    @contextmanager
    def _replace_realm(self, response):
        original_url = response.url
        if self.realm:
            parts = urlsplit(original_url)
            netloc = parts.netloc.replace(parts.hostname, self.realm)
            response.url = urlunsplit((parts.scheme, netloc, parts.path,
                                       parts.query, parts.fragment))
        yield
        response.url = original_url

    @contextmanager
    def _replace_regex(self):
        original_regex = getattr(requests_kerberos.kerberos_._negotiate_value,
                                 'regex', None)
        requests_kerberos.kerberos_._negotiate_value.regex = self.regex
        yield
        if original_regex:
            setattr(requests_kerberos.kerberos_._negotiate_value, 'regex',
                    original_regex)
        else:
            delattr(requests_kerberos.kerberos_._negotiate_value, 'regex')

    def generate_request_header(self, response):
        with self._replace_regex():
            with self._replace_realm(response):
                result = super(KerberosAuth, self).generate_request_header(response)
                if result is not None:
                    result = result.replace('Negotiate ',
                                            '%s ' % self.auth_scheme)
                return result

    def handle_401(self, response, **kwargs):
        with self._replace_regex():
            return super(KerberosAuth, self).handle_401(response, **kwargs)

    def handle_other(self, response):
        with self._replace_regex():
            return super(KerberosAuth, self).handle_other(response)

    def authenticate_server(self, response):
        with self._replace_regex():
            with self._replace_realm(response):
                return super(KerberosAuth, self).authenticate_server(response)


class MultiAuth(requests.auth.AuthBase):
    # the unexplained behavior here has to do with it inheriting
    # from the base class. I'd have to go doc-diving there.

    def __init__(self, session=None):
        self.auth_map = {}
        self.current_auth = None
        self.session = weakref.ref(session) if session else None

    def add_auth(self, scheme, auth_instance):
        auth_instances = self.auth_map.setdefault(scheme.lower(), [])
        auth_instances.append(auth_instance)

    def handle_401(self, response, **kwargs):
        """Takes the given response and tries digest-auth, if needed."""

        original_request = response.request.copy()
        www_authenticate = response.headers.get('www-authenticate', '').lower()
        www_auth_schemes = [x.strip().split()[0]
                            for x in www_authenticate.split(',') if x.strip()]
        auths_to_try = [x for x in www_auth_schemes
                        if x in [y.lower() for y in self.auth_map.keys()]]

        for auth_scheme in auths_to_try:
            for auth_instance in self.auth_map[auth_scheme]:
                # Consume content and release the original connection
                # to allow our new request to reuse the same one.
                response.content
                response.raw.release_conn()
                prepared_request = original_request.copy()
                prepared_request.hooks = default_hooks()
                prepared_request.prepare_auth(auth_instance)

                adapter = HTTPAdapter()
                if self.session:
                    adapter = self.session() or adapter
                new_response = adapter.send(prepared_request, **kwargs)
                new_response.history.append(response)
                new_response.request = prepared_request

                if new_response.status_code != 401:
                    self.current_auth = auth_instance
                    return new_response
                response = new_response

        return response

    def handle_response(self, response, **kwargs):
        if response.status_code == 401 and not self.current_auth:
            response = self.handle_401(response, **kwargs)
        return response

    def __call__(self, request):
        if self.current_auth:
            request = self.current_auth(request)
        request.register_hook('response', self.handle_response)
        return request
