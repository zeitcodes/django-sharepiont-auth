from base64 import urlsafe_b64encode
from django.conf import settings
try:
    from django.contrib.auth import get_user_model
except ImportError:
    from django.contrib.auth.models import User

    def get_user_model(*args, **kwargs):
        return User
from hashlib import sha1
from lxml import etree
from lxml.objectify import ElementMaker
import requests


USER_CREATION = getattr(settings, 'AD_USER_CREATION', True)


class ActiveDirectoryBackend(object):
    supports_anonymous_user = False
    supports_inactive_user = True
    supports_object_permissions = False

    def __init__(self):
        self.User = get_user_model()

    def authenticate(self, username, password):
        ad_url, auth_uri = self.get_user_realm(username)
        envelope = self.get_envelope(ad_url, auth_uri, username, password)
        response = requests.post(ad_url, data=envelope, headers={'content-type': 'application/soap+xml'})
        if response.ok:
            if self.has_token(response.content):
                users = self.User.objects.filter(email=username)
                if len(users) > 1:
                    return None
                elif len(users) == 1:
                    return users[0]
                else:
                    return self.create_user(username)
        return None

    def get_user(self, user_id):
        try:
            user = self.User.objects.get(pk=user_id)
            return user
        except self.User.DoesNotExist:
            return None

    def create_user(self, email):
        if USER_CREATION:
            username_field = getattr(self.User, 'USERNAME_FIELD', 'username')
            user_kwargs = {'email': email}
            user_kwargs[username_field] = self.username_generator(email)
            return self.User.objects.create_user(**user_kwargs)
        else:
            return None

    @staticmethod
    def username_generator(email):
        return urlsafe_b64encode(sha1(email).digest()).rstrip(b'=')

    def get_user_realm(self, username):
        ad_url = 'https://login.microsoftonline.com/extSTS.srf'
        auth_uri = 'https://portal.microsoftonline.com'

        params = {
            'login': username,
            'xml': 1,
        }
        response = requests.get('https://login.microsoftonline.com/GetUserRealm.srf', params=params)
        if response.ok:
            document = etree.fromstring(response.content)
            name_space_type = document.xpath('//NameSpaceType')[0].text
            if name_space_type == 'Federated':
                ad_url = document.xpath('//STSAuthURL')[0].text
                auth_uri = 'urn:federation:MicrosoftOnline'
        return ad_url, auth_uri

    def get_envelope(self, ad_url, auth_uri, username, password):
        NSMAP = {
            's': 'http://www.w3.org/2003/05/soap-envelope',
            'wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
            'wsp': 'http://schemas.xmlsoap.org/ws/2004/09/policy',
            'wsu': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
            'wsa': 'http://www.w3.org/2005/08/addressing',
            'wst': 'http://schemas.xmlsoap.org/ws/2005/02/trust'
        }

        S = ElementMaker(
            annotate=False,
            namespace=NSMAP['s'],
            nsmap=NSMAP,
        )

        WSSE = ElementMaker(
            annotate=False,
            namespace=NSMAP['wsse'],
            nsmap=NSMAP,
        )

        WSP = ElementMaker(
            annotate=False,
            namespace=NSMAP['wsp'],
            nsmap=NSMAP,
        )

        WSU = ElementMaker(
            annotate=False,
            namespace=NSMAP['wsu'],
            nsmap=NSMAP,
        )

        WSA = ElementMaker(
            annotate=False,
            namespace=NSMAP['wsa'],
            nsmap=NSMAP,
        )

        WST = ElementMaker(
            annotate=False,
            namespace=NSMAP['wst'],
            nsmap=NSMAP,
        )

        envelope = S.Envelope(
            S.Header(
                WSA.Action('http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue', mustUnderstand='1'),
                WSA.To(ad_url, mustUnderstand='1'),
                WSSE.Security(
                    WSSE.UsernameToken(
                        WSSE.Username(username),
                        WSSE.Password(password),
                    ),
                ),
            ),
            S.Body(
                WST.RequestSecurityToken(
                    WST.RequestType('http://schemas.xmlsoap.org/ws/2005/02/trust/Issue'),
                    WSP.AppliesTo(
                        WSA.EndpointReference(
                            WSA.Address(auth_uri),
                        ),
                    ),
                    WST.KeyType('http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey'),
                    WST.TokenType('urn:oasis:names:tc:SAML:1.0:assertion'),
                ),
            ),
        )

        return etree.tostring(envelope)

    def has_token(self, text):
        document = etree.fromstring(text)
        results = document.xpath('//wst:RequestedSecurityToken', namespaces={'wst': 'http://schemas.xmlsoap.org/ws/2005/02/trust'})
        return len(results) > 0
