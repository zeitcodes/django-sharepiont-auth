from django.conf import settings
try:
    from django.contrib.auth import get_user_model
except ImportError:
    from django.contrib.auth.models import User

    def get_user_model(*args, **kwargs):
        return User
from hashlib import md5
from lxml import etree
from lxml.objectify import ElementMaker
import requests


SHAREPOINT_URL = getattr(settings, 'SHAREPOINT_URL')
USER_CREATION = getattr(settings, 'SHAREPOINT_USER_CREATION', True)


class SharePointBackend(object):
    supports_anonymous_user = False
    supports_inactive_user = True
    supports_object_permissions = False

    def __init__(self):
        self.User = get_user_model()

    def authenticate(self, username, password):
        envelope = self.get_envelope(username, password)
        response = self.get_response(envelope)
        if response.ok:
            token = self.parse_token(response.content)
            if token is not None:
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
        return md5(email).hexdigest()

    def get_envelope(self, username, password):
        NSMAP_1 = {
            's': 'http://www.w3.org/2003/05/soap-envelope',
            'a': 'http://www.w3.org/2005/08/addressing',
            'u': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
        }
        NSMAP_2 = {
            'o': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
        }
        NSMAP_3 = {
            't': 'http://schemas.xmlsoap.org/ws/2005/02/trust',
        }
        NSMAP_4 = {
            'wsp': 'http://schemas.xmlsoap.org/ws/2004/09/policy',
        }

        S = ElementMaker(namespace=NSMAP_1['s'], nsmap=NSMAP_1, annotate=False)
        A = ElementMaker(namespace=NSMAP_1['a'], nsmap=NSMAP_1, annotate=False)
        U = ElementMaker(namespace=NSMAP_1['u'], nsmap=NSMAP_1, annotate=False)
        O = ElementMaker(namespace=NSMAP_2['o'], nsmap=NSMAP_2, annotate=False)
        T = ElementMaker(namespace=NSMAP_3['t'], nsmap=NSMAP_3, annotate=False)
        WSP = ElementMaker(namespace=NSMAP_4['wsp'], nsmap=NSMAP_4, annotate=False)



        envelope = S.Envelope(
            S.Header(
                A.Action('http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue', mustUnderstand='1'),
                A.ReplyTo(
                    A.Address('http://www.w3.org/2005/08/addressing/anonymous'),
                ),
                A.To('https://login.microsoftonline.com/extSTS.srf', mustUnderstand='1'),
                O.Security(
                    O.UsernameToken(
                        O.Username(username),
                        O.Password(password),
                    ),
                    mustUnderstand='1',
                ),
            ),
            S.Body(
                T.RequestSecurityToken(
                    WSP.AppliesTo(
                        A.EndpointReference(
                            A.Address(SHAREPOINT_URL),
                        ),
                    ),
                    T.KeyType('http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey'),
                    T.RequestType('http://schemas.xmlsoap.org/ws/2005/02/trust/Issue'),
                    T.TokenType('urn:oasis:names:tc:SAML:1.0:assertion'),
                ),
            ),
        )

        return etree.tostring(envelope)

    def get_response(self, envelope):
        return requests.post('https://login.microsoftonline.com/extSTS.srf', data=envelope)

    def parse_token(self, text):
        document = etree.fromstring(text)
        results = document.xpath('//wsse:BinarySecurityToken',
            namespaces={'wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'})
        if len(results):
            return results[0].text
        else:
            return None
