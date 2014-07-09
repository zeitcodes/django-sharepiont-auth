from django.core.urlresolvers import reverse
from django.test import TestCase, Client
from django.test.utils import override_settings

EMAIL_ADDRESS = 'jason@zeitcode.com'
EMAIL_PASSWORD = '**password**'
EMAIL_DOMAIN = EMAIL_ADDRESS.split('@')[-1]


class AuthTestCase(TestCase):
    def setUP(self):
        self.client = Client()

    def test_get_login(self):
        url = reverse('auth_login')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_post_login_success(self):
        url = reverse('auth_login')
        data = {
            'username': EMAIL_ADDRESS,
            'password': EMAIL_PASSWORD,
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 302)

    def test_post_login_fail(self):
        url = reverse('auth_login')
        data = {
            'username': EMAIL_ADDRESS,
            'password': 'bad_password',
        }
        response = self.client.post(url, data)
        form = response.context_data['form']
        self.assertFalse(form.is_valid())
        self.assertTrue('__all__' in form.errors.keys())
        self.assertEqual(response.status_code, 200)


class WhitelistSucceedTestCase(TestCase):
    def setUP(self):
        self.client = Client()

    @override_settings(AD_DOMAIN_WHITELIST=[EMAIL_DOMAIN])
    def test_post_login_success_with_whitelist(self):
        url = reverse('auth_login')
        data = {
            'username': EMAIL_ADDRESS,
            'password': EMAIL_PASSWORD,
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 302)



class WhitelistFailTestCase(TestCase):
    def setUP(self):
        self.client = Client()

    @override_settings(AD_DOMAIN_WHITELIST=['microsoft.com'])
    def test_post_login_fail_with_whitelist(self):
        url = reverse('auth_login')
        data = {
            'username': EMAIL_ADDRESS,
            'password': EMAIL_PASSWORD,
        }
        response = self.client.post(url, data)
        form = response.context_data['form']
        self.assertFalse(form.is_valid())
        self.assertTrue('__all__' in form.errors.keys())
        self.assertEqual(response.status_code, 200)



class BlacklistSucceedTestCase(TestCase):
    def setUP(self):
        self.client = Client()

    @override_settings(AD_DOMAIN_BLACKLIST=['spammer.com'])
    def test_post_login_success_with_blacklist(self):
        url = reverse('auth_login')
        data = {
            'username': EMAIL_ADDRESS,
            'password': EMAIL_PASSWORD,
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 302)



class BlacklistFailTestCase(TestCase):
    def setUP(self):
        self.client = Client()

    @override_settings(AD_DOMAIN_BLACKLIST=[EMAIL_DOMAIN])
    def test_post_login_fail_with_blacklist(self):
        url = reverse('auth_login')
        data = {
            'username': EMAIL_ADDRESS,
            'password': EMAIL_PASSWORD,
        }
        response = self.client.post(url, data)
        form = response.context_data['form']
        self.assertFalse(form.is_valid())
        self.assertTrue('__all__' in form.errors.keys())
        self.assertEqual(response.status_code, 200)

