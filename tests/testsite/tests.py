from django.core.urlresolvers import reverse
from django.test import TestCase, Client


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
            'username': 'jason@zeitcode.com',
            'password': '**use real password**',
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 302)

    def test_post_login_fail(self):
        url = reverse('auth_login')
        data = {
            'username': 'jason@zeitcode.com',
            'password': 'bad_password',
        }
        response = self.client.post(url, data)
        form = response.context_data['form']
        self.assertFalse(form.is_valid())
        self.assertTrue('__all__' in form.errors.keys())
        self.assertEqual(response.status_code, 200)
