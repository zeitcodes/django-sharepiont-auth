Django SharePoint Auth
======================

*Django SharePoint Auth* allows you to authenticate using your SharePoint credentials.

Installation
------------

Run `pip install django-sharepoint-auth`

Add the `SharePointBackend` to your `AUTHENTICATION_BACKENDS` setting:

```python
AUTHENTICATION_BACKENDS = (
    ...
    'sharepoint_auth.auth.SharePointBackend',
)
```

Add a `SHAREPOINT_URL` setting for your SharePoint URL.

```python
    SHAREPOINT_URL = 'http://mycompany.sharepoint.com'
```
