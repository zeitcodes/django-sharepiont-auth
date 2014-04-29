Django SharePoint Auth
======================

*Django SharePoint Auth* allows you to authenticate using your **managed** or **federated** Active Directory credentials.

Installation
------------

Run `pip install django-sharepoint-auth`

Add the `ActiveDirectoryBackend` to your `AUTHENTICATION_BACKENDS` setting:

```python
AUTHENTICATION_BACKENDS = (
    ...
    'sharepoint_auth.auth.ActiveDirectoryBackend',
)
```
