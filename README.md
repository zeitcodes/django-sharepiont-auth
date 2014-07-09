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

Settings
--------

###AD_USER_CREATION

**default:** `True`
Allow creation of new users after successful authentication.


###AD_DOMAIN_WHITELIST

**default:** `None`
Either `None` meaning allow all or a list of domains that can authenticate through Active Directory.

###AD_DOMAIN_BLACKLIST

**default:** `[]`
A list of domain that will be block from authenticating through Active Directory.
