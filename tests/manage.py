#!/usr/bin/env python
import os
import sys

if __name__ == "__main__":
    sys.path.insert(0, '/Users/Jason/SkyDrive/Projects/apps/django-sharepoint-auth')

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "testsite.settings")

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
