from django.conf.urls import patterns, include, url
from django.contrib.auth import views


urlpatterns = patterns('',
    url(r'^login/$', views.login, name='auth_login'),
    url(r'^logout/$', views.logout, name='auth_logout'),
)
