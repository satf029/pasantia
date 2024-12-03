
from django.urls import path
from eprof import views

urlpatterns = [
    path('',views.login, name='login'),
    path('callback',views.callback, name='callback'),
    path('logout',views.logout, name='logout')
]