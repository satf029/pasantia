from django.shortcuts import render,redirect
from django.conf import settings
from eprof.services.keycloak_service import KeycloakService
from django.http import HttpResponse

# Create your views here.
def login(request):
    kc=KeycloakService.get_instance()
    authorization_url=kc.openid.auth_url(
        redirect_uri="http://localhost:8000/",
        scope="openid profile email ",
        
    )
    
    return redirect(authorization_url)