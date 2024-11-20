from django.shortcuts import render
from django.conf import settings
from eprof.services.keycloak_service import KeycloakService


# Create your views here.
def login(request):
    kc=KeycloakService.get_instance()
    authorization_url=kc.openid.auth_url(
        scope="openid profile email ",
        redirect_uri="http://localhost:8000/",
    )

    return render(request,"login.html") 