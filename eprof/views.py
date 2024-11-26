from django.shortcuts import render,redirect
from django.conf import settings
from eprof.services.keycloak_service import KeycloakService
from django.http import HttpResponse
from django.core.cache import cache
from .utils.utils import obtenerRPT
from keycloak.exceptions import KeycloakPostError
# Create your views here.
def login(request):
    kc=KeycloakService.get_instance()
    authorization_url=kc.openid.auth_url(
        redirect_uri="http://localhost:8000/callback",
        scope="openid profile email"
    )
    
    return redirect(authorization_url)

def callback(request):
    code = request.GET.get("code")
    if not code:
        return HttpResponse("Error: No code provided", status=400)

    kc = KeycloakService.get_instance()
    try:
        # Intenta obtener el token con el código de autorización
        token = kc.get_token(code)  # Obtener token normal sin permisos
        token = obtenerRPT(token["access_token"])  # Obtener token con permisos incluidos

        access_token = token["access_token"]  # Token normal
        refresh_token = token["refresh_token"]  # Token con permisos

        # Guardar tokens en la sesión
        request.session["access_token"] = access_token
        request.session["refresh_token"] = refresh_token

        # Cachear los tokens para mayor rendimiento
        cache.set("access_token", access_token, timeout=300)
        cache.set("refresh_token", refresh_token, timeout=1800)

    except KeycloakPostError as e:
        # Si el código no es válido o el token ha expirado
        if 'invalid_grant' in str(e) or 'invalid_token' in str(e):
            # Intentar usar el refresh_token si está disponible
            print("Token inválido o expirado. Intentando refrescar el token...")

            refresh_token = request.session.get("refresh_token")
            if not refresh_token:
                return HttpResponse("Error: No refresh token available", status=400)

            try:
                # Intentar obtener un nuevo access_token usando el refresh_token
                token = kc.renovarToken(refresh_token)
                token = obtenerRPT(token["access_token"])  # Obtener token con permisos incluidos

                access_token = token["access_token"]
                refresh_token = token["refresh_token"]

                # Guardar los nuevos tokens en la sesión
                request.session["access_token"] = access_token
                request.session["refresh_token"] = refresh_token

                # Cachear los tokens para mayor rendimiento
                cache.set("access_token", access_token, timeout=300)
                cache.set("refresh_token", refresh_token, timeout=1800)

            except KeycloakPostError as e:
                # Si falla al refrescar el token
                return redirect('eprof:login')

    return render(request, "login.html")

def logout(request):
    kc = KeycloakService.get_instance()

    refresh_token = cache.get("refresh_token")

    if not refresh_token:
        refresh_token = request.session.get("refresh_token")

    if refresh_token:
        request.session.flush()
        cache.clear()
        kc.openid.logout(refresh_token)
        
    return redirect('eprof:login')