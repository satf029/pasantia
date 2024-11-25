from eprof.utils.utils import comprobarToken, obtenerToken
from django.shortcuts import redirect

# Middleware que verifica el token antes de cada solicitud
class KeycloakTokenMiddleware:
    """Middleware que verifica el token antes de cada solicitud.

    Este middleware se encarga de verificar la validez del token de autenticación
    en cada solicitud, excepto en la ruta de logout. Si el token ha expirado, 
    redirige al usuario a la página de inicio de sesión.

    Attributes:
        get_response (callable): Función que se llama para procesar la solicitud
                                  después de que se ejecuta el middleware.
    """
    def __init__(self, get_response):
        """Inicializa el middleware.

        Args:
            get_response (callable): Función que se llama para procesar la solicitud
                                      después de que se ejecuta el middleware.
        """
        self.get_response = get_response

    def __call__(self, request):
        """Procesa la solicitud y verifica el token.

        Args:
            request (HttpRequest): La solicitud HTTP que se está procesando.

        Returns:
            HttpResponse: La respuesta HTTP después de procesar la solicitud.

        
        """
        # Omitir la verificación del token en la ruta de logout
        if request.path == '/logout':
            return self.get_response(request)
        
        # Obtener token de la cache o la sesión
        token = obtenerToken(request)

        # Verificar el token
        try:
            comprobarToken(request, token)
        except Exception as e:
            print("El token ya expiró, redirigiendo a la página de inicio")
            return redirect('logout')


        return self.get_response(request)