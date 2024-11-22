from django.conf import settings
from keycloak import (
    KeycloakAdmin,
    KeycloakOpenID,
    KeycloakOpenIDConnection,
    KeycloakUMA,
)


class KeycloakService:
    """
    Clase que proporciona servicios de autenticación e interacción con Keycloak.

    Esta clase encapsula las operaciones relacionadas con la autenticación de usuarios y la administración
    utilizando el cliente KeycloakOpenID y KeycloakAdmin.

    :param server_url: La URL del servidor Keycloak.
    :type server_url: str
    :param client_id: El ID del cliente registrado en Keycloak.
    :type client_id: str
    :param realm_name: El nombre del reino en Keycloak.
    :type realm_name: str
    :param client_secret_key: La clave secreta del cliente para autenticación.
    :type client_secret_key: str
    :param username: Nombre de usuario para la administración de Keycloak.
    :type username: str
    :param password: Contraseña para la administración de Keycloak.
    :type password: str
    :param user_realm_name: Nombre del reino del usuario para la administración.
    :type user_realm_name: str
    """

    _instance = None

    def __init__(self):
        """
        Inicializa una instancia de KeycloakService con las configuraciones necesarias.

        Configura los clientes KeycloakOpenID y KeycloakAdmin usando las configuraciones del entorno.
        """
        self.openid = KeycloakOpenID(
            server_url=settings.KEYCLOAK_SERVER_URL,
            client_id=settings.KEYCLOAK_CLIENT_ID,
            realm_name=settings.KEYCLOAK_REALM,
            client_secret_key=settings.KEYCLOAK_CLIENT_SECRET,
        )
        self.admin = KeycloakAdmin(
            server_url=settings.KEYCLOAK_SERVER_URL,
            username="admin",
            password="admin",
            realm_name=settings.KEYCLOAK_REALM,
            user_realm_name="master",
        )

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = KeycloakService()
        return cls._instance

    def get_token(self, code):
        """
        Obtiene un token de acceso de Keycloak usando un código de autorización.

        Utiliza el código de autorización recibido para obtener un token de acceso y de actualización.

        :param code: El código de autorización recibido de Keycloak.
        :type code: str
        :return: Un diccionario con el token de acceso y otros datos relacionados.
        :rtype: dict
        """
        redirect_uri = "http://localhost:8000/callback/"
        token = self.openid.token(
            code=code, redirect_uri=redirect_uri, grant_type="authorization_code"
        )
        return token

    def get_userId(self, token):
        """
        Obtiene el ID del usuario a partir del token de acceso.

        Extrae el ID del usuario (sub) del token de acceso proporcionado.

        :param token: El token de acceso de Keycloak.
        :type token: dict
        :return: El ID del usuario.
        :rtype: str
        """
        user_info = self.openid.userinfo(token)
        return user_info.get("sub")

    def isActive(self, token):
        """
        Verifica si el token de acceso está activo.

        Realiza una introspección del token para determinar su estado de actividad.

        :param token: El token de acceso de Keycloak.
        :type token: dict
        :return: Verdadero si el token está activo, falso en caso contrario.
        :rtype: bool
        """
        return self.openid.introspect(token).get("active")

    def renovarToken(self, refresh_token):
        """
        Renueva el token de acceso usando el token de actualización.

        Solicita un nuevo token de acceso utilizando el token de actualización proporcionado.

        :param token: El token de actualización de Keycloak.
        :type token: dict
        :return: Un diccionario con el nuevo token de acceso y otros datos relacionados.
        :rtype: dict
        """
        return self.openid.refresh_token(refresh_token)

    def get_permisos(self, token):
        return self.openid.uma_permissions(token)
