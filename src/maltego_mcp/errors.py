"""Errores de dominio. Sus mensajes se muestran al agente: deben ser accionables y sin secretos."""


class MaltegoMcpError(Exception):
    """Error esperado cuyo mensaje es seguro para devolver al cliente MCP."""


class InvalidInput(MaltegoMcpError):
    """Entrada inválida (valor, tipo de entidad, case_id...)."""


class NotFound(MaltegoMcpError):
    """El recurso solicitado no existe."""


class BackendError(MaltegoMcpError):
    """Fallo del almacenamiento del grafo."""


class TransformError(MaltegoMcpError):
    """Fallo al ejecutar un transform de Maltego."""


class ConfigError(MaltegoMcpError):
    """Configuración del servidor incorrecta."""
