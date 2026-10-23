# Validación automatizada de Active Response

## Alcance del cambio

Los scripts Python de CHG-021 tenían evidencia de UAT en las VMs, pero el workflow del repositorio no los comprobaba. Este incremento añade pruebas reproducibles del contrato de entrada, el protocolo de Wazuh y las operaciones solicitadas a nftables.

La incorporación inicial (PR #48) se limitó a pruebas, CI y documentación. La [corrección de la consulta de tabla](active-response-table-query.md) añade comprobaciones de inventario JSON y una prueba de integración con nftables real. Conserva la allowlist `10.77.0.10`, las reglas y la configuración de Wazuh. Las pruebas usan la biblioteca estándar; no incorporan dependencias Python externas ni servicios nuevos.

## Ejecución local

Desde la raíz del repositorio, con Python 3.12:

```bash
python3 -m compileall -q scripts tests
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

El workflow `Lab validation` ejecuta los mismos comandos con el Python 3.12 de Ubuntu 24.04, además de sus controles existentes de Bash, PowerShell, SSH, journald, Suricata y material privado.

Las pruebas unitarias sustituyen las llamadas a procesos por dobles controlados y escriben los registros en un directorio temporal. Se ejecutan sin Wazuh, nftables, red ni privilegios de administrador; no lanzan el harness contra una VM.

La integración requiere Linux, nftables, Python 3 y util-linux (`unshare` y `setpriv`). Se ejecuta en un namespace de red nuevo y descarta su estado al salir:

```bash
sudo unshare --net -- python3 tests/integration/active_response_nft.py
```

Esta prueba rechaza el namespace del host y cualquier namespace que ya contenga tablas. Usa nftables real para comprobar ausencia, alta, repetición, retiro y denegación de permisos al quitar `CAP_NET_ADMIN` en procesos hijos. Los registros se escriben en un directorio temporal; no se instala nada en Wazuh. GitHub Actions instala nftables y ejecuta esta comprobación adicional.

## Contratos comprobados

| Área | Comportamiento que debe conservarse |
| --- | --- |
| Entrada | JSON vacío, inválido, incompleto o con estructura inesperada falla sin invocar nftables. |
| Alcance | `add` y `delete` rechazan fuentes fuera de la allowlist, IPv6 y valores inválidos. |
| Protocolo | `add` emite `check_keys` para la fuente autorizada; sólo `continue` permite solicitar el bloqueo. `abort` y respuestas inesperadas no bloquean. |
| Contención | Se usan `/usr/sbin/nft`, la tabla `inet mini_soc_ar` y el set `blocked_ipv4`; la creación queda limitada al hook de forwarding y no escribe configuración persistente. |
| Repetición y retiro | Un elemento ya presente y un elemento/tabla ya ausente conservan el comportamiento idempotente esperado. `delete` no inicia otro intercambio `check_keys`. |
| Errores de ejecución | Fallos de creación, alta o baja del elemento y ausencia del ejecutable se informan como error, sin registrar una operación exitosa. |
| Consulta de estado | Un fallo de consulta o un inventario inválido termina con error, sin declarar ausencia ni solicitar modificaciones. La identidad de tabla requiere nombre y familia exactos. |
| Harness | Envía la fuente autorizada, responde al `check_keys` correcto, rechaza una clave o comando inesperado y propaga la salida de error y el código de retorno del proceso. |

## Evidencia y límites

La evidencia de este incremento es la suite versionada y el resultado de `Lab validation` para el commit correspondiente. Los datos son sintéticos y no contienen alertas, PCAP ni registros de las VMs.

Las pruebas unitarias comprueban decisiones del código y solicitudes a procesos simulados. La integración comprueba operaciones nftables reales dentro de un namespace descartable. Ninguna acredita pérdida/recuperación de conectividad de SOC-TEST-01, salud de agentes ni entrega del `delete` temporizado por Wazuh. La evidencia histórica de esas capacidades sigue siendo el UAT documentado en [CHG-021](CHG-021.md); la aceptación de la versión corregida requiere repetirlo.

El plazo de 60 segundos pertenece a la configuración de Wazuh. El set nftables no tiene expiración propia: el retiro depende de recibir y ejecutar `delete`. Persisten los límites documentados de ownership runtime/persistente y la necesidad de revisar fallos de infraestructura antes de un uso productivo. Las pruebas tampoco cubren todas las condiciones de concurrencia, bloqueo de pipes, permisos de logs o variantes de mensajes de error de nftables.

La confusión entre error de consulta y tabla ausente tiene una prueba de regresión que falló con la versión anterior y pasó con la corrección. El [registro del cambio](active-response-table-query.md) conserva el estado de aceptación y el procedimiento de UAT; un resultado CI no se presenta como despliegue o validación completa de las VMs.

## Rollback

Para revertir sólo controles de CI y pruebas basta revertir su commit. Si se despliega la corrección del script, también corresponde el [rollback de la VM](active-response-table-query.md#rollback). Este documento describe el alcance de validación; la implementación de los scripts y la configuración de CHG-021 continúan siendo las fuentes de verdad del comportamiento.
