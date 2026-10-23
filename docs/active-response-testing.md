# Validación automatizada de Active Response

## Alcance del cambio

Los scripts Python de CHG-021 tenían evidencia de UAT en las VMs, pero el workflow del repositorio no los comprobaba. Este incremento añade pruebas reproducibles del contrato de entrada, el protocolo de Wazuh y las operaciones solicitadas a nftables.

El cambio se limita a pruebas, CI y documentación. Conserva los scripts desplegables, la allowlist `10.77.0.10`, las reglas y la configuración del laboratorio. Las pruebas usan `unittest` de la biblioteca estándar; no incorporan dependencias Python externas ni servicios nuevos.

## Ejecución local

Desde la raíz del repositorio, con Python 3.12:

```bash
python3 -m compileall -q scripts tests
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

El workflow `Lab validation` ejecuta los mismos comandos con el Python 3.12 de Ubuntu 24.04, además de sus controles existentes de Bash, PowerShell, SSH, journald, Suricata y material privado.

Las pruebas sustituyen las llamadas a procesos por dobles controlados y escriben los registros en un directorio temporal. Se ejecutan sin Wazuh, nftables, red ni privilegios de administrador; no lanzan el harness contra una VM.

## Contratos comprobados

| Área | Comportamiento que debe conservarse |
| --- | --- |
| Entrada | JSON vacío, inválido, incompleto o con estructura inesperada falla sin invocar nftables. |
| Alcance | `add` y `delete` rechazan fuentes fuera de la allowlist, IPv6 y valores inválidos. |
| Protocolo | `add` emite `check_keys` para la fuente autorizada; sólo `continue` permite solicitar el bloqueo. `abort` y respuestas inesperadas no bloquean. |
| Contención | Se usan `/usr/sbin/nft`, la tabla `inet mini_soc_ar` y el set `blocked_ipv4`; la creación queda limitada al hook de forwarding y no escribe configuración persistente. |
| Repetición y retiro | Un elemento ya presente y un elemento/tabla ya ausente conservan el comportamiento idempotente esperado. `delete` no inicia otro intercambio `check_keys`. |
| Errores de ejecución | Fallos de creación, alta o baja del elemento y ausencia del ejecutable se informan como error, sin registrar una operación exitosa. |
| Harness | Envía la fuente autorizada, responde al `check_keys` correcto, rechaza una clave o comando inesperado y propaga la salida de error y el código de retorno del proceso. |

## Evidencia y límites

La evidencia de este incremento es la suite versionada y el resultado de `Lab validation` para el commit correspondiente. Los datos son sintéticos y no contienen alertas, PCAP ni registros de las VMs.

Estas pruebas comprueban decisiones del código y solicitudes a procesos simulados. No demuestran el procesamiento real de reglas por el kernel, pérdida/recuperación de conectividad, salud de agentes ni entrega del `delete` temporizado por Wazuh. La evidencia de esas capacidades sigue siendo el UAT documentado en [CHG-021](CHG-021.md); este cambio no afirma haberlo repetido.

El plazo de 60 segundos pertenece a la configuración de Wazuh. El set nftables no tiene expiración propia: el retiro depende de recibir y ejecutar `delete`. Persisten los límites documentados de ownership runtime/persistente y la necesidad de revisar fallos de infraestructura antes de un uso productivo. Las pruebas tampoco cubren todas las condiciones de concurrencia, bloqueo de pipes, permisos de logs o variantes de mensajes de error de nftables.

Una limitación adicional del código actual es que interpreta cualquier retorno no exitoso de `nft list table` como tabla ausente. En `delete`, un error de consulta por permisos podría registrarse como `table_absent=true`. Las pruebas de tabla ausente usan el error esperado de inexistencia; no certifican esa distinción. Corregirla requiere un incremento del comportamiento runtime con su prueba de regresión y UAT, separado de esta incorporación de controles.

Como los scripts y las configuraciones de las VMs no cambian, no se requiere un nuevo despliegue para este incremento. Un cambio posterior del comportamiento de respuesta debe pasar por el flujo de control de cambios y UAT del laboratorio.

## Rollback

Revertir el commit de pruebas, workflow y documentación restaura el estado anterior del repositorio. No hay estado de firewall, agentes ni configuración de VM que restaurar. Este documento describe el alcance de validación; la implementación de los scripts y la configuración de CHG-021 continúan siendo las fuentes de verdad del comportamiento.
