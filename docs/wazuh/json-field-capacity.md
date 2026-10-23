# Capacidad de campos JSON del manager

## Problema y evidencia de partida

Durante el UAT de la corrección de Active Response se observaron errores repetidos `Too many fields for JSON decoder` en Wazuh Manager 4.14.8. La opción empaquetada era `analysisd.decoder_order_size=256`; la búsqueda de esa opción en `local_internal_options.conf` no produjo coincidencias.

El operador examinó hasta las últimas 1000 líneas del EVE actual de SOC-GW-01. La muestra contenía 79 eventos JSON válidos, sin líneas omitidas:

| Tipo | Eventos | Máximo aproximado de campos hoja | Eventos por encima de 256 |
| --- | ---: | ---: | ---: |
| `stats` | 77 | 456 | 77 |
| `flow` | 2 | 20 | 0 |

El recuento desciende por objetos anidados y cuenta cada array como un campo; es orientativo y no sustituye al decodificador real. Esta muestra apunta a las estadísticas de Suricata como fuente del exceso. No incluyó eventos `alert`, por lo que no permite afirmar que las alertas hayan sido verificadas.

El código de Wazuh 4.14.8 registra el error al intentar agregar un campo dinámico después de alcanzar el límite. Se omiten esos campos adicionales; no debe describirse como prueba de descarte completo de todos los eventos. También pueden generarse múltiples mensajes de error por un solo evento grande.

La interrupción TCP anterior coincidió con un reinicio del manager entre 04:58:18 y 04:58:43 UTC del 2026-10-23. El gateway reconectó a las 01:58:43-03:00 y se verificó `connected` con ACK reciente a las 02:06:36-03:00. Esto es evidencia de transporte distinta del problema de capacidad JSON; no se atribuye el reinicio a este error.

## Cambio acotado y riesgo

El [fragmento versionado](../../config/manager/local_internal_options.conf) eleva el límite a **512** mediante `/var/ossec/etc/local_internal_options.conf`. Se combina esa única opción con el contenido existente; no se reemplaza el archivo entero. La documentación oficial admite valores de 32 a 1024 y prescribe el archivo local para conservar personalizaciones durante actualizaciones.

512 cubre los 456 campos estimados con margen de 56. El ajuste conserva la entrada EVE actual, los eventos de estadísticas y las reglas de detección. No añade listeners, agentes, filtros, dependencias ni cambios al script de Active Response. Es un cambio independiente de la corrección de consultas nftables.

El límite afecta globalmente al motor de análisis y puede aumentar el consumo de memoria por evento. Requiere un reinicio breve del manager, con interrupción temporal de la telemetría. Registrar recursos antes/después, comprobar reconexión y mantener disponible el respaldo. La muestra es limitada y eventos futuros pueden superar 512; el ajuste no demuestra capacidad de producción ni elimina la necesidad de revisar qué telemetría resulta útil.

## Prueba sintética antes y después

En SOC-MGMT-01, ejecutar esta prueba antes del cambio y repetirla después del reinicio. Usa una sesión de `wazuh-logtest` y un JSON sintético de 456 campos hoja, sin datos reales ni firma de Active Response. No genera tráfico de prueba entre VMs.

```bash
sudo python3 - <<'PY'
import json
import subprocess

stats = {f"f{i:03d}": i for i in range(454)}
stats["uat_end_marker"] = "json-fields-456"
payload = json.dumps({"event_type": "stats", "stats": stats}, separators=(",", ":"))
result = subprocess.run(
    ["/var/ossec/bin/wazuh-logtest", "-v"],
    input=payload + "\n", text=True, capture_output=True, timeout=30,
)
lines = (result.stdout + "\n" + result.stderr).splitlines()
print("Retorno logtest:", result.returncode)
print("Campos numerados decodificados:", sum(
    line.strip().startswith("stats.f") for line in lines
))
print("Campo final decodificado:", any(
    line.strip().startswith("stats.uat_end_marker:") for line in lines
))
print("Error de limite en salida:", any(
    "Too many fields for JSON decoder" in line for line in lines
))
for line in lines:
    if line.strip().startswith(("name:", "stats.uat_end_marker:")):
        print(line.strip())
if result.returncode:
    for line in lines[-10:]:
        print(line[:240])
PY
```

Con el decodificador JSON y el límite 256 se espera extracción incompleta (255 campos numerados y marcador final ausente). Con 512 deben aparecer los **454 campos numerados**, el marcador final y el decodificador `json`, sin error de límite. Un retorno cero de logtest por sí solo no prueba que todos los campos hayan sido extraídos. Si el resultado no coincide, revisar antes de aplicar o aceptar el cambio.

## Activación en SOC-MGMT-01

Precondiciones: CI del PR aprobado, prueba sintética previa documentada, manager activo, gateway conectado y ausencia de bloqueos de Active Response pendientes. No generar eventos de respuesta mientras se reinicia el manager. Capturar `free -h` y `systemctl show wazuh-manager -p MemoryCurrent -p MemoryPeak` antes/después como referencia local, sin inferir causalidad sólo a partir de dos muestras.

El siguiente bloque exige que no exista ya una asignación local para esa opción. Conserva propietario y permisos, prepara el archivo completo antes del reemplazo y valida la configuración antes de reiniciar. Si hay una configuración local concurrente, detenerse y revisarla en lugar de duplicar asignaciones.

```bash
sudo bash -euo pipefail <<'SH'
test "$(hostname)" = soc-mgmt-01
systemctl is-active --quiet wazuh-manager
cfg=/var/ossec/etc/local_internal_options.conf
test -f "$cfg"
test ! -L "$cfg"
if grep -Eq '^[[:space:]]*analysisd[.]decoder_order_size[[:space:]]*=' "$cfg"; then
    printf 'Ya existe una asignacion local: revisar antes de continuar.\n' >&2
    exit 1
fi
backup=$(mktemp "${cfg}.pre-json512.XXXXXX")
cp -p -- "$cfg" "$backup"
printf 'Respaldo: %s\n' "$backup"
staged=$(mktemp "${cfg}.new.XXXXXX")
trap 'rm -f -- "$staged"' EXIT
cp -p -- "$cfg" "$staged"
printf '\n# Capacidad para EVE stats del laboratorio.\nanalysisd.decoder_order_size=512\n' >> "$staged"
mv -f -- "$staged" "$cfg"
if ! /var/ossec/bin/wazuh-analysisd -t; then
    cp -p -- "$backup" "$cfg"
    printf 'Validacion fallida: se restauro el archivo anterior.\n' >&2
    exit 1
fi
if ! systemctl restart wazuh-manager; then
    cp -p -- "$backup" "$cfg"
    systemctl restart wazuh-manager
    printf 'Activacion fallida: se restauro la configuracion anterior.\n' >&2
    exit 1
fi
systemctl is-active wazuh-manager
/var/ossec/bin/wazuh-control status
ss -lntp '( sport = :1514 )'
SH
```

Conservar la ruta exacta del respaldo. Si la recuperación automática del servicio también falla, mantener la sesión administrativa y revisar el journal; no asumir restauración operativa sólo porque se restauró el archivo.

## UAT y cierre

1. Repetir la prueba sintética: extracción completa de los 456 campos y marcador final presente.
2. Confirmar `wazuh-remoted`, `wazuh-analysisd`, TCP/1514 y reconexión del gateway con ACK reciente.
3. Observar nuevos eventos `stats` de EVE durante al menos 60 segundos y comprobar que no aparecen nuevos errores de capacidad en el manager durante el mismo intervalo. Verificar producción/recepción de telemetría para evitar confundir ausencia de errores con ausencia de eventos. Conservar evidencia local acotada; no activar archivos globales ni debug permanente para esta prueba.
4. Revisar salud y recursos del manager tras el cambio. Errores posteriores deben investigarse por su fuente; no elevar automáticamente el límite a 1024.
5. Completar el UAT automático de [CHG-021](../CHG-021.md) con una única señal autorizada, `ADD`, contención, `DELETE` por timeout y recuperación. La ausencia de errores JSON no sustituye esa validación.
6. Registrar resultados sanitizados, SHA del PR, versión de Wazuh y alcance de la muestra antes de integrar el cambio en main.

**Estado:** UAT aprobado el **2026-10-23** para la muestra y el escenario documentados a continuación. Las salidas de las VMs fueron aportadas por el operador: la sesión de asistencia no tiene acceso directo a ellas. La CI valida los controles existentes del repositorio; no ejecuta Wazuh Manager ni acredita por sí sola este UAT. Los controles del commit final y la integración se registran en el [PR #50](https://github.com/Dante2617012022/mini-soc-lab/pull/50).

## Evidencia de aceptación — 2026-10-23

Se aplicó la opción del commit `cfe6ebaca0e1646abf6bcf2ab1478e60b99e0aa3` en Wazuh Manager 4.14.8, mediante el archivo local y con respaldo conservado en la VM. Los [controles de esa revisión](https://github.com/Dante2617012022/mini-soc-lab/actions/runs/39905192477) habían pasado antes de la instalación. Las modificaciones posteriores de este registro no alteran el valor configurado.

### Decodificación y conectividad

El JSON sintético ocupa 4951 bytes y contiene 456 campos hoja: `event_type`, 454 campos numerados y el marcador final.

| Comprobación | Antes: límite 256 | Después: límite 512 |
| --- | --- | --- |
| Decodificador | `json` | `json` |
| Campos numerados extraídos | 255 de 454 | 454 de 454 |
| Marcador final | Ausente | `json-fields-456` presente |
| Retorno de logtest | 0 | 0 |
| Texto del error de límite en la CLI | Ausente | Ausente |

El resultado inicial reprodujo extracción incompleta pese al retorno cero y a la ausencia del mensaje de error en la CLI. El resultado posterior confirmó la extracción completa del evento sintético.

A las 05:35:42 UTC se verificó una única asignación local `analysisd.decoder_order_size=512`, el listener TCP/1514 de `wazuh-remoted` y la prueba sintética completa. El manager había vuelto activo tras el reinicio, con `analysisd`, `remoted` y `execd` en ejecución. A las 05:35:58 UTC, SOC-GW-01 figuraba `connected`, con keepalive y ACK de las 05:35:55 UTC.

### Telemetría real durante 65 segundos

Las lecturas del gateway se tomaron entre 05:43:56 y 05:45:01 UTC. Los contadores conservaban el mismo inicio de acumulación y su marca de actualización avanzó de 05:43:38 a 05:44:38 UTC.

| Comprobación | Inicio | Fin |
| --- | ---: | ---: |
| Eventos EVE recogidos | 318 | 325 |
| Bytes EVE recogidos | 2480926 | 2536198 |
| Descartes al destino `agent` | 0 | 0 |
| Último evento `stats`, hora UTC | 05:43:52 | 05:44:56 |
| Campos estimados en ese `stats` | 456 | 456 |

Se recogieron 7 eventos adicionales y 55272 bytes. El agente continuó conectado, con ACK de 05:44:55 UTC. A las 05:45:27 UTC, el manager seguía activo y el archivo de log consultado contenía **cero errores nuevos de capacidad desde 05:35:42 UTC**, una ventana de 9 minutos y 45 segundos que cubre la observación del gateway. `wazuh-remoted.state` mostraba cola vacía, `evt_count=145` y `discarded_count=0`.

Los contadores del manager son agregados: no identifican individualmente todos los eventos EVE. Esta evidencia acredita producción y recogida de estadísticas nuevas, conexión activa y ausencia del error observado durante la ventana. No se activó archivado global ni debug permanente para forzar visibilidad de eventos de nivel 0.

### Recursos

| Momento | `MemoryCurrent`, bytes | Memoria disponible de la VM |
| --- | ---: | --- |
| Antes del reinicio | 4863549440 | 5,1 GiB |
| 05:35:42 UTC | 862601216 | 5,3 GiB |
| 05:45:27 UTC | 4945412096 | No capturada en esa lectura |

A las 05:55:42 UTC, la VM tenía 5,0 GiB disponibles de 7,8 GiB totales y 1,3 MiB de swap usada. El desglose del cgroup del manager fue `anon=571310080`, `file=4270223360`, `kernel=155549696` y `slab=146001080` bytes. Predominó memoria de archivos/caché; `slab` forma parte de `kernel` y no debe sumarse otra vez. Los contadores `low`, `high`, `max`, `oom`, `oom_kill` y `oom_group_kill` fueron cero.

No se observó presión de memoria en esta muestra. Las lecturas separadas por el reinicio no permiten atribuir al ajuste la caída inicial ni el aumento posterior de `MemoryCurrent`; tampoco acreditan capacidad sostenida de producción.

### Regresión de detección y respuesta

El ensayo automático de la corrección independiente [#49](https://github.com/Dante2617012022/mini-soc-lab/pull/49) se completó después del ajuste JSON, con el script de la revisión `3a0dda469b01192b03eaf83d237a27ed34210a8c`.

- Un único disparo autorizado generó la alerta central a las **05:54:51.734 UTC**: agente `002`, regla Wazuh `100021`, firma Suricata `1000001` y fuente `10.77.0.10`.
- Se registró `ADD` a las 05:54:51 UTC y `DELETE` a las 05:55:52 UTC: 61 segundos, compatibles con el timeout configurado de 60 segundos.
- SOC-TEST-01 pasó de 3/3 respuestas a 0/3 durante la contención y volvió a 3/3 a las 05:56:05 UTC. El bloque de prueba no llamó al harness manual.
- A las 06:01:59 UTC, el set estaba vacío, el agente continuaba conectado con ACK de 06:01:38 UTC, los servicios `wazuh-agent`, `suricata` y `nftables` estaban activos y `net.ipv4.ip_forward=1`.

La correlación central y los estados observados cierran la regresión de detección, respuesta y recuperación para este escenario. La muestra inicial de estadísticas y esta alerta controlada son evidencias distintas; no se generaliza el resultado a todas las reglas o tipos de eventos.

## Rollback

Restaurar el contenido del archivo local desde la ruta exacta de respaldo mostrada por el instalador, conservando propietario/permisos. Ejecutar `/var/ossec/bin/wazuh-analysisd -t` y reiniciar `wazuh-manager` con systemd únicamente si la validación termina correctamente. Confirmar puerto 1514 y conexión del gateway. El rollback vuelve a admitir el límite anterior y puede reintroducir truncamiento de campos; no cambia las reglas persistentes del gateway.

El revert en Git no restaura por sí solo la configuración de la VM. No borrar otras opciones locales ni copiar el fragmento versionado encima del archivo completo.

## Referencias

- [Wazuh: opciones internas y archivo de overrides](https://documentation.wazuh.com/current/user-manual/reference/internal-options.html).
- [Wazuh 4.14.8: límite predeterminado](https://github.com/wazuh/wazuh/blob/v4.14.8/etc/internal_options.conf).
- [Wazuh 4.14.8: extracción de campos JSON](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/decoders/plugins/json_decoder.c).
- [Wazuh: pruebas de reglas y decodificadores](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html).
- [Wazuh: estadísticas del collector](https://documentation.wazuh.com/current/user-manual/reference/statistics-files/wazuh-logcollector-state.html).
- [Linux: contabilidad de memoria en cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html#memory).
