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
printf '\n# Capacidad validada para EVE stats del laboratorio.\nanalysisd.decoder_order_size=512\n' >> "$staged"
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

**Estado:** propuesta preparada; reproducción sintética en Wazuh, instalación, UAT y consumo posterior pendientes. Las salidas de las VMs son aportadas por el operador: la sesión de asistencia no tiene acceso directo a ellas. La CI valida los controles existentes del repositorio; no ejecuta Wazuh Manager ni acredita este UAT.

## Rollback

Restaurar el contenido del archivo local desde la ruta exacta de respaldo mostrada por el instalador, conservando propietario/permisos. Ejecutar `/var/ossec/bin/wazuh-analysisd -t` y reiniciar `wazuh-manager` con systemd únicamente si la validación termina correctamente. Confirmar puerto 1514 y conexión del gateway. El rollback vuelve a admitir el límite anterior y puede reintroducir truncamiento de campos; no cambia las reglas persistentes del gateway.

El revert en Git no restaura por sí solo la configuración de la VM. No borrar otras opciones locales ni copiar el fragmento versionado encima del archivo completo.

## Referencias

- [Wazuh: opciones internas y archivo de overrides](https://documentation.wazuh.com/current/user-manual/reference/internal-options.html).
- [Wazuh 4.14.8: límite predeterminado](https://github.com/wazuh/wazuh/blob/v4.14.8/etc/internal_options.conf).
- [Wazuh 4.14.8: extracción de campos JSON](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/decoders/plugins/json_decoder.c).
- [Wazuh: pruebas de reglas y decodificadores](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html).
