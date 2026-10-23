# Active Response: distinguir ausencia de tabla y fallo de consulta

## Problema y cambio mínimo

El script de CHG-021 trataba cualquier retorno no exitoso de `nft list table inet mini_soc_ar` como tabla ausente. Durante `delete`, un error de permisos podía terminar con código 0 y `table_absent=true`, aunque no se hubiese comprobado ni retirado el bloqueo. Durante `add`, ese mismo error permitía intentar crear la tabla.

La corrección consulta `nft -j list tables` y sólo reconoce ausencia cuando la consulta termina correctamente, entrega una estructura válida y no contiene la tabla de familia `inet` llamada `mini_soc_ar`. Los errores de ejecución o formato terminan con código 1, registro `ERROR` y ninguna operación posterior sobre el firewall.

Se conserva la allowlist, el intercambio `check_keys`, la tabla runtime, el set y la configuración de Wazuh. No se agrega ningún servicio, dependencia Python, fuente de configuración ni interfaz de administración.

## Riesgo, validación y evidencia

El riesgo abordado es informar un retiro exitoso sin haber podido verificar el estado real. La nueva consulta requiere la salida JSON soportada por nftables; cualquier incompatibilidad se informa como error en lugar de interpretar ausencia. La sintaxis y el esquema se contrastaron con [nft(8)](https://www.netfilter.org/projects/nftables/manpage.html) y [libnftables-json(5) de Debian 13](https://manpages.debian.org/trixie/libnftables1/libnftables-json.5.en.html).

La prueba de regresión falló con el script anterior en `add` (intentaba crear la tabla después del error) y `delete` (devolvía código 0). Con la corrección pasan las 27 pruebas unitarias. La suite cubre tabla presente, ausencia confirmada, coincidencia exacta de nombre/familia, JSON inválido o incompleto y comportamiento `add/delete` existente.

CI incorpora además una prueba con nftables real en un namespace descartable. Comprueba el set después de altas/retiros, repeticiones y denegaciones reales de `CAP_NET_ADMIN`. El entorno local de esta sesión no permite crear el namespace; la prueba pasó en GitHub Actions y el operador la repitió correctamente en Debian antes del despliegue.

Se conserva como evidencia pública el código, la suite y la ejecución CI del commit. Cualquier evidencia de las VMs se publica únicamente después de sanitizarla. La validación automatizada no acredita por sí sola conectividad, salud de Wazuh ni timeout real.

## Estado de aceptación

- Corrección y 27 pruebas unitarias: completadas localmente; sintaxis Python y revisión de espacios aprobadas.
- GitHub Actions de la versión ensayada: [Lab validation](https://github.com/Dante2617012022/mini-soc-lab/actions/runs/39898079455) aprobado para `3a0dda469b01192b03eaf83d237a27ed34210a8c`, incluidas las 27 pruebas unitarias, la integración con nftables real v1.0.9 y todos los controles existentes.
- UAT de la versión corregida: aprobado el **2026-10-23**, con evidencia de consola aportada por el operador. La sesión de asistencia no tiene conexión directa a las VMs.
- Los controles del commit final y la integración se registran en el [PR #49](https://github.com/Dante2617012022/mini-soc-lab/pull/49), siguiendo [el flujo de cambios](change-control.md). Las actualizaciones de este registro no cambian el script ensayado.

## Evidencia del UAT de la corrección — 2026-10-23

Se ensayó `3a0dda469b01192b03eaf83d237a27ed34210a8c` en SOC-GW-01 con Debian 13, Python 3.13.5 y nftables 1.1.3. Pasaron las 27 pruebas unitarias y la integración real en namespace descartable, incluidas denegaciones de permisos en `add/delete`. Después se instaló únicamente el script, con respaldo local, propietario/grupo `root:wazuh` y modo `750`.

El archivo fuente y el instalado tuvieron el mismo SHA-256: `3308c834260a4460cee910515e33aa21cecaa340002de1e2eee1aaa979506170`.

El UAT manual confirmó conectividad inicial 3/3, alta limitada a la fuente autorizada, contención 0/3, retiro con set vacío y recuperación 3/3. Los registros fueron `ADD` a las 01:37:26-03:00 y `DELETE` a las 01:39:05-03:00. Ese retiro manual no acredita el timeout.

Antes del ensayo automático se recuperó la conexión del agente y se resolvió, en el cambio independiente [#50](https://github.com/Dante2617012022/mini-soc-lab/pull/50), el límite de campos JSON observado en estadísticas EVE. La desconexión había coincidido con un reinicio del manager; no se atribuye ese reinicio al error JSON ni a esta corrección.

El ensayo automático utilizó un único ICMP autorizado desde SOC-TEST-01 hacia el gateway. Las horas siguientes están normalizadas a UTC; el gateway y el equipo de prueba mostraban UTC-03:00.

| Momento UTC | Evidencia observada |
| --- | --- |
| Antes del disparo | Conectividad de SOC-TEST-01: 3 enviados / 3 recibidos |
| 05:54:51 | Disparo único y registro `ADD source=10.77.0.10` |
| 05:54:51.734 | Alerta central: agente `002`, regla `100021`, firma Suricata `1000001`, fuente autorizada `10.77.0.10` |
| 05:54:56 | Prueba durante la contención: 3 enviados / 0 recibidos |
| 05:55:02 | El set contenía únicamente `10.77.0.10`; agente conectado, servicios activos e IP forwarding habilitado |
| 05:55:52 | Registro `DELETE source=10.77.0.10`, 61 segundos después del alta, compatible con el timeout configurado de 60 segundos |
| 05:56:05 | Recuperación: 3 enviados / 3 recibidos |
| 06:01:59 | Set vacío; agente `connected`, keepalive/ACK de 06:01:38; `wazuh-agent`, `suricata` y `nftables` activos; `net.ipv4.ip_forward=1` |

El bloque ejecutado para el ensayo automático sólo generó el disparo y comprobó conectividad; no invocó el harness manual. La evidencia conjunta acredita detección, contención y retiro temporizado para esta ejecución controlada. No constituye una prueba de carga, disponibilidad prolongada ni capacidad de producción. Disposición: **True Positive — Authorized Security Test / Benign**.

## UAT en SOC-GW-01

Ejecutar desde la consola de la VM del gateway durante una ventana de laboratorio, sin generar simultáneamente eventos de Active Response. Primero verificar `hostname`, `python3 --version` y `sudo /usr/sbin/nft --version`. Se necesita git para obtener la revisión; `nftables`, Python 3 y `util-linux` para la prueba aislada. Los ejemplos usan `sudo`; en una sesión ya iniciada como `root`, omitir ese prefijo.

### 1. Obtener la versión y comprobarla sin desplegar

Usar un directorio nuevo para conservar cualquier copia existente del proyecto:

```bash
git clone https://github.com/Dante2617012022/mini-soc-lab.git mini-soc-ar-uat
cd mini-soc-ar-uat
git fetch origin 3a0dda469b01192b03eaf83d237a27ed34210a8c
git checkout --detach 3a0dda469b01192b03eaf83d237a27ed34210a8c
git rev-parse HEAD
python3 -m compileall -q scripts tests
python3 -m unittest discover -s tests -p 'test_*.py' -v
sudo unshare --net -- python3 tests/integration/active_response_nft.py
```

Este ejemplo reproduce la revisión ensayada y aprobada en CI. Para una revisión posterior, verificar su SHA y sus controles antes de sustituirlo. Todos los comandos deben terminar correctamente antes de avanzar. La prueba aislada no instala el script en Wazuh ni modifica la tabla de la VM.

### 2. Conservar el estado e instalar sólo el script corregido

Antes de reemplazarlo, revisar el set actual con `sudo /usr/sbin/nft list set inet mini_soc_ar blocked_ipv4`: debe estar vacío, o la tabla debe estar ausente. Un error de permisos u otra falla de consulta impide continuar. Confirmar la conectividad base desde SOC-TEST-01 según CHG-021.

Desde la raíz de la copia de prueba, este bloque conserva la versión instalada en un directorio de respaldo y evita reemplazos parciales:

```bash
sudo bash -eu <<'SH'
installed=/var/ossec/active-response/bin/mini-soc-nft-block.py
backup_dir=$(mktemp -d /var/ossec/active-response/mini-soc-ar-backup.XXXXXX)
cp -p -- "$installed" "$backup_dir/mini-soc-nft-block.py"
install -o root -g wazuh -m 0750 scripts/active-response/mini-soc-nft-block.py "$installed.new"
trap 'rm -f -- "$installed.new"' EXIT
python3 -m py_compile "$installed.new"
mv -f -- "$installed.new" "$installed"
printf 'Respaldo para rollback: %s\n' "$backup_dir/mini-soc-nft-block.py"
sha256sum scripts/active-response/mini-soc-nft-block.py "$installed"
stat -c '%U:%G %a %n' "$installed"
SH
```

Conservar la ruta de respaldo mostrada. Los hashes deben coincidir y los permisos deben ser `root:wazuh 750`. No hace falta editar ni reiniciar el manager por este reemplazo de script.

### 3. Alta, retiro y flujo automático

Repetir el UAT de [CHG-021](CHG-021.md#manual-response-uat), usando el harness de esta copia:

```bash
sudo python3 scripts/active-response/chg-021-harness.py add
sudo /usr/sbin/nft list set inet mini_soc_ar blocked_ipv4
```

Corroborar desde SOC-TEST-01 la contención esperada y luego retirar el bloqueo:

```bash
sudo python3 scripts/active-response/chg-021-harness.py delete
sudo /usr/sbin/nft list set inet mini_soc_ar blocked_ipv4
```

Después del retiro, corroborar recuperación. El harness manual no programa un timeout: debe ejecutarse `delete` al terminar la prueba incluso si otra comprobación falla. Si falla el retiro, mantener la consola del gateway y aplicar el rollback/recuperación documentados en CHG-021.

Finalmente repetir el evento automático autorizado y acotado de CHG-021: verificar `ADD`, `DELETE` temporizado por Wazuh, set vacío, conectividad recuperada y servicios saludables. No generar firmas nuevas ni tráfico adicional para este cambio.

### 4. Cierre

Registrar SHA probado, versiones, resultados de unitarias/integración, códigos de retorno, set antes/después, tiempos `ADD/DELETE` y salud final. Sólo se aprueba el UAT si todo coincide. Conservar evidencia cruda localmente y publicar únicamente un resumen sanitizado; actualizar el estado de aceptación antes de integrar el PR.

## Riesgos residuales

La consulta y la posterior modificación siguen siendo operaciones separadas: no se elimina una carrera con un cambio concurrente de tabla. Los mensajes usados para tolerar elementos ya presentes/ausentes, las condiciones de permisos de logs y el timeout administrado por Wazuh conservan sus limitaciones anteriores. La corrección mejora la exactitud del resultado; un error de retiro puede dejar la contención activa y requiere revisión del operador.

## Rollback

Antes del despliegue se debe conservar una copia de la versión instalada en `SOC-GW-01`, con propietario y permisos. Si falla el UAT, restaurar esa copia, comprobar sintaxis y permisos `root:wazuh 750`, y verificar el estado del set y la conectividad. El revert del commit sólo revierte el repositorio; no sustituye la restauración en la VM. No se cambia `/etc/nftables.conf` ni la configuración del manager en este incremento.
