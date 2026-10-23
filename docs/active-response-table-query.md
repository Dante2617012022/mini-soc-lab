# Active Response: distinguir ausencia de tabla y fallo de consulta

## Problema y cambio mínimo

El script de CHG-021 trataba cualquier retorno no exitoso de `nft list table inet mini_soc_ar` como tabla ausente. Durante `delete`, un error de permisos podía terminar con código 0 y `table_absent=true`, aunque no se hubiese comprobado ni retirado el bloqueo. Durante `add`, ese mismo error permitía intentar crear la tabla.

La corrección consulta `nft -j list tables` y sólo reconoce ausencia cuando la consulta termina correctamente, entrega una estructura válida y no contiene la tabla de familia `inet` llamada `mini_soc_ar`. Los errores de ejecución o formato terminan con código 1, registro `ERROR` y ninguna operación posterior sobre el firewall.

Se conserva la allowlist, el intercambio `check_keys`, la tabla runtime, el set y la configuración de Wazuh. No se agrega ningún servicio, dependencia Python, fuente de configuración ni interfaz de administración.

## Riesgo, validación y evidencia

El riesgo abordado es informar un retiro exitoso sin haber podido verificar el estado real. La nueva consulta requiere la salida JSON soportada por nftables; cualquier incompatibilidad se informa como error en lugar de interpretar ausencia. La sintaxis y el esquema se contrastaron con [nft(8)](https://www.netfilter.org/projects/nftables/manpage.html) y [libnftables-json(5) de Debian 13](https://manpages.debian.org/trixie/libnftables1/libnftables-json.5.en.html).

La prueba de regresión falló con el script anterior en `add` (intentaba crear la tabla después del error) y `delete` (devolvía código 0). Con la corrección pasan las 27 pruebas unitarias. La suite cubre tabla presente, ausencia confirmada, coincidencia exacta de nombre/familia, JSON inválido o incompleto y comportamiento `add/delete` existente.

CI incorpora además una prueba con nftables real en un namespace descartable. Comprueba el set después de altas/retiros, repeticiones y denegaciones reales de `CAP_NET_ADMIN`. El entorno local de esta sesión no permite crear el namespace; su resultado se obtiene en GitHub Actions y debe repetirse en Debian antes del despliegue.

Se conserva como evidencia pública el código, la suite y la ejecución CI del commit. Cualquier evidencia de las VMs se publica únicamente después de sanitizarla. La validación automatizada no acredita por sí sola conectividad, salud de Wazuh ni timeout real.

## Estado de aceptación

- Corrección y 27 pruebas unitarias: completadas localmente; sintaxis Python y revisión de espacios aprobadas.
- GitHub Actions: pendiente para el commit final.
- UAT de la versión corregida en `SOC-GW-01`: pendiente; no hay conexión directa disponible a las VMs desde esta sesión.
- Integración en `main`: posterior al UAT, de acuerdo con [el flujo de cambios](change-control.md).

## UAT en SOC-GW-01

Ejecutar desde la consola de la VM del gateway durante una ventana de laboratorio, sin generar simultáneamente eventos de Active Response. Primero verificar `hostname`, `python3 --version` y `sudo /usr/sbin/nft --version`. Se necesita git para obtener la rama; `nftables`, Python 3 y `util-linux` para la prueba aislada.

### 1. Obtener la versión y comprobarla sin desplegar

Usar un directorio nuevo para conservar cualquier copia existente del proyecto:

```bash
git clone --single-branch --branch fix/active-response-table-query https://github.com/Dante2617012022/mini-soc-lab.git mini-soc-ar-uat
cd mini-soc-ar-uat
git rev-parse HEAD
python3 -m compileall -q scripts tests
python3 -m unittest discover -s tests -p 'test_*.py' -v
sudo unshare --net -- python3 tests/integration/active_response_nft.py
```

Comprobar que el SHA coincide con el head aprobado del PR. Todos los comandos deben terminar correctamente antes de avanzar. La prueba aislada no instala el script en Wazuh ni modifica la tabla de la VM.

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
