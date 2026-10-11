# Recorrido de análisis de alertas

Este índice organiza casos existentes del Mini-SOC para evaluar el razonamiento de un candidato SOC L1. No agrega incidentes, resultados ni ejercicios nuevos.

## Casos documentados

| Evidencia | Observación | Decisión documentada |
|---|---|---|
| [SOC-DET-001](detections/SOC-DET-001-ssh-auth-failure.md) | Un fallo SSH controlado, regla 5760 | Actividad de prueba; un fallo no prueba fuerza bruta ni compromiso |
| [SOC-DET-002](detections/SOC-DET-002-fim-realtime-modification.md) | Modificación de archivo, regla 550, después de recuperar telemetría | Cambio autorizado; no inferir manipulación maliciosa por un hash distinto |
| [SOC-DET-003](detections/SOC-DET-003-authorized-privilege-elevation.md) | Apertura y cierre de sesión privilegiada, reglas 5501/5502 | Administración autorizada; el mapeo ATT&CK no demuestra un atacante |
| [SOC-DET-004](detections/SOC-DET-004-controlled-udp-rate-anomaly.md) | Umbral UDP controlado; pruebas positiva y negativa | Detección solamente; no activar contención por esta regla |

## Decisiones operativas para revisar

- **Disponibilidad de telemetría:** SOC-DET-002 documenta el diagnóstico de los bindings bridged de VirtualBox y la recuperación antes de aceptar evidencia.
- **Separación entre alerta y respuesta:** [CHG-025](CHG-025.md) explica por qué se descartó un trigger ICMP que habría activado una respuesta ajena al objetivo del ejercicio.
- **Alcance de contención:** [CHG-021](CHG-021.md) limita el script nftables a una IP de prueba y documenta la eliminación automática del bloqueo por timeout.
- **Enriquecimiento:** [CHG-020](CHG-020.md) diferencia un hash desconocido en VirusTotal de un resultado limpio; la detección local no depende del tercero.

## Aporte y límites

Proyecto propio con trabajo en configuración, pruebas, diagnóstico, validación y documentación; el código y la configuración cuentan con asistencia de IA. La evidencia debe evaluarse junto con la explicación del procedimiento y sus límites, sin atribuir autoría autónoma de todo el código.

Los cuatro casos son actividades autorizadas y benignas. La documentación no prueba desempeño sobre incidentes desconocidos, tiempos de respuesta de un SOC real ni dominio de todas las plataformas mencionadas.

## Próximo objetivo de práctica

**Pendiente, no presentado como completado:** investigar un conjunto de eventos de un ejercicio autorizado sin conocer el resultado de antemano. Registrar línea temporal, consultas, hipótesis descartadas, impacto, severidad y ticket de cierre o escalamiento. Separar eventos reales del laboratorio de datos sintéticos y mantener los secretos fuera del repositorio.

[Volver al laboratorio](../README.md)
