# mini-soc-lab

Mini SOC / Blue Team lab con Wazuh, Suricata, YARA, VirusTotal y nftables.

## Objetivo

Construir un laboratorio defensivo, reproducible y auditable que demuestre capacidades prácticas de Security Operations sin presentar un entorno de laboratorio como experiencia SOC de producción.

El proyecto convierte un diseño académico en una implementación controlada mediante gestión de cambios, CI, UAT, rollback y evidencia técnica versionada.

## Arquitectura implementada

```text
PC del operador / Windows 11 / VirtualBox
├── SOC-ENDPOINT-01 — Debian 13
│   ├── Wazuh Agent
│   ├── SSH / authentication telemetry
│   ├── File Integrity Monitoring
│   └── actividad privilegiada
├── SOC-GW-01 — Debian 13
│   ├── nftables: gateway default-deny para el segmento de prueba
│   ├── Suricata NIDS + EVE JSON
│   ├── Wazuh Agent
│   └── Active Response temporal y acotado
└── SOC-TEST-01 — Debian 13
    └── workload descartable 10.77.0.10/24 detrás de SOC-GW-01

PC de gestión / Windows / VirtualBox
└── SOC-MGMT-01 — Ubuntu Server 24.04 LTS
    ├── Wazuh Manager
    ├── Wazuh Indexer
    └── Wazuh Dashboard

Servicio externo
└── VirusTotal API — enriquecimiento únicamente por hash
```

`SOC-GW-01` y `SOC-TEST-01` usan una red interna aislada de VirtualBox. El gateway conserva una interfaz NAT para salida y enruta sólo el segmento de prueba autorizado. El manager y los agentes usan conectividad bridged dedicada para telemetría Wazuh, mientras NAT continúa como ruta por defecto donde corresponde.

## Principios de diseño

- Hosts físicos principalmente como hipervisores; los roles de seguridad viven en VMs.
- Wazuh como núcleo de telemetría, correlación, investigación y respuesta.
- Suricata como NIDS real sobre el gateway, integrado mediante EVE JSON.
- nftables como única tecnología de firewall del gateway; no se introduce iptables sólo para Active Response.
- Segmento de prueba aislado, forwarding default-deny y mínimo flujo necesario.
- Detección y validación antes de automatizar respuesta.
- Active Response limitado por regla específica, allowlist, timeout y rollback.
- VirusTotal se trata como tercero externo: consulta por SHA-256, sin subir archivos.
- Secretos, credenciales, PCAP y evidencia cruda no se versionan.
- MITRE ATT&CK se asigna sólo cuando el comportamiento observado lo justifica.
- Graylog permanece fuera de alcance para evitar una segunda plataforma de logs sin necesidad demostrada.

## Capacidades demostradas

| Caso | Evidencia |
| --- | --- |
| SOC-DET-001 | Fallo SSH detectado por Wazuh; triage y ATT&CK documentados |
| SOC-DET-002 | FIM realtime sobre harness controlado; hashes antes/después |
| SOC-DET-003 | Sesión privilegiada autorizada observada y contextualizada |
| Network detection | Suricata SID local controlado → EVE JSON → Wazuh → Dashboard |
| File detection | YARA local sobre artefacto benigno determinístico |
| Threat enrichment | SHA-256 consultado en VirusTotal con secreto efímero y degradación segura |
| Active Response | Wazuh → nftables → bloqueo temporal de SOC-TEST-01 → rollback automático |

La evidencia distingue deliberadamente **detección**, **contexto**, **disposición analítica** y **respuesta**. Un evento que coincide con una regla no se presenta automáticamente como incidente.

## Flujo de cambio

Los cambios se realizan mediante ramas pequeñas y pull requests. GitHub conserva scripts y documentación; las VMs son el entorno de ejecución y UAT.

```text
objetivo → riesgo → cambio mínimo → validación → UAT → evidencia → CI → merge
```

Cada incremento busca tener rollback explícito y evitar cambios oportunistas fuera de alcance.

## Estado actual

El núcleo técnico del laboratorio está implementado y validado end-to-end.

CHG-002 a CHG-011 establecieron endpoint, manager, conectividad Wazuh y tres casos iniciales de detección/triage. La recuperación de una interrupción real de telemetría causada por bindings bridged obsoletos de VirtualBox quedó documentada como evidencia de troubleshooting sin rotar innecesariamente identidad ni claves.

CHG-012 a CHG-016 incorporaron `SOC-GW-01` y `SOC-TEST-01`, un segmento routed aislado, forwarding IPv4, NAT y política nftables default-deny. La configuración de red mantiene una única fuente de verdad por VM y el acceso administrativo no requiere exponer SSH a la LAN.

CHG-017 instaló y validó Suricata 7 sobre el gateway, incluyendo ET Open y la corrección de un problema del adaptador virtual mediante `virtio-net`. CHG-018 integró EVE JSON con Wazuh usando decoders/reglas nativas. CHG-019 añadió una firma Suricata local, determinística y benigna y validó el camino completo hasta Wazuh Dashboard.

CHG-020 añadió YARA y enriquecimiento hash-only con VirusTotal. Un HTTP 404 se trató correctamente como hash no indexado/desconocido, no como evidencia de archivo limpio; la clave API se manejó de forma efímera y YARA continuó funcionando sin el servicio externo.

CHG-021 cerró el ciclo detection-to-response. Una regla Wazuh específica para la firma controlada activa en `SOC-GW-01` un script stateful que sólo acepta `10.77.0.10`, crea una tabla nftables runtime dedicada y bloquea temporalmente el forwarding. El UAT automático registró `ADD`, pérdida de conectividad esperada, `DELETE` por timeout de 60 segundos y recuperación completa, con Wazuh Agent, Suricata, nftables e IP forwarding saludables al finalizar.

La documentación detallada de cada cambio vive en `docs/CHG-*.md`. Los siguientes incrementos deben centrarse en coherencia final de portfolio, arquitectura/evidencia y hardening priorizado por riesgo, no en agregar herramientas por cantidad.

## Riesgos residuales conocidos

Este laboratorio no pretende ser un SOC de producción. Entre los temas deliberadamente pendientes están el hardening de exposición bridged, política de actualización de agentes, ownership de reglas nftables runtime/persistentes, revisión del enrollment Wazuh, retención/backup/HA y controles operativos propios de un servicio gestionado.

El Active Response de CHG-021 es fail-open ante un reload del ruleset persistente de nftables: el estado runtime se elimina. Esto es aceptado para el containment temporal del laboratorio y debe rediseñarse antes de un uso productivo.

## Seguridad y uso autorizado

Este repositorio documenta infraestructura propia y controlada. Las pruebas deben ejecutarse únicamente sobre sistemas y redes autorizados. No se publican secretos, credenciales, datos personales, PCAP ni capturas/evidencia sin sanitizar.

## Lectura para portfolio

El valor del proyecto no es la cantidad de herramientas instaladas, sino la capacidad de explicar decisiones: trust boundaries, mínimo privilegio, fuentes de verdad, validación antes de activación, falsos positivos, rollback, continuidad, privacidad de datos, troubleshooting y gobierno de cambios.

La implementación demuestra fundamentos aplicables a SOC L1 / Junior Blue Team / Cybersecurity Analyst y Security Engineering junior, sin afirmar experiencia operando un SOC productivo.
