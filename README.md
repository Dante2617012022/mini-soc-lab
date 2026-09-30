# mini-soc-lab

Mini SOC / Blue Team lab with Wazuh, Suricata, YARA, VirusTotal, MITRE ATT&CK and nftables.

## Objetivo

Construir un laboratorio defensivo, reproducible y auditable que demuestre capacidades prácticas de Security Operations sin confundir un entorno de laboratorio con experiencia SOC de producción.

El proyecto parte de un diseño académico previo y lo convierte en una implementación controlada con gestión de cambios, evidencia verificable y decisiones de arquitectura basadas en riesgo.

## Alcance inicial

La primera versión separa responsabilidades entre máquinas virtuales:

```text
PC Dante / VirtualBox
└── SOC-ENDPOINT-01
    └── Debian 13
        ├── Wazuh Agent
        ├── SSH / authentication telemetry
        ├── File Integrity Monitoring
        ├── sudo / user activity
        └── YARA (fase posterior)

PC hermano / VirtualBox
├── SOC-MGMT-01
│   └── Ubuntu Server 24.04 LTS
│       ├── Wazuh Server
│       ├── Wazuh Indexer
│       └── Wazuh Dashboard
└── SOC-GW-01 (fase posterior)
    └── Debian
        ├── nftables
        ├── Suricata
        └── Wazuh Agent

Servicio externo
└── VirusTotal API (enriquecimiento por hash)
```

## Principios de diseño

- Hosts físicos usados principalmente como hipervisores.
- Wazuh como núcleo de detección, correlación e investigación.
- Suricata como NIDS en un gateway dedicado, no como control decorativo.
- nftables reemplaza el appliance MikroTik del diseño académico para este laboratorio.
- VirusTotal se trata como tercero externo: se priorizan consultas por hash y no se suben archivos privados.
- Detección y validación antes de automatizar bloqueos.
- Secretos, credenciales, PCAP y evidencia cruda no se versionan.
- La evidencia pública debe estar sanitizada y contextualizada.
- Graylog queda fuera de la primera versión para evitar una segunda plataforma de logs sin necesidad demostrada.

## Casos de uso previstos

1. Intentos fallidos de autenticación SSH y password guessing.
2. Cambios sobre archivos críticos mediante FIM.
3. Uso de sudo y cambios de cuentas privilegiadas.
4. Detecciones de red mediante Suricata y EVE JSON.
5. Detección con YARA y enriquecimiento por hash con VirusTotal.
6. Active Response con bloqueo temporal en nftables, únicamente después de validar falsos positivos y rollback.

## Flujo de trabajo

Los cambios se realizan mediante ramas pequeñas y pull requests. GitHub mantiene scripts, configuraciones y documentación; las VMs son el entorno de ejecución y UAT.

```text
objetivo → evaluación de riesgo → cambio mínimo → CI → UAT en VM → evidencia → merge
```

## Estado

**Fase 7 — Wazuh FIM realtime y segunda detección end-to-end validadas.**

CHG-002 a CHG-004 dejaron `SOC-ENDPOINT-01` provisionado, endurecido y con telemetría real validada. CHG-005 provisionó `SOC-MGMT-01` sobre Ubuntu Server 24.04 LTS y estableció un baseline verificable con rollback. CHG-006 confirmó de forma read-only que el endpoint estaba listo para un despliegue controlado del Wazuh Agent.

CHG-007 instaló y validó Wazuh 4.14.8 en modo all-in-one sobre `SOC-MGMT-01`, con manager, indexer, dashboard y Filebeat operativos. El acceso de UAT al dashboard se realizó mediante un forward temporal restringido a loopback, luego retirado; la credencial inicial de administración fue rotada, el repositorio Wazuh quedó deshabilitado para evitar upgrades accidentales y se creó el snapshot `WAZUH-CENTRAL-READY`.

CHG-008 validó el camino cross-host real mediante una segunda NIC bridged en cada VM. NAT continúa siendo la ruta por defecto y la interfaz bridged queda dedicada al tráfico del laboratorio. TCP/1514 y TCP/1515 fueron validados end-to-end sin crear forwards Wazuh ni reglas adicionales en los hosts Windows.

CHG-009 formaliza el despliegue de Wazuh Agent 4.14.8-1 en `SOC-ENDPOINT-01`, su enrollment como Agent ID 001 y la comunicación activa con el manager. También documenta `SOC-DET-001`, una prueba controlada de autenticación SSH fallida detectada por Wazuh Rule 5760 (level 5), con mapeo MITRE ATT&CK T1110.001 y T1021.004 y disposición analítica `True Positive — Authorized Security Test / Benign`.

CHG-010 formaliza `SOC-DET-002`: una modificación controlada en un directorio dedicado de laboratorio detectada por Wazuh FIM en modo realtime mediante Rule 550 (level 7). La alerta registró cambio de mtime y hashes MD5/SHA-1/SHA-256, con mapeo MITRE ATT&CK T1565.001 Stored Data Manipulation y disposición analítica `True Positive — Authorized Security Test / Benign`.

Durante la validación se detectó además una interrupción real del camino de telemetría causada por bindings bridged de VirtualBox que ya no coincidían con los adaptadores físicos activos de los hosts. El problema se aisló antes de tocar identidad o claves Wazuh, se restauró conectividad L3/TCP/1514 y el agente recuperó su sesión existente. La prueba FIM aceptada se repitió únicamente después de recuperar el canal.

El próximo incremento debe seleccionarse por riesgo y valor de evidencia. Los hallazgos SCA/CIS se tratarán como un workstream de hardening separado; Suricata, YARA y Active Response permanecen fuera de esta fase.

## Seguridad y uso autorizado

Este repositorio documenta un laboratorio propio y controlado. Las pruebas deben ejecutarse únicamente sobre sistemas y redes autorizados. No se publican secretos, credenciales, datos personales, direcciones internas innecesarias ni capturas sin sanitizar.
