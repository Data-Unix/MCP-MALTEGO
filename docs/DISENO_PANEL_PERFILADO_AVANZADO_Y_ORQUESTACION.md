# Arquitectura y Diseño del Panel de Perfilado Avanzado, Automatización y Motor de Verificación

Este documento establece la especificación técnica, de diseño y de ingeniería para el **Módulo de Perfilado Avanzado Multidimensional** de MCP Maltego. Integra la taxonomía completa de entidades de Maltego, el pipeline de ejecución escalonada de Transforms y Machines, la ingesta estructurada con **Gemini 3.8 Flash** y el motor de verificación técnica profunda y auditoría pericial.

---

## 1. Arquitectura del Panel y Modelado de Datos Maltego

### 1.1 Taxonomía de Clases de Entidades y Colecciones
El panel procesa y unifica todas las familias ontológicas estándar de Maltego, junto con extensiones CTI y forenses:

```
[ONTOLOGÍA BASE DE PERFILADO]
├── Infraestructura & Redes
│   ├── maltego.Domain / maltego.DNSName
│   ├── maltego.IPv4Address / maltego.IPv6Address
│   ├── maltego.NSRecord / maltego.MXRecord
│   ├── maltego.Netblock / maltego.AS
│   └── maltego.Port / maltego.Service / maltego.URL
├── Identidad & Huella Personal
│   ├── maltego.Person
│   ├── maltego.EmailAddress / maltego.PhoneNumber
│   ├── maltego.Alias / maltego.Image
│   └── maltego.Affiliation / maltego.SocialNetwork
├── Corporativo, Financiero & Gobernanza
│   ├── maltego.Company / maltego.Organization
│   ├── maltego.Document (Memorandos, balances, actas)
│   ├── maltego.BankAccount / maltego.CryptocurrencyAddress
│   └── maltego.Contract / maltego.Policy
├── Geoespacial & Sedes
│   ├── maltego.Location / maltego.Country
│   └── maltego.GPS (Latitud, Longitud WGS84)
└── Extensiones Forenses & Amenazas (Prefijo cti.* / threat.*)
    ├── threat.ThreatActor / threat.Campaign
    ├── threat.Malware / threat.Tool
    └── threat.Vulnerability / threat.TTP (MITRE ATT&CK)
```

#### Manejo de Colecciones (`Entity Collections`)
Para prevenir el colapso visual ante objetivos con cientos de registros (por ejemplo, 3.000 subdominios o 400 IPs de un ASN):
- **Agrupamiento Dinámico:** Si un nodo expande más de 12 entidades del mismo tipo, la interfaz las condensa automáticamente en una colección visual (`maltego.Collection`), mostrando la métrica agregada (por ejemplo, `[342 IPv4 Addresses | Hostinger]`).
- **Desglose Progresivo (Explode):** El analista puede expandir selectivamente mediante filtros de certeza (`confidence >= 0.8`), pertenencia a subredes o presencia en listas de riesgo.

---

### 1.2 Estructura y Distribución de la Interfaz del Panel

El panel se organiza en una arquitectura de tres columnas de alta densidad visual con soporte para modo expandido y pantalla completa:

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ BARRA SUPERIOR DE MANDO: Caso Activo | Selector de Tipología (21) | Presupuesto Rondas | Ejecutar Profiling │
├─────────────────────────┬───────────────────────────────────────────────┬──────────────────────────────┤
│ COLUMNA 1 (280px - 340px)│ COLUMNA 2 (Área Central Flexible)             │ COLUMNA 3 (320px - 420px)    │
│ EXPEDIENTE & OBJETIVOS  │ EXPEDIENTE PERICIAL MULTIDIMENSIONAL         │ TELEMETRÍA & AUDITORÍA       │
├─────────────────────────┼───────────────────────────────────────────────┼──────────────────────────────┤
│ • Selector de Entidad   │ 1. Header del Perfil & Índice de Riesgo CTI   │ • Origen de Datos & Evidencias│
│ • Resumen de Relaciones │ 2. Gráfico Radar Hexagonal (6 Pilares)        │ • Registro Inmutable Hashes  │
│ • Tipología Seleccionada│ 3. Matriz de Atributos Específicos Extraídos │ • Estado Ingesta Gemini Flash│
│ • Colecciones Activas   │ 4. Registro de Anomalías & Banderas Rojas     │ • Validación Técnica Fuentes │
│ • Historial de Pasos    │ 5. Recomendaciones Tácticas & Contramedidas   │ • Botones Exportar MTGX/PDF  │
└─────────────────────────┴───────────────────────────────────────────────┴──────────────────────────────┘
```

#### Elementos Visuales del Panel:
1. **Radar Hexagonal de 6 Pilares:**
   - Eje 1: Solvencia & M&A Estratégico.
   - Eje 2: Ciberdefensa, Redes & Superficie Expuesta.
   - Eje 3: Consistencia Forense & Victimología.
   - Eje 4: Estabilidad Política & Gobernanza.
   - Eje 5: Huella Psicográfica & Consumo.
   - Eje 6: Fiabilidad Conductual & Riesgo Clínico.
2. **Matriz de Atributos Específicos:** Renderizado dinámico de tarjetas según la tipología evaluada (por ejemplo, agresividad mediática y límite de capital en `investor`; huella JARM, TLS y puertos abiertos en `device`; o modelo de punto de anclaje Rossmo en `geographic`).
3. **Píldoras Tácticas de Riesgo:** Indicadores con contraste de color normalizado (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`).

---

## 2. Flujo de Automatización: Orquestación de Transforms y Machines

Para evitar la saturación del panel, el bloqueo por tasa de consultas (rate-limiting) y el ruido topológico, la recolección de información se realiza en un pipeline estructurado de **4 fases consecutivas con presupuestos acotados**:

```
[OBJETIVO INICIAL (Semilla: Empresa, Persona, IP o Dominio)]
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────────┐
│ FASE 1: RECONOCIMIENTO PASIVO & TOPOLOGÍA DE INFRAESTRUCTURA        │
│ Transforms: to_dns_records, to_subdomains_crtsh, to_ip_geoloc        │
│ Máximo: 25 entidades | Timeout: 8s | Enriquecimiento: RIPE / ASN     │
└──────────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────────┐
│ FASE 2: HUELLA DIGITAL, SERVICIOS & ATRIBUTOS DE COMUNICACIÓN        │
│ Transforms: to_mx_records, to_jarm_fingerprint, to_breached_emails   │
│ Máximo: 40 entidades | Deduplicación por hash SHA-256 de valor       │
└──────────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────────┐
│ FASE 3: RED CORPORATIVA, PARTICIPACIONES & GOBERNANZA                │
│ Transforms: to_officers, to_shareholders, to_subsidiaries (TRX BPO) │
│ Máximo: 30 entidades | Agrupamiento automático en Collections        │
└──────────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────────┐
│ FASE 4: INTELIGENCIA DE AMENAZAS & CORRELACIÓN PERICIAL             │
│ Transforms: mitre_technique_match, cti_feed_correlate, score_profile │
│ Fusión en GraphStore | Generación de StepRecord inmutable           │
└──────────────────────────────────────────────────────────────────────┘
```

### Reglas de Control de Flujo (Throttling & Round Budgeting):
- **Presupuesto por Ronda:** Cada fase no puede inyectar más de 50 nodos en el caso activo sin intervención expresa.
- **Rollup Automático de Hojas:** Los nodos con una sola conexión y baja certeza (< 0.40) se consolidan dentro del nodo padre para mantener la legibilidad.
- **Deduplicación Canónica:** Antes de escribir en la memoria de grafo, toda entidad se normaliza mediante `domain/identity.py` (resolución de homónimos, formatos telefónicos E.164, minúsculas en FQDN y direcciones IP canónicas).

---

## 3. División de Trabajo: Ingesta Gemini 3.8 Flash vs. Orquestador Experto

La arquitectura divide estrictamente la velocidad de procesamiento lingüístico del rigor analítico y forense:

```
┌─────────────────────────────────────────────────────────────────────────┐
│ GEMINI 3.8 FLASH: MOTOR DE INGESTA RÁPIDA & ESTRUCTURACIÓN             │
│ • Procesa volcados no estructurados, actas, balances y feeds a gran vel.│
│ • Convierte texto disperso en esquemas JSON planos estrictos.          │
│ • Extrae entidades, valores declarados y relaciones preliminares.       │
└─────────────────────────────────────────────────────────────────────────┘
                                     │
                             (JSON Estructurado)
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ ORQUESTADOR (@investigador-fuentes-profiling-experto-en-profundidad)    │
│ • Ejecuta heurísticas de las 21 tipologías y calcula scores de riesgo. │
│ • Valida contra fuentes técnicas autorizadas (RIPE, BGP, WHOIS, CT).    │
│ • Detecta discrepancias cronológicas, alucinaciones o drift de datos.   │
│ • Aplica el modelo de puntuación multivariable y emite el dictamen.    │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Contrato de Ingesta (Gemini 3.8 Flash)
Gemini 3.8 Flash recibe el texto crudo y genera exclusivamente una estructura validada bajo el siguiente esquema plano:

```json
{
  "target_identifier": "string",
  "target_type": "string (maltego.*)",
  "extracted_entities": [
    {
      "maltego_type": "string",
      "value": "string",
      "role": "string",
      "properties": {
        "source_reference": "string",
        "declared_date": "string",
        "jurisdiction": "string"
      }
    }
  ],
  "stated_facts": [
    {
      "claim": "string",
      "confidence_declared": 0.0,
      "source_excerpt": "string"
    }
  ]
}
```

---

## 4. Motor de Verificación Crítica y Anti-Alucinación OSINT

Como orquestador, el sistema ejecuta una verificación pericial sobre cualquier afirmación o entidad derivada por el modelo antes de incorporarla al informe o asignarle riesgo:

```
┌───────────────────────────────────────────────────────────────────────┐
│ FLUJO DE VERIFICACIÓN CRÍTICA DEL ORQUESTADOR                         │
├───────────────────────────────────────────────────────────────────────┤
│ 1. Triangulación de Fuentes Primarias Técnicas:                      │
│    - RIPEstat / PeeringDB: Valida si la IP/ASN realmente le pertenece │
│      a la entidad corporativa o es un proxy/hosting compartido.       │
│    - Certificate Transparency (crt.sh): Valida si los subdominios     │
│      fueron emitidos por una CA confiable y coinciden con la empresa. │
│    - DNS inverso & WHOIS: Valida coherencia de fechas y registradores.│
│                                                                       │
│ 2. Detección de Discrepancias Temporales (Drift):                     │
│    - Si un hecho corporativo declara presencia actual pero el DNS     │
│      apunta a servidores dados de baja o estacionados, se degrada     │
│      la certeza a INFORMATIONAL.                                      │
│                                                                       │
│ 3. Cadena de Custodia & Hashing Forense:                              │
│    - Toda evidencia cruda (texto original del transform o feed)      │
│      se almacena con su hash SHA-256 en StepRecord.                   │
│    - El informe final referencia el hash inmutable, permitiendo       │
│      reproducibilidad pericial de la prueba.                          │
│                                                                       │
│ 4. Regla de Descarte de Falsos Positivos:                             │
│    - Si Gemini 3.8 Flash infiere un vínculo corporativo por similitud │
│      nominal, el orquestador exige verificar NIF/CIF o registro       │
│      mercantil oficial; si no existe arista de soporte, se rechaza.   │
└───────────────────────────────────────────────────────────────────────┘
```

---

## 5. Implementación en el Dashboard de MCP Maltego

1. **Ruta de Visualización:** Integrada bajo `[PROFILING] PERFILADO PERICIAL MULTIDIMENSIONAL` en el selector lateral del panel web.
2. **Endpoints de API del Backend:**
   - `POST /api/cases/{case_id}/profile`: Ejecución síncrona/reactiva del motor heurístico sobre la entidad seleccionada.
   - `GET /api/cases/{case_id}/profiles`: Historial de dictámenes consolidados del caso.
   - `GET /api/bgp/ripestat` & `GET /api/bgp/peeringdb`: Verificación en vivo de telemetría de enrutamiento y centros de datos físicos.
3. **Exportación Pericial:** Capacidad de generar el expediente en formatos `.mtgx` (para Maltego Desktop), `.html` interactivo y `.json` normalizado para ingesta SIEM/SOAR.

