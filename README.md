# Asesor de Plataforma · IT San Andrés (maqueta)

Agente que recomienda infraestructura en Azure según el **perfil de plataforma definido por IT**. El usuario describe la necesidad en un chat, el agente repregunta lo que falte, consulta precios reales, valida contra las políticas y entrega la recomendación más un **documento descargable (Word y PDF)**.

## Cómo funciona

```
Navegador (chat)  ──SSE──▶  API .NET 8 (Render)  ──▶  Claude API (tool use)
                                   │
                                   ├─ get_it_profile                → profile/it-profile.json
                                   ├─ azure_price_lookup            → Azure Retail Prices API (pública)
                                   ├─ validate_proposal             → reglas determinísticas en C#
                                   └─ create_recommendation_document → .docx / vista imprimible
```

- **El perfil manda.** Regiones, series de VM, topes de costo y requisitos por criticidad se leen del JSON. La validación es código, no criterio del modelo.
- **Precios sin inventar.** Salen de la Azure Retail Prices API: precios de lista en USD, sin descuentos ni impuestos.
- **Trazabilidad.** El chat muestra cada paso del agente y el consumo de tokens por consulta.
- **Sin dependencias NuGet.** Usa solo la BCL de .NET; el .docx se arma con OpenXML a mano.

## Estructura

| Ruta | Qué es |
|---|---|
| `profile/it-profile.json` | Perfil de plataforma. **Valores de ejemplo**, a reemplazar por IT |
| `prompts/system.md` | Instrucciones del agente: rol, reglas y flujo |
| `src/ClaudeAgent.cs` | Loop agéntico sobre la Messages API |
| `src/AgentTools.cs` | Definición y ruteo de herramientas |
| `src/AzurePricing.cs` | Consulta de precios, con caché de 6 h |
| `src/PolicyValidator.cs` | Reglas: región, serie/vCPU, IP pública, zonas, backup, DR, instancias, tags, presupuesto |
| `src/DocumentService.cs` | Documento de recomendación: Word y vista para PDF |
| `wwwroot/` | Front: chat, estilos del documento, marca |

## Correr local

```bash
export ANTHROPIC_API_KEY=sk-ant-...
dotnet run            # http://localhost:8080
```

Con `ASPNETCORE_ENVIRONMENT=Development` se habilita `POST /api/dev/tools/{nombre}` para probar herramientas sin pasar por el modelo:

```bash
curl -X POST localhost:8080/api/dev/tools/validate_proposal -H 'Content-Type: application/json' \
  -d '{"environment":"dev","criticality":"baja","components":[{"kind":"vm","name":"api","sku":"Standard_B2s","quantity":1,"hourlyUsd":0.05}]}'
```

## Deploy en Render

1. Subir esta carpeta a un repo de GitHub.
2. En Render: **New → Blueprint** y elegir el repo. Toma `render.yaml` y construye con el `Dockerfile`.
3. Cargar las variables secretas `ANTHROPIC_API_KEY` y `ACCESS_KEY`.
4. En la consola de Anthropic, fijar un **límite de gasto** para la key.

| Variable | Default | Uso |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Obligatoria |
| `ACCESS_KEY` | vacío | Si se define, el front la pide y la API la exige (`X-Access-Key`) |
| `CLAUDE_MODEL` | `claude-sonnet-5-5` | Modelo |
| `CHAT_RATE_PER_MINUTE` | `10` | Tope **global** de consultas por minuto |
| `AGENT_MAX_STEPS` | `12` | Máximo de llamadas al modelo por consulta |
| `AGENT_MAX_TOKENS` | `16000` | `max_tokens` inicial por llamada |
| `AGENT_MAX_TOKENS_CAP` | `32000` | Tope al reintentar: si una llamada corta por límite, se repite con el doble hasta este valor |
| `PROFILE_PATH` | `profile/it-profile.json` | Perfil alternativo |

## Ajustar el perfil

Editar `profile/it-profile.json` y redeployar. El front lo muestra en la barra lateral y el agente lo lee en cada consulta. Campos que usa el validador:

- `regions.allowed`, `regions.primary`, `regions.dr`
- `environments.<env>`: `maxMonthlyUsd`, `allowedVmSeries`, `maxVcpuPerVm` y `allowPublicIp`
- `criticality.<nivel>`: `minComputeInstances`, `requireAvailabilityZones`, `requireBackup` y `requireDrRegion`
- `tagging.required`
- `appSizing.classes`: clases chica, mediana y grande, por usuarios concurrentes y GB
- `databases`:
  - `engines` (con `requiresApproval`)
  - `sizing.<tamaño>`: `allowedTiers`, `backupRetentionDays` y `readReplica`
  - `privateEndpointIn`
- `platformStack.<capa>`: `preferred`, `allowed` y `requiresApproval`, por `id`. No aplica a productos de terceros.
- `apiManagement`: `requiredFor` (mobile, terceros, otras_apps) y `tiersByEnvironment`
- `secrets`: `required`, `premiumRequiresApproval`, `purgeProtectionIn` y `privateEndpointIn`

Los lineamientos completos se ven en `/lineamientos.html`, que se puede imprimir o guardar como PDF para circular a IT.

## Supuestos y limitaciones de la maqueta

- Identidad visual tomada del logo institucional de St. Andrew's Scots School: azul `#00478E` y crema `#F7F4ED`, medidos sobre el logo. El logo y el escudo están en `wwwroot/brand/` (`logo.svg`, `logo-white.svg`, `crest.svg`, `crest-white.svg`), en versión color y blanca. Cada SVG contiene el PNG embebido en base64, lo que permite versionarlos como texto; el documento Word extrae el PNG de `logo.svg`. El original es de baja resolución (314×69 px). Para reemplazarlo por un logo oficial nítido, se pisan los archivos con el mismo nombre. Si `logo.svg` pasa a ser vectorial puro, el Word sale sin logo hasta que se agregue un PNG.
- *Supuesto:* las tipografías Source Serif 4 y Source Sans 3 son aproximaciones; ajustar si el manual de marca define otras.
- *Supuesto:* el perfil incluido es ilustrativo, no una definición de IT.
- Historial del chat en el navegador (localStorage). Documentos en memoria del servidor por 24 h: se pierden si Render reinicia o duerme la instancia.
- Plan free de Render: la instancia se duerme por inactividad y la primera consulta tarda en arrancar.
- Precios: solo servicios con precio por hora o por unidad en la Retail Prices API. Licencias, egress y soporte no se estiman.
- Usa una API key de cuenta particular. **No cargar datos reales sensibles** (inventario, IPs, datos personales) en las consultas.
- El rate limit es global, no por usuario.

## Próximos pasos sugeridos

- Login con Microsoft Entra ID en lugar de `ACCESS_KEY`.
- Persistir documentos y consultas (Blob Storage o Postgres) para auditoría.
- Versionar el perfil en un repo de IT con aprobación por PR.
- Pasar la key a una cuenta organizacional de Anthropic con límites por área.
