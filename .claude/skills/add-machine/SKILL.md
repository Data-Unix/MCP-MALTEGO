---
name: add-machine
description: Procedimiento para crear o modificar una Machine (secuencia automática de transforms con etapas, rondas y presupuestos) en maltego-mcp, predefinida en código o propia en el catálogo TOML. Úsala para automatizar un flujo de reconocimiento.
license: MIT
---
# Añadir una Machine

- **Semántica**: cada etapa aplica sus transforms a todo lo descubierto en la ronda (`accumulate=True`); con varias
  rondas, la frontera siguiente son las entidades nuevas. Las cadenas ad hoc (`transforms=[...]`) aplican cada paso
  solo a lo del paso anterior.
- **Predefinida**: añade `Machine(nombre, descripción, input_types, stages)` a `BUILTIN_MACHINES` en
  `src/maltego_mcp/machines.py` y, si es la natural para un tipo, a `DEFAULT_MACHINE_BY_TYPE`.
- **Propia del usuario** (sin código; equivale a `register_machine` de otros MCP: semilla = `input_types`,
  transforms por etapa = `stages`, límite de expansión = `rounds`), en `~/.maltego-mcp/transforms.toml`:
  ```toml
  [[machines]]
  name = "MiRecon"
  input_types = ["maltego.Domain"]
  stages = [["DNSToIP", "DomainToNS"], ["IPToAS"]]
  rounds = 1
  ```
- Incluye transforms de proveedores sin miedo: si falta la clave se omiten y se informa en `unavailable`.
- **Tests**: en `tests/test_copilot.py` con el `Router` simulado; comprueba etapas, que no se repite un transform
  sobre la misma entidad y el presupuesto `max_total_entities`.
- Documenta la Machine en `README.md`, `README.es.md`, `docs/USO.md` y `CHANGELOG.md`.
