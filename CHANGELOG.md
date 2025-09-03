# CHANGELOG

## v0.1.1 — 2025-09-01
- Agent: support rudimentaire des commentaires inline dans la config (trim après `#`).
- Serveur: `127.0.0.1` considéré interne (évite les faux ORANGE pour agent→serveur).
- Serveur: endpoint `/api/health` (nodes, events, now).
- Serveur: logging HTTP avec code de statut.
- UI: servie via chemin absolu déduit du binaire.
