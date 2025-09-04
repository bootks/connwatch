# connwatch

Petit outil maison pour **superviser les connexions réseau** et mettre en avant ce qui est **suspect** (ORANGE/RED) sans se noyer dans la config.

- Agent léger (Linux) : collecte via `ss`, **sampler rapide** (ms) + **upload en lot** (s), **zéro-perte** des connexions éphémères.
- Serveur HTTP : endpoints JSON (`/api/*`), règles simples (ports, DoH, latéralisation), UI statique.

## Fonctionnalités

- Classement GREEN / ORANGE / RED (ports inattendus, DoH, latéral admin LAN).
- **Process** (exe/pid) quand possible.
- **Zéro-perte** : connexions brèves captées même entre deux refreshs.
- UI statique embarquée (ou **index custom** via `CONNWATCH_UI_INDEX`).

---

## Installation rapide (build from source)

```bash
# Prérequis Go 1.22+
go mod tidy

# Build
( cd agent/cmd/agent  && go build -o connwatch-agent )
( cd server/cmd/server && go build -o connwatch-server )

# Install
sudo install -m0755 agent/cmd/agent/connwatch-agent   /usr/local/bin/
sudo install -m0755 server/cmd/server/connwatch-server /usr/local/bin/

# Users & confs
sudo useradd -r -s /usr/sbin/nologin connwatch || true
sudo install -m0640 agent/config.example.yaml  /etc/connwatch-agent.yaml
sudo install -m0644 server/config.example.yaml /etc/connwatch-server.yaml
sudo chown connwatch:connwatch /etc/connwatch-server.yaml

(Optionnel) Process visibles sous user connwatch
Par défaut, Linux limite ss -p aux process du même utilisateur. Pour voir tous les process sans root :
sudo install -d -m0755 /usr/local/lib/connwatch
sudo cp /usr/bin/ss /usr/local/lib/connwatch/ss
sudo setcap cap_net_admin,cap_net_raw+ep /usr/local/lib/connwatch/ss
getcap /usr/local/lib/connwatch/ss  # doit afficher les deux cap
