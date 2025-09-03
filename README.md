# connwatch (v0.1.1 • MVP + correctifs)

Agent léger + serveur web pour superviser **les connexions réseau** par hôte, classées **VERT / ORANGE / ROUGE**.
Correctifs : parsing commentaires inline côté agent ; loopback considéré interne ; `/api/health` ; logs HTTP avec codes ; UI servie sans dépendre du répertoire courant.

## Build (Go 1.21+)

```bash
cd ~/connwatch
go mod init connwatch || true
go mod tidy

cd agent/cmd/agent && go build -o connwatch-agent
cd ../../../server/cmd/server && go build -o connwatch-server
```

## Serveur

```bash
cd ~/connwatch
cp server/config.example.yaml server/config.yaml
# Éditez auth_token et vérifiez internal_cidrs inclut "127.0.0.0/8"
./server/cmd/server/connwatch-server server/config.yaml
# UI : http://<serveur>:8080/
```

## Agent

```bash
sudo useradd -r -s /usr/sbin/nologin connwatch || true
sudo cp agent/cmd/agent/connwatch-agent /usr/local/bin/
sudo cp agent/config.example.yaml /etc/connwatch-agent.yaml
sudo nano /etc/connwatch-agent.yaml
# server_url: "http://<IP_SERVEUR>:8080"
# auth_token: <le même que côté serveur>
# host_id: auto
# tags: ["home","linux"]

sudo cp deploy/systemd/connwatch-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now connwatch-agent
```

## Tests rapides

```bash
curl -s http://127.0.0.1:8080/api/health | jq
curl -s http://127.0.0.1:8080/api/nodes | jq
curl -s http://127.0.0.1:8080/api/events | jq
```
