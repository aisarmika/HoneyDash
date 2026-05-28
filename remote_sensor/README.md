# HoneyDash Remote Sensor Forwarder

Connects any Cowrie honeypot to the HoneyDash dashboard over the network.

## Setup (on your machine with the honeypot)

**1. Install dependency**
```bash
pip install requests
```

**2. Configure the forwarder** — edit the top of `forwarder.py`:
```python
HONEYDASH_URL   = "http://<VPS_IP>:8000"       # HoneyDash backend address
SENSOR_API_KEY  = "<key from backend/.env>"     # shared secret
SENSOR_NAME     = "remote-sensor-01"            # name shown in dashboard
COWRIE_LOG_PATH = "/path/to/cowrie.json"        # your local Cowrie log
```

Or set environment variables instead of editing the file:
```bash
export HONEYDASH_URL="http://<VPS_IP>:8000"
export SENSOR_API_KEY="<your-key>"
export SENSOR_NAME="remote-sensor-01"
export COWRIE_LOG_PATH="/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
```

**3. Run the forwarder**
```bash
python3 forwarder.py
```

**4. Run as a background service (optional)**
```bash
# Create a systemd service so it starts automatically
sudo tee /etc/systemd/system/honeydash-forwarder.service > /dev/null <<EOF
[Unit]
Description=HoneyDash Remote Sensor Forwarder
After=network.target

[Service]
User=$USER
WorkingDirectory=$(pwd)
Environment=HONEYDASH_URL=http://<VPS_IP>:8000
Environment=SENSOR_API_KEY=<your-key>
Environment=SENSOR_NAME=remote-sensor-01
Environment=COWRIE_LOG_PATH=/path/to/cowrie.json
ExecStart=/usr/bin/python3 $(pwd)/forwarder.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable honeydash-forwarder
sudo systemctl start honeydash-forwarder
sudo systemctl status honeydash-forwarder
```

## How it works

The forwarder tails the Cowrie JSON log file and POSTs each event to:
```
POST http://<VPS_IP>:8000/api/ingest/event
X-Sensor-Key: <shared secret>
```

Events appear in the HoneyDash dashboard under the sensor name you set.
The forwarder only forwards **new** events (seeks to end of log on startup).
It handles log rotation automatically.
