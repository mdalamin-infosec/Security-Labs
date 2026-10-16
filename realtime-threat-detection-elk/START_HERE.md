# Start Here

## 1. Verify the offline pieces (2 minutes)

```bash
python3 -m unittest discover -s tests
python3 -m threatwatch demo
```

## 2. Optional: prove the rules fire (needs Suricata and scapy)

```bash
sudo apt install suricata
pip install scapy
bash tests/pcap/run_suricata_pcap.sh
```

Expect `PASS` for all eight SIDs and for the benign control.

## 3. Optional: live stack (needs Docker)

```bash
cp .env.example .env     # set SURICATA_IFACE
docker compose up -d
python kibana/setup_kibana.py
```

Allow a minute for Elasticsearch and Kibana. Use `docs/VALIDATION.md` first-run checklist to confirm each step.

## 4. Publish to GitHub (inside an existing repo)

```bash
cp -r realtime-network-threat-detection <your-repo>/SIEM/
cd <your-repo>
rm -rf SIEM/realtime-network-threat-detection/.git
git add . && git commit -m "Add real-time network threat detection project"
git push origin master
```

Before pushing, confirm no real captures, `.env` file or private IP inventory is included. `data/`, `reports/` and `.env` are in `.gitignore`.
