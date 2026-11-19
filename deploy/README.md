# Deploying SentinelWatch to a public URL

One small Linux server (Ubuntu 24.04, 2 vCPU / 4 GB RAM minimum, because OpenSearch needs memory) runs the whole stack with Docker. Only the website container is public (ports 80 and 443). The API, Postgres and OpenSearch are not reachable from the internet.

1. Make the server (for example a DigitalOcean droplet "Basic, 4 GB"). Note its IP address. In the provider's firewall allow only ports 22, 80 and 443.
2. SSH in and install Docker: `curl -fsSL https://get.docker.com | sh`
3. `git clone https://github.com/404mtrx/Capstone && cd Capstone`
4. Pick the site address: your own domain pointed at the server, or the free `<ip with dashes>.sslip.io` (IP 203.0.113.5 becomes `203-0-113-5.sslip.io`).
5. `bash deploy/setup.sh 203-0-113-5.sslip.io` (it makes `deploy/.env` with random secrets, starts everything, creates the OpenSearch user).
6. Make your admin login: `docker compose -f deploy/docker-compose.prod.yml exec api python -m app.create_user --role admin YOURNAME`, then create analysts the same way with `--role analyst`.
7. Open `https://<your site address>` and log in.

Send logs from your own machine to the public site:

    export SENTINEL_API_KEY=<API_KEY from deploy/.env on the server>
    python collector/send_events.py normalized_events.json --url https://<site>/api/events
    export SENTINEL_API_URL=https://<site>/api   # then run the detection engine as usual

Update after a code change: `git pull && docker compose -f deploy/docker-compose.prod.yml up -d --build`.
Logs: `docker compose -f deploy/docker-compose.prod.yml logs -f api`.

## Everything runs by itself (no laptops needed)

`docker compose -f deploy/docker-compose.prod.yml up -d` starts, and restarts after a reboot or crash:
the website, the API, Postgres, OpenSearch, the **detection engine** (`engine`) and a **collector** that
reads this server's own `/var/log/auth.log`. A public server receives real SSH login attempts from the
internet, so alerts appear without anyone running a terminal.

- Watch them: `docker compose -f deploy/docker-compose.prod.yml logs -f engine collector`
- Make your own test attack (from any computer): `ssh nosuchuser@YOUR-IP` and type a wrong password a few times.
  The failed logins show up in Logs, and the engine raises alerts within about 10 seconds.
- Logs from another machine (for example the lab VM) can still be sent with `collector/follow_logs.py` and
  the API key, as described above.
