# Deployment Guide

## Production Deployment Checklist

### 1. Security Hardening

#### Generate Strong API Key
```bash
openssl rand -hex 32
```

Update in `docker-compose.yml`:
```yaml
services:
  asn-api:
    environment:
      - API_SECRET_KEY=<your-generated-key>
```

#### Database Passwords
Change default passwords in `docker-compose.yml`:
```yaml
environment:
  POSTGRES_PASSWORD: <strong-password>
  # Update in all services that connect to DB
```

### 2. Reverse Proxy Setup

#### Nginx Configuration
```nginx
upstream asn_api {
    server localhost:8080;
}

server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;
    
    ssl_certificate /etc/ssl/certs/your-cert.pem;
    ssl_certificate_key /etc/ssl/private/your-key.pem;
    
    location / {
        proxy_pass http://asn_api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
    limit_req zone=api_limit burst=20;
}

server {
    listen 443 ssl http2;
    server_name grafana.yourdomain.com;
    
    ssl_certificate /etc/ssl/certs/your-cert.pem;
    ssl_certificate_key /etc/ssl/private/your-key.pem;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 3. Persistent Volumes

Create docker-compose.override.yml:
```yaml
version: '3.8'

services:
  db-metadata:
    volumes:
      - /data/asn-platform/postgres:/var/lib/postgresql/data
      
  db-timeseries:
    volumes:
      - /data/asn-platform/clickhouse:/var/lib/clickhouse
      
  broker-cache:
    volumes:
      - /data/asn-platform/redis:/data
```

Ensure directory permissions:
```bash
sudo mkdir -p /data/asn-platform/{postgres,clickhouse,redis}
sudo chown -R 999:999 /data/asn-platform/postgres    # Postgres UID
sudo chown -R 101:101 /data/asn-platform/clickhouse  # ClickHouse UID
sudo chown -R 999:999 /data/asn-platform/redis       # Redis UID
```

### 4. Backup Strategy

#### Automated Backup Script
```bash
#!/bin/bash
# /usr/local/bin/backup-asn-platform.sh

BACKUP_DIR="/backup/asn-platform/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# PostgreSQL backup
docker-compose exec -T db-metadata pg_dump -U asn_admin asn_registry | \
    gzip > "$BACKUP_DIR/postgres.sql.gz"

# ClickHouse backup
docker-compose exec -T db-timeseries clickhouse-client --query="BACKUP DATABASE default TO Disk('default', '$BACKUP_DIR/clickhouse')"

# Retain last 7 days
find /backup/asn-platform -type d -mtime +7 -exec rm -rf {} \;
```

Add to crontab:
```bash
0 2 * * * /usr/local/bin/backup-asn-platform.sh
```

### 5. Monitoring and Logging

#### Log Aggregation with Loki
```yaml
# Add to docker-compose.override.yml
  loki:
    image: grafana/loki:latest
    ports:
      - "3100:3100"
    volumes:
      - /data/asn-platform/loki:/loki

  promtail:
    image: grafana/promtail:latest
    volumes:
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - ./promtail-config.yml:/etc/promtail/config.yml
    command: -config.file=/etc/promtail/config.yml
```

#### Health Check Monitoring
```bash
#!/bin/bash
# /usr/local/bin/check-asn-health.sh

HEALTH_URL="http://localhost:8080/health"
ALERT_EMAIL="admin@yourdomain.com"

if ! curl -sf "$HEALTH_URL" > /dev/null; then
    echo "ASN Platform health check failed!" | \
        mail -s "ASN Platform DOWN" "$ALERT_EMAIL"
fi
```

### 6. Resource Limits

Update docker-compose.yml:
```yaml
services:
  asn-api:
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
          
  db-timeseries:
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
        reservations:
          cpus: '2'
          memory: 4G
```

### 7. Horizontal Scaling

#### Scale Celery Workers
```bash
docker-compose up -d --scale asn-engine=3
```

#### Load Balanced API
```yaml
# docker-compose.override.yml
services:
  asn-api:
    deploy:
      replicas: 3
      
  nginx-lb:
    image: nginx:alpine
    volumes:
      - ./nginx-lb.conf:/etc/nginx/nginx.conf
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      - asn-api
```

### 8. Environment-Specific Configuration

#### Production .env
```bash
# Database
POSTGRES_PASSWORD=<strong-random-password>
CLICKHOUSE_PASSWORD=<strong-random-password>

# API
API_SECRET_KEY=<hex-32-bytes>
API_RATE_LIMIT=100

# Ingestion
BGP_STREAM_URL=wss://ris-live.ripe.net/v1/ws/
THREAT_FEED_INTERVAL=3600

# Monitoring
GRAFANA_ADMIN_PASSWORD=<strong-password>
```

### 9. SSL/TLS Certificates

#### Using Let's Encrypt
```bash
# Install certbot
sudo apt-get install certbot

# Generate certificates
sudo certbot certonly --standalone -d api.yourdomain.com
sudo certbot certonly --standalone -d grafana.yourdomain.com

# Auto-renewal
sudo crontab -e
0 0 1 * * certbot renew --quiet
```

### 10. Firewall Rules

```bash
# Allow only necessary ports
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

## Post-Deployment Verification

```bash
# Check all services healthy
docker-compose ps

# Verify API
curl -k https://api.yourdomain.com/health

# Check data ingestion
docker-compose exec db-timeseries clickhouse-client --query \
    "SELECT count() FROM bgp_events WHERE timestamp > now() - INTERVAL 5 MINUTE"

# Verify scoring
docker-compose logs asn-engine | tail -n 50

# Access Grafana
open https://grafana.yourdomain.com
```

## Maintenance Tasks

### Weekly
- Review disk usage: `df -h`
- Check container health: `docker-compose ps`
- Review Grafana alerts

### Monthly
- Verify backups are working
- Update Docker images: `docker-compose pull && docker-compose up -d`
- Review and rotate logs

### Quarterly
- Security audit
- Performance review
- Capacity planning

## Troubleshooting

### High Memory Usage
```bash
# Check container stats
docker stats

# If ClickHouse is the issue, adjust max_memory_usage
docker-compose exec db-timeseries clickhouse-client --query \
    "SET max_memory_usage = 4000000000"
```

### Slow API Response
```bash
# Check PostgreSQL query performance
docker-compose exec db-metadata psql -U asn_admin -d asn_registry -c \
    "SELECT * FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10;"
```

### BGP Ingestion Stopped
```bash
# Restart ingestor
docker-compose restart asn-ingestor

# Check logs
docker-compose logs -f asn-ingestor
```

## Support

For issues or questions:
1. Check [STATUS.md](./STATUS.md) for known limitations
2. Review logs: `docker-compose logs <service>`
3. Verify configuration in docker-compose.yml
4. Consult documentation in [docs/](./docs/)
