# Kubernetes Deployment Guide

This guide outlines how to deploy the ASN Risk Intelligence Platform to a Kubernetes cluster.

## Prerequisites
*   Kubernetes Cluster (v1.24+)
*   `kubectl` configured
*   PostgreSQL and ClickHouse (Managed or Helm installed)
*   Redis (Managed or Helm installed)

## 1. ConfigMap & Secrets

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: asn-config
data:
  DB_META_HOST: "asn-postgres"
  DB_TS_HOST: "asn-clickhouse"
  REDIS_HOST: "asn-redis"
---
apiVersion: v1
kind: Secret
metadata:
  name: asn-secrets
stringData:
  POSTGRES_PASSWORD: "secure_password"
  CLICKHOUSE_PASSWORD: "secure_password"
```

## 2. API Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: asn-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: asn-api
  template:
    metadata:
      labels:
        app: asn-api
    spec:
      containers:
      - name: api
        image: registry.example.com/asn-api:latest
        envFrom:
          - configMapRef:
              name: asn-config
          - secretRef:
              name: asn-secrets
        ports:
        - containerPort: 80
        readinessProbe:
          httpGet:
            path: /health
            port: 80
---
apiVersion: v1
kind: Service
metadata:
  name: asn-api
spec:
  selector:
    app: asn-api
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
  type: LoadBalancer
```

## 3. Worker Deployment (Engine & Ingestor)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: asn-workers
spec:
  replicas: 1
  selector:
    matchLabels:
      app: asn-workers
  template:
    metadata:
      labels:
        app: asn-workers
    spec:
      containers:
      - name: ingestor
        image: registry.example.com/asn-ingestor:latest
        envFrom:
          - configMapRef:
              name: asn-config
          - secretRef:
              name: asn-secrets
      - name: engine
        image: registry.example.com/asn-engine:latest
        envFrom:
          - configMapRef:
              name: asn-config
          - secretRef:
              name: asn-secrets
```
