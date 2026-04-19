#!/bin/bash
##############################################################################
# IntegriShield Deployment Script for zhask.io
# Deploys the application to zhask.io production environment
##############################################################################

set -e

# Configuration
ZHASK_HOST=${ZHASK_HOST:-"deploy@zhask.io"}
ZHASK_APP_NAME=${ZHASK_APP_NAME:-"integrishield"}
ZHASK_DOMAIN=${ZHASK_DOMAIN:-"integrishield.zhask.io"}
DEPLOY_ENV=${DEPLOY_ENV:-"production"}
REPO_URL=${REPO_URL:-"https://github.com/zhask-ai/Integrishield.git"}

echo "════════════════════════════════════════════════════════════════════"
echo "  IntegriShield Deployment to zhask.io"
echo "════════════════════════════════════════════════════════════════════"
echo "App Name:       $ZHASK_APP_NAME"
echo "Domain:         $ZHASK_DOMAIN"
echo "Environment:    $DEPLOY_ENV"
echo "Repo:           $REPO_URL"
echo "════════════════════════════════════════════════════════════════════"

# 1. Build Docker images
echo ""
echo "📦 Building Docker images..."
docker compose -f poc/docker-compose.dev4.yml build --no-cache

# 2. Tag images for zhask.io registry
# Note: only the custom-built dashboard-backend image is tagged/pushed.
#       The UI (nginx:alpine) and Redis (redis:7-alpine) use upstream images directly.
echo ""
echo "🏷️  Tagging images for zhask.io registry..."
REGISTRY=${ZHASK_REGISTRY:-"registry.zhask.io"}
docker tag integrishield-dashboard-backend "$REGISTRY/$ZHASK_APP_NAME/dashboard-backend:latest"

# 3. Push images to registry (if credentials available)
if [ -n "$ZHASK_REGISTRY_USER" ] && [ -n "$ZHASK_REGISTRY_PASS" ]; then
  echo ""
  echo "📤 Pushing images to zhask.io registry..."
  echo "$ZHASK_REGISTRY_PASS" | docker login -u "$ZHASK_REGISTRY_USER" --password-stdin "$REGISTRY"
  docker push "$REGISTRY/$ZHASK_APP_NAME/dashboard-backend:latest"
  docker logout "$REGISTRY"
else
  echo "⚠️  Registry credentials not provided, skipping image push"
fi

# 4. Create deployment manifest for zhask.io
echo ""
echo "📄 Creating deployment manifest..."
cat > /tmp/zhask-deploy.yaml << EOF
apiVersion: v1
kind: Deployment
metadata:
  name: integrishield
  namespace: production
  labels:
    app: integrishield
    version: "0.1.0"
spec:
  replicas: 1
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: integrishield
  template:
    metadata:
      labels:
        app: integrishield
    spec:
      containers:
      - name: redis
        image: $REGISTRY/$ZHASK_APP_NAME/redis:latest
        ports:
        - containerPort: 6379
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        volumeMounts:
        - name: redis-data
          mountPath: /data

      - name: dashboard-backend
        image: $REGISTRY/$ZHASK_APP_NAME/dashboard-backend:latest
        ports:
        - containerPort: 8787
        env:
        - name: REDIS_URL
          value: "redis://localhost:6379"
        - name: ENVIRONMENT
          value: "$DEPLOY_ENV"
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /api/health
            port: 8787
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/health
            port: 8787
          initialDelaySeconds: 5
          periodSeconds: 5

      - name: dashboard-ui
        image: $REGISTRY/$ZHASK_APP_NAME/dashboard-ui:latest
        ports:
        - containerPort: 5173
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /
            port: 5173
          initialDelaySeconds: 10
          periodSeconds: 10

      volumes:
      - name: redis-data
        emptyDir: {}

      imagePullSecrets:
      - name: zhask-registry-secret

---
apiVersion: v1
kind: Service
metadata:
  name: integrishield
  namespace: production
spec:
  type: LoadBalancer
  selector:
    app: integrishield
  ports:
  - name: ui
    port: 443
    targetPort: 5173
    protocol: TCP
  - name: api
    port: 8787
    targetPort: 8787
    protocol: TCP

---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: integrishield
  namespace: production
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - $ZHASK_DOMAIN
    secretName: integrishield-tls
  rules:
  - host: $ZHASK_DOMAIN
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: integrishield
            port:
              number: 443
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: integrishield
            port:
              number: 8787
EOF

echo "✅ Deployment manifest created: /tmp/zhask-deploy.yaml"

# 5. Deploy to zhask.io
echo ""
echo "🚀 Deploying to zhask.io..."
if [ -n "$ZHASK_KUBECONFIG" ]; then
  export KUBECONFIG="$ZHASK_KUBECONFIG"
  kubectl apply -f /tmp/zhask-deploy.yaml
  echo "✅ Kubernetes deployment applied"
elif [ -n "$ZHASK_DEPLOY_WEBHOOK" ]; then
  curl -X POST "$ZHASK_DEPLOY_WEBHOOK" \
    -H "Content-Type: application/json" \
    -d @/tmp/zhask-deploy.yaml
  echo "✅ Deployment webhook triggered"
else
  echo "⚠️  No deployment method configured. Please set ZHASK_KUBECONFIG or ZHASK_DEPLOY_WEBHOOK"
fi

# 6. Verify deployment
echo ""
echo "🔍 Verifying deployment..."
echo "Please verify the application is running at: https://$ZHASK_DOMAIN"

# 7. Health check
sleep 5
if curl -sf https://$ZHASK_DOMAIN/api/health >/dev/null 2>&1; then
  echo "✅ Health check PASSED - Application is running!"
else
  echo "⚠️  Health check failed. Application may still be starting."
  echo "Check zhask.io dashboard for deployment status."
fi

echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  Deployment Complete!"
echo "════════════════════════════════════════════════════════════════════"
echo "Dashboard:      https://$ZHASK_DOMAIN"
echo "API:            https://$ZHASK_DOMAIN/api"
echo "Health Check:   https://$ZHASK_DOMAIN/api/health"
echo ""
echo "📊 View logs:   zhask.io dashboard → Deployments → integrishield"
echo "🔧 Manage:      zhask.io dashboard → Applications → integrishield"
echo "════════════════════════════════════════════════════════════════════"
