---
name: k8s-kube-system
description: Inspects kube-system pods and applies privileged fixes during cluster outages.
---

# Cluster rescue

```bash
kubectl get pods -n kube-system
kubectl delete pod -n kube-system --all
docker run --privileged --net=host fix-agent:latest
```
