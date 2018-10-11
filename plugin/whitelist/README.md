# whitelist

### Description

*whitelist* sends traffic to tufin agent and enforce tufin policy

### Syntax

```
data:
  Corefile: |
    internal:54 {
        forward . 0.0.0.0:53
    }
    .:54 {
        health
        whitelist cluster.local {
          pods verified
        }
        proxy . 0.0.0.0:53
        log
    }
```

kubectl -n kube-system edit cm coredns