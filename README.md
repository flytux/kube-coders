# kube-coders


---

멀티 개발자가 VS Code 기반으로 원격 개발이 가능한 환경을 제공합니다.
- Code-Server를 기준으로 kubernetes 클러스터 내 개별 파드를 구성하여 제공합니다.
- Keycloak 통합 인증 서버를 통해 사용자 인증을 수행합니다. (OIDC)
- API Gateway에서 사용자 인증 처리 후 Keycloak 사용자 ID (sub)를 이용하여 각 사용자 별 Code-Server로 연결합니다.
- Code-Server는 API Gateway에 등록된 사설인증서를 이용한 TLS 통신으로 동작합니다. (Extension 정상 구동 시 필요)
- Code-Server 버전과 VS-Code 버전에 따라 지원되는 extension을 컨테이너 이미지 빌드시 포함하여 구성합니다.
- 각 사용자별 코드 서버 배포는 Keycloak 사용자 등록 --> 사용자 별 개발 환경 배포 (Helm chart) 형태로 수행되고, 자동화 구성이 필요합니다. (TBD)
---
![kube-coders-overview](./images/kube-coders-overview.png)  
---
![coders-screenshot](./images/coders-screenshot.png)  
---

### 구성 순서
---

**1. nfs, nfs-csi storage class 설치**
```
# nfs 서버 설치
apt install nfs-server
dnf install nfs-utils

mkdir -p /var/nfs/pv
chown -R 65534:65534 /var/nfs/pv

# 파일 공유 설정
cat <<EOF > /etc/exports
/var/nfs/pv 192.168.122.126(rw,sync,no_subtree_check,no_root_squash)  # node 1
/var/nfs/pv 192.168.122.210(rw,sync,no_subtree_check,no_root_squash)  # node 2
EOF

# nfs-csi 드라이버 설치
curl -skSL https://raw.githubusercontent.com/kubernetes-csi/csi-driver-nfs/v4.5.0/deploy/install-driver.sh | bash -s v4.5.0 --

# strageclass 설치
$ cat <<EOF > nfs-sc.yml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: nfs-csi
provisioner: nfs.csi.k8s.io
parameters:
  server: 192.168.45.46
  share: /var/nfs/pv
  mountPermissions: "0777"
reclaimPolicy: Retain
volumeBindingMode: Immediate
mountOptions:
  - nfsvers=4.1
EOF

kubectl apply -f nfs-sc.yml

kubectl patch storageclass nfs-csi -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'

# pvc 생성 테스트
kubectl create -f https://raw.githubusercontent.com/kubernetes-csi/csi-driver-nfs/master/deploy/example/pvc-nfs-csi-dynamic.yaml

# snapshot controller 설치

kubectl apply -f https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/v6.0.1/client/config/crd/snapshot.storage.k8s.io_volumesnapshotclasses.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/v6.0.1/client/config/crd/snapshot.storage.k8s.io_volumesnapshotcontents.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/v6.0.1/client/config/crd/snapshot.storage.k8s.io_volumesnapshots.yaml

kubectl apply -f https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/v6.0.1/deploy/kubernetes/snapshot-controller/rbac-snapshot-controller.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/v6.0.1/deploy/kubernetes/snapshot-controller/setup-snapshot-controller.yaml

# snapshotclass 설치
kubectl apply -f https://raw.githubusercontent.com/kubernetes-csi/csi-driver-nfs/master/deploy/example/snapshot/snapshotclass-nfs.yaml

# volumesnapshot 생성
kubectl apply -f https://raw.githubusercontent.com/kubernetes-csi/csi-driver-nfs/master/deploy/example/snapshot/snapshot-nfs-dynamic.yaml

# pvc 생성 from volumesnapshot
kubectl apply -f https://raw.githubusercontent.com/kubernetes-csi/csi-driver-nfs/master/deploy/example/snapshot/pvc-nfs-snapshot-restored.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-csi/csi-driver-nfs/master/deploy/example/snapshot/nginx-pod-restored-snapshot.yaml

```

**2. apisix-gateway 설치**
```
# helm chart를 이용한 apisix 설치

# apisix ingress와 tls 설정을 추가한 values.yaml을 적용한다.

# self signed 인증서 생성 (Wildcard Top Level Domain 인식안됨 *.local -> *.kw.local)
# openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes -keyout local.key -out local.crt -subj '/CN=*.kw.local' -addext 'subjectAltName=DNS:*.kw.local'

openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes -keyout gateway.key -out gateway.crt -subj '/CN=gateway.local' -addext 'subjectAltName=DNS:gateway.local'

# 인증서 시크릿 생성
kubectl create secret tls gateway-tls --key gateway.key --cert gateway.crt -n apisix

# apisix 설치
helm upgrade -i apisix apisix-2.10.0.tgz -f values.yaml -n apisix --create-namespace

```

**3. keycloak 설치**

```
# Keycloak 설치
helm upgrade -i keycloak keycloak-24.5.0.tgz -f values.yaml -n keycloak --create-namespace
```

**4. keycloak realm, user 설정**

```
# 변수 설정
KEYCLOAK_URL="http://key.local"
ADMIN_USERNAME="admin"
ADMIN_PASSWORD="admin"
REALM_NAME="dev"
CLIENT_ID="apisix"

# ADMIN_TOKEN 조회
ADMIN_TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
         -H "Content-Type: application/x-www-form-urlencoded" \
         -d "username=${ADMIN_USERNAME}" \
         -d "password=${ADMIN_PASSWORD}" \
         -d "grant_type=password" \
         -d "client_id=admin-cli" | jq -r '.access_token')

# ADMIN_TOKEN TTL 변경 -> 1 시간
curl -s -X PUT "${KEYCLOAK_URL}/admin/realms/master" \
     -H "Authorization: Bearer ${ADMIN_TOKEN}" \
     -H "Content-Type: application/json" \
     -d '{
         "accessTokenLifespan": 3600
     }'

# dev realm 생성		 
curl -s -X POST "${KEYCLOAK_URL}/admin/realms" \
     -H "Authorization: Bearer ${ADMIN_TOKEN}" \
     -H "Content-Type: application/json" \
     -d '{"realm":"'${REALM_NAME}'", "enabled":true}'		 
		 
# apisix client 생성		 
curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/clients" \
     -H "Authorization: Bearer ${ADMIN_TOKEN}" \
     -H "Content-Type: application/json" \
     -d '{
         "clientId": "'${CLIENT_ID}'",
         "protocol": "openid-connect",
         "publicClient": false,
         "standardFlowEnabled": true,
         "directAccessGrantsEnabled": true,
         "webOrigins": ["+"]
     }'

# client uuid 조회	 
CLIENT_UUID=$(curl "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/clients" -H "Authorization: Bearer ${ADMIN_TOKEN}" |  jq -r --arg CLIENT_ID "$CLIENT_ID" '.[] | select(.clientId == $CLIENT_ID) | .id')

# client secret 조회
CLIENT_SECRET=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/clients/${CLIENT_UUID}/client-secret" \
     -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq -r '.value')

# 사용자 생성
curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/users" \
     -H "Authorization: Bearer ${ADMIN_TOKEN}" \
     -H "Content-Type: application/json" \
     -d '{
           "username": "jaehoon",
           "email": "jaehoon@kubeworks.net",
           "enabled": true,
           "firstName": "Jaehoon",
           "lastName": "Jung",
           "credentials": [{"type": "password", "value": "1", "temporary": false}]
       }'

# 사용자 ID 조회	   
USER_ID=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/users?username=jaehoon" \
     -H "Authorization: Bearer ${ADMIN_TOKEN}" \
     | jq -r '.[0].id')
```

**5. code-server 배포**

```
# Service 이름을 code-$USER_ID 로 설정하여 코드서버을 Deployment로 생성하여 배포
# Code 서버의 최신 버전 이미지를 플러그인 포함하여 빌드
# Keycloak USER_ID 생성 후 자동으로 배포하도록 구성
```

**6. apisix route 설정**

```
# CoreDNS에 클러스터 인그레스 엔트리 추가
hosts {
        192.168.100.1 gateway.local dash.local key.local
        fallthrough
}

# APISIX Dashboard에서 Route 추가
---
uri: /*
name: 'code-server-route'
plugins:
  openid-connect:
    _meta:
      disable: false
    bearer_only: false
    client_id: apisix                                 # CLIENT_ID
    client_secret: lk0DLH9zJcn4uGmtLi4hJ9SYJIzE32l6   # CLIENT_SECRET
    discovery: http://keycloak.keycloak/realms/dev/.well-known/openid-configuration
    introspection_endpoint_auth_method: client_secret_post
    realm: dev    
    token_endpoint_auth_method: client_secret_basic
  proxy-rewrite:
    regex_uri:
      - ^/(.*)
      - /$1
  serverless-post-function:
    functions:
      - |
        function log(conf, ctx)
          local core = require "apisix.core"
          local b64 = require("ngx.base64")
          local cjson = require "cjson"
          local upstream = require("apisix.upstream")
          local ipmatcher  = require("resty.ipmatcher")
          local jwt_userinfo = core.request.header(ctx, "X-Userinfo")
          decoded_userinfo, err = b64.decode_base64url(jwt_userinfo)
          local userinfo = cjson.decode(decoded_userinfo)
          ngx.log(ngx.ERR, "UserId: " .. userinfo.sub)
          local host_name = "code-" .. userinfo.sub
          local function parse_domain(host)
            local ip = ""
            local host_name = host .. .code-server
            if not ipmatcher.parse_ipv4(host) and not ipmatcher.parse_ipv6(host)
            then
              local ip, err = core.resolver.parse_domain(host)
              if ip then
                return ip
              end
              if err then
                core.log.error("dns resolver domain: ", host, " error: ", err)
              end
            end
            return host
          end
          local up_conf = {
                            timeout = {
                            connect = 6,
                            send = 300,
                            read = 300
                            },
                            scheme = "http",
                            type = "roundrobin",
                            pass_host = "pass",
                            keepalive_pool = {
                              idle_timeout = 60,
                              requests = 1000,
                              size = 320
                            },
                            hash_on = "vars",
                            nodes = {
                              {
                                priority = 0,
                                port = 8443,
                                host = parse_domain(host_name),
                                weight = 1
                              }
                            }
                          }
          local matched_route = ctx.matched_route
          up_conf.parent = matched_route
          local upstream_key = up_conf.type .. "#route_" .. matched_route.value.id
          core.log.info("upstream_key: ", upstream_key)
          upstream.set(ctx, upstream_key, ctx.conf_version, up_conf)  
        end
        return log
    phase: access
upstream:
  nodes:
    - host: httpbin.org
      port: 80
      weight: 1
  type: roundrobin
  scheme: http
  pass_host: pass
enable_websocket: true
```
