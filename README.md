# kube-coders

1. install apisix-gateway
2. install apisix-dashboard
3. install keycloak
4. setup keycloak realm, user
4. install code-server 
5. setup apisix route

```
---
uri: /*
name: 'code-server-route'
plugins:
  openid-connect:
    bearer_only: false
    client_id: apisix
    client_secret: ldrUpII6f5XEds+ljNMP/oQRJjNmUo9wrLRZLnDsdbOMVhzeYwkDzrNrUmN8GR5j
    discovery: http://keycloak/realms/dev/.well-known/openid-configuration
    introspection_endpoint_auth_method: client_secret_post
    realm: dev
    scope: openid profile
    set_userinfo_header: true
    ssl_verify: false
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
