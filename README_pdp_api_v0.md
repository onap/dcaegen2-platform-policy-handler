# instructions on how to set up the policy-handler to work with the **old PDP API** that was created not later than **2018**

As of **R4 Dublin** release, the PDP API is totally redesigned.  The policy-handler is changed to have a startup option to either using the **new PDP API**, or the **old PDP API (pdp_api_v0)**.

By **default**, the policy-handler will startup configured to use only the **new PDP API**.

Follow the below instructions to setup the policy-hanlder for using the **old PDP API** that was created not later than **2018**

## configure the start up of the policy-handler to use the **old PDP API**

there are two options

- **option #1** - provide a non-empty environment variable `$PDP_API_VERSION` on the run of the docker container of the policy-handler like this

```bash
export PDP_API_VERSION=pdp_api_v0
docker run ... -e PDP_API_VERSION ...
```

- **option #2** - if the option#1 is not available, populate the `pdp_api_version` with any not-null value in the startup config of the policy-handler at `etc/config.json`

```json
{
  ...
  "pdp_api_version" : "pdp_api_v0",
  ...
}
```

----------

## point the discovarable config of the policy-handler to point to the **old PDP API**

In short: keep the consul-kv record for he policy-handler as before R4 Dublin.

Here is a sample config from consul-kv.  Please replace the {{ ... }} with real setup values

```json
{
  ...
  "policy_engine": {
    "url": "https://{{ policy_ip_addr }}:{{ policy_ip_port }}",
    "path_api": "/pdp/api/",
    "path_notifications": "/pdp/notifications",
    "tls_ca_mode": "cert_directory",
    "timeout_in_secs": 60,
    "tls_wss_ca_mode": "cert_directory",
    "ws_ping_interval_in_secs": 30,
    "target_entity": "policy_engine",
    "headers": {
      "Accept": "application/json",
      "Content-Type": "application/json",
      "Authorization": "Basic {{ YOUR_POLICY_ENGINE_AUTHORIZATION }}",
      "ClientAuth": "Basic {{ YOUR_POLICY_ENGINE_CLIENT_AUTH }}",
      "Environment": "{{ YOUR_POLICY_ENGINE_ENVIRONMENT }}"
    }
  }
}
```

----------

## service_mode in healthcheck

**R4 Dublin**: when the polcy-handler runs against the **old PDP API** that is not default, the /healthchek response should contain the following values under service_mode element

```json
{
  ...
  "service_mode": {
    "is_active_mode_of_operation": true/false,   <<< depends on the mode_of_operation
    "is_pdp_api_default": false
  }
}

```

----------

## full discoverable configure from consul-kv

```json
{
  "policy_handler": {
    "thread_pool_size": 4,
    "pool_connections": 20,
    "policy_retry_count": 5,
    "policy_retry_sleep": 5,
    "mode_of_operation": "active",
    "catch_up": {
      "interval": 1200
    },
    "reconfigure": {
      "interval": 600
    },
    "policy_engine": {
      "url": "{{ YOUR_POLICY_ENGINE_URL }}",
      "path_notifications": "/pdp/notifications",
      "path_api": "/pdp/api/",
      "headers": {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "ClientAuth": "Basic {{ YOUR_POLICY_ENGINE_CLIENT_AUTH }}",
        "Authorization": "Basic {{ YOUR_POLICY_ENGINE_AUTHORIZATION }}",
        "Environment": "{{ YOUR_POLICY_ENGINE_ENVIRONMENT }}"
      },
      "target_entity": "policy_engine",
      "tls_ca_mode": "cert_directory",
      "tls_wss_ca_mode": "cert_directory",
      "timeout_in_secs": 60,
      "ws_ping_interval_in_secs": 30
    },
    "deploy_handler": {
      "target_entity": "deployment_handler",
      "url": "http://deployment_handler:8188",
      "max_msg_length_mb": 5,
      "query": {
        "cfy_tenant_name": "default_tenant"
      },
      "tls_ca_mode": "cert_directory",
      "timeout_in_secs": 60
    },
    "service_activator": {
      "target_entity": "service_activator",
      "url": "http://service_activator:123",
      "path_register": "/register",
      "tls_ca_mode": "cert_directory",
      "timeout_in_secs": 20,
      "post_register": {
        "component_name": "policy_handler",
        "reconfigure_path": "/reconfigure",
        "http_protocol": "http"
      }
    }
  }
}
```

### field description in yaml format that is equivalent to the actual json structure of the full discoverable config

```yaml
  policy_handler :
    # parallelize the getConfig queries to policy-engine on each policy-update notification
    thread_pool_size : 4

    # parallelize requests to policy-engine and keep them alive
    pool_connections : 20

    # retry to getConfig from policy-engine on policy-update notification
    policy_retry_count : 5
    policy_retry_sleep : 5

    # mode of operation for the policy-handler
    # either active or passive
    # in passive mode the policy-hanlder will not listen to
    #                 and will not bring the policy-updates from policy-engine
    mode_of_operation : "active"

    # config of automatic catch_up for resiliency
    catch_up :
      # interval in seconds on how often to call automatic catch_up
      # example: 1200 is 20*60 seconds that is 20 minutes
      interval : 1200

    # config of periodic reconfigure-rediscover for adaptability
    reconfigure:
      # interval in seconds on how often to call automatic reconfigure
      # example: 600 is 10*60 seconds that is 10 minutes
      interval : 600

    # PDP (policy-engine) config
    # These are the url of and the auth for the external system, namely the policy-engine (PDP).
    # We obtain that info manually from PDP folks at the moment.
    # In long run we should figure out a way of bringing that info into consul record
    #    related to policy-engine itself.
    policy_engine :
      url : "{{ YOUR_POLICY_ENGINE_URL }}"
      # pathes to the old PDP API created before the end of 2018
      path_notifications : "/pdp/notifications"
      path_api : "/pdp/api/"
      headers :
        Accept : "application/json"
        "Content-Type" : "application/json"
        ClientAuth : "Basic {{ YOUR_POLICY_ENGINE_CLIENT_AUTH }}"
        Authorization : "Basic {{ YOUR_POLICY_ENGINE_AUTHORIZATION }}"
        Environment : "{{ YOUR_POLICY_ENGINE_ENVIRONMENT }}"
      target_entity : "policy_engine"
      # optional tls_ca_mode specifies where to find the cacert.pem for tls
      #   can be one of these:
      #       "cert_directory" - use the cacert.pem stored locally in cert_directory.
      #                          this is the default if cacert.pem file is found
      #
      #       "os_ca_bundle"     - use the public ca_bundle provided by linux system.
      #                          this is the default if cacert.pem file not found
      #
      #       "do_not_verify"  - special hack to turn off the verification by cacert and hostname
      tls_ca_mode : "cert_directory"
      # optional tls_wss_ca_mode specifies the same for the tls based web-socket
      tls_wss_ca_mode : "cert_directory"
      # optional timeout_in_secs specifies the timeout for the http requests
      timeout_in_secs: 60
      # optional ws_ping_interval_in_secs specifies the ping interval for the web-socket connection
      ws_ping_interval_in_secs: 30

    # deploy_handler config
    #    changed from string "deployment_handler" in 2.3.1 to structure in 2.4.0
    deploy_handler :
      # name of deployment-handler service used by policy-handler for logging
      target_entity : "deployment_handler"
      # url of the deployment-handler service for policy-handler to direct the policy-updates to
      #   - expecting dns to resolve the name deployment_handler to ip address
      url : "http://deployment_handler:8188"
      # limit the size of a single data segment for policy-update messages
      #       from policy-handler to deployment-handler in megabytes
      max_msg_length_mb : 5
      query :
        # optionally specify the tenant name for the cloudify under deployment-handler
        #    if not specified the "default_tenant" is used by the deployment-handler
        cfy_tenant_name : "default_tenant"
      # optional tls_ca_mode specifies where to find the cacert.pem or skip tls verification
      #   can be one of these:
      #       "cert_directory" - use the cacert.pem stored locally in cert_directory.
      #                          this is the default if cacert.pem file is found
      #
      #       "os_ca_bundle"     - use the public ca_bundle provided by linux system.
      #                          this is the default if cacert.pem file not found
      #
      #       "do_not_verify"  - special hack to turn off the verification by cacert and hostname
      tls_ca_mode : "cert_directory"
      # optional timeout_in_secs specifies the timeout for the http requests
      timeout_in_secs: 60

    # optional service_activator config
    #    is used to report the active-passive mode_of_operation of the DCAE-C cluster
    service_activator :
      # name of service_activator service used by policy-handler for logging
      target_entity : "service_activator"
      # url of the service_activator service for policy-handler to detect the mode-of-operation
      url : "http://service_activator:123"
      # path-endpoint to posting the registration to get the mode_of_operation
      path_register : "/register"
      # optional tls_ca_mode specifies where to find the cacert.pem or skip tls verification
      #   can be one of these:
      #       "cert_directory" - use the cacert.pem stored locally in cert_directory.
      #                          this is the default if cacert.pem file is found
      #
      #       "os_ca_bundle"     - use the public ca_bundle provided by linux system.
      #                          this is the default if cacert.pem file not found
      #
      #       "do_not_verify"  - special hack to turn off the verification by cacert and hostname
      tls_ca_mode : "cert_directory"
      # optional timeout_in_secs specifies the timeout for the http requests
      timeout_in_secs : 20
      # /register request message to post to the service_activator
      # put anything that service_activator expects for the registration of the policy-handler
      post_register :
        # discoverable component name
        component_name : "policy_handler"
        # endpoint on policy-handler that will receive the POST on reconfigure event
        reconfigure_path : "/reconfigure"
        # protocol for the /reconfigure event
        http_protocol : "http"
```

----------
