# ONAP DCAE policy-handler

See [wiki for DCAE gen2 architecture of policy-handling by DCAE-controller](https://wiki.onap.org/display/DW/DCAE+gen2+architecture+of+policy-handling+by+DCAE-controller)

## web-service for policies to be used by DCAE-Controller

- GET `/policy_latest/<policy_id>` -- get the latest policy from policy-engine that is identified by `policy_id`
- POST `/policies_latest` -- *only for the old(pdp_api_v0) PDP API* -- gets the latest policies that match to the **policy-filter** provided in the body of the request.  The policy-filter mimics the body of the /getConfig on policy-engine.

    sample request - policy-filter

```json
{
  "configAttributes": { "key1":"value1" },
  "configName": "alex_config_name",
  "onapName": "DCAE",
  "policyName": "DCAE_alex.Config_alex_.*",
  "unique": false
}
```

- GET `/healthcheck` - returns 200 OK and current run stats
- **web-socket** to **policy-engine**
  - receives the **push notifications** of the changed and removed policies from the policy-engine,
  - matches the policy-updates to policies and policy-filters found in deployment-handler,
  - retrieves the full policy-bodies of the matched policies,
  - delivers the policy-updates to deployment-handler

## manual http API

- GET `/policies_latest` -- get all the latest policies from policy-engine that either have the policy_id or match to the policy-filter found in deployment-handler deployments
- GET `/catch_up` -- catch up with the latest state of the policy-engine
- GET `/shutdown` -- shutdown the server

----------

## standalone installation

`virtualenv policy_venv`

`cd policy_venv`

`source bin/activate`

`cd ../policy_handler`

`pip install -r requirements.txt`

----------

## preparation to run

`cd policy_venv`

`source bin/activate`

`cd ../policy_handler`

----------

## local configure

local config file `policy_handler/etc/config.json` contains:

```json
{
  "wservice_port" : 25577,
  "consul_url" : "http://consul:8500",
  "consul_timeout_in_secs" : 60,
  "pdp_api_version" : null,
  "policy_handler" : {
    "system" : "policy_handler",
    "tls" : {
      "cert_directory" : "etc/tls/certs/",
      "cacert" : "cacert.pem",
      "private_key" : "key.pem",
      "server_cert" : "cert.pem",
      "server_ca_chain" : "ca_chain.pem"
    }
  },
  "logging" : {...}
}
```

Field descriptions

- `wservice_port` - port of the policy-hanlder web-service
- `consul_url` - optional url for the consul agent
- `consul_timeout_in_secs` - optional timeout in seconds to wait for the response from consul agent
- `pdp_api_version` - optional value for PDP_API_VERSION.
  - The default PDP API is used when this field is null or absent.  The new PDP as of 2019 is the default
  - To use the old PDP API that was created before the end of 2018, put any value like pdp_api_v0 into this field.  Alternatlively, provide a non-empty environment variable $PDP_API_VERSION=pdp_api_v0 on the run of the docker container
- `policy_handler` - local config for policy-handler application
  - `system` - general system name of the policy-handler
  - `tls` - tls settings for the https clients and server - required to enable tls
    - `cert_directory` - relative path pointing to the folder with certificates
    - `cacert` - file name for the ca-cert or ca-bundle file in pem format in cert_directory -- used by https clients
    - `private_key` - file name for the private key in cert_directory -- used by https server
    - `server_cert` - file name for the https server certificate file in pem format in cert_directory
    - `server_ca_chain` - file name for the optional https server ca-chain certificates file in pem format in cert_directory -- used when the ca-chain is not included in the server_cert file
- `logging` - logging config for general logging

----------

## discoverable configure from consul-kv for the **new PDP API**

on the start of the policy-handler, it will get the discoverable part of the configure from consul-kv for the key taken from the `local-config.policy_handler.system`

See [README_pdp_api_v0.md](Readme_pdp_api_v0.md) for instructions on how to set up the policy-handler to work with the **old PDP API** that was created not later than **2018**

### using the new PDP API

As of **R4 Dublin** release, the PDP API is totally redesigned.  The policy-handler is changed to have a startup option to either using the new PDP API, or the old PDP API (pdp_api_v0).

By **default**, the policy-handler will startup configured to use only the **new PDP API**.

#### service_mode in healthcheck

**R4 Dublin**: when the polcy-handler runs against the default **new PDP API**, the /healthchek response should contain the following values under service_mode element

```json
{
  ...
  "service_mode": {
    "is_active_mode_of_operation": false,
    "is_pdp_api_default": true
  }
}

```

#### make sure that the start up of the policy-handler is configured to use the **new PDP API**

make sure that both of the following settings are set properly

- make sure that the environment variable `$PDP_API_VERSION` is either **empty** or **not set** at all on the run of the docker container of the policy-handler

- make sure that the `pdp_api_version` param is either `null` or not present in the startup config of the policy-handler at `etc/config.json`

```json
{
    "pdp_api_version" : null,
}
```

#### the discovarable config of the policy-handler to point to the **new PDP API**

In short: keep the consul-kv record for the policy-handler as before R4 Dublin.

Here is a sample config from consul-kv.  Please replace the {{ ... }} with real setup values

```json
{
  ...
  "policy_engine": {
    "url": "https://{{ policy_ip_addr }}:{{ policy_ip_port }}",
    "path_decision": "/decision/v1",
    "tls_ca_mode": "cert_directory",
    "timeout_in_secs": 60,
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
      "path_decision": "/decision/v1",
      "headers": {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "ClientAuth": "Basic {{ YOUR_POLICY_ENGINE_CLIENT_AUTH }}",
        "Authorization": "Basic {{ YOUR_POLICY_ENGINE_AUTHORIZATION }}",
        "Environment": "{{ YOUR_POLICY_ENGINE_ENVIRONMENT }}"
      },
      "target_entity": "policy_engine",
      "tls_ca_mode": "cert_directory",
      "timeout_in_secs": 60
    },
    "dmaap_mr" : {
        "url" : "http://{{ YOUR_DMAAP_MR_URL }}/events/{{ POLICY_UPDATE_TOPICNAME }}/{{ POLICY_UPDATE_CONSUMEGROUP }}/{{ POLICY_UPDATE_CONSUMERID }}",
        "query": {
          "timeout": 15000
        },
        "headers" : {
            "Content-Type" : "application/json",
            "Authorization": "Basic {{ YOUR_DMAAP_MR_SUBSCRIBER_AUTHORIZATION }}"
        },
        "target_entity" : "dmaap_mr",
        "tls_ca_mode" : "cert_directory",
        "timeout_in_secs": 60
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
      # path to decision on the new PDP API as of 2019
      path_decision : "/decision/v1"
      headers :
        Accept : "application/json"
        "Content-Type" : "application/json"
        ClientAuth : "Basic {{ YOUR_POLICY_ENGINE_CLIENT_AUTH }}"

        # to override the Authorization value,
        #    set the environment vars $PDP_USER and $PDP_PWD in policy-handler
        Authorization : "Basic {{ YOUR_POLICY_ENGINE_AUTHORIZATION }}"

        Environment : "{{ YOUR_POLICY_ENGINE_ENVIRONMENT }}"

      # target_entity name that is used for logging
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
      # optional timeout_in_secs specifies the timeout for the http requests
      timeout_in_secs: 60


    # DMaaP MR subscriber config
    # These are the url of and the auth for the external system, namely the policy-engine (PDP).
    # We obtain that info manually from PDP and DMaaP folks at the moment.
    dmaap_mr :
      url: "http://{{ YOUR_DMAAP_MR_URL }}/events/{{ POLICY_UPDATE_TOPICNAME }}/{{ POLICY_UPDATE_CONSUMEGROUP }}/{{ POLICY_UPDATE_CONSUMERID }}"

      query:
        # The number of milliseconds for DMaaP MR to wait for messages if none are immediately available.
        # This should normally be used, and set at 15000 or higher.
        # This is referred to as long-polling timeout
        # ?timeout=15000 passed to DMaaP MR in the query
        timeout: 15000

      headers:
        "Content-Type": "application/json"
        # provide Authorization for the subscriber if using https and user-password authentication
        # to override the Authorization value,
        #    set the environment vars $DMAAP_MR_USER and $DMAAP_MR_PWD in policy-handler
        Authorization: "Basic {{ YOUR_DMAAP_MR_SUBSCRIBER_AUTHORIZATION }}"

      # target_entity name that is used for logging
      target_entity: "dmaap_mr"
      # optional tls_ca_mode specifies where to find the cacert.pem for tls
      #   can be one of these:
      #       "cert_directory" - use the cacert.pem stored locally in cert_directory.
      #                          this is the default if cacert.pem file is found
      #
      #       "os_ca_bundle"     - use the public ca_bundle provided by linux system.
      #                          this is the default if cacert.pem file not found
      #
      #       "do_not_verify"  - special hack to turn off the verification by cacert and hostname
      tls_ca_mode: "cert_directory"
      # optional timeout_in_secs specifies the timeout for the http requests
      timeout_in_secs: 60


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

## run

in folder `policy_handler`:

`./run_policy.sh`

----------

## customization per company

### ```etc_customize/``` folder

- company is expected to place any company specific files required to be in the docker image in the folder ```etc_customize/```

- change the ```etc_customize/customize.sh``` script to perform company specific actions during docker image build

- ```etc_customize/customize.sh``` script is expected to be overridden by company to customize docker image build

### ```policyhandler/customize/``` folder

contains ```CustomizerBase``` and ```Customizer``` classes

- ```CustomizerBase``` defines the interface and the default=ONAP behavior

- ```CustomizerBase``` is owned by ONAP and should not be changed by the company

- ```Customizer``` inherits ```CustomizerBase```

- policy-handler instantiates ```Customizer``` to get the customized behavior

- ```Customizer``` is owned by the company and should be changed by the company
- ONAP is not going to change ```Customizer```

- the methods of ```Customizer``` are expected to be overridden by the company to change the behavior of the policy-handler

- samples are provided for methods in ```Customizer``` class as the commented out lines

- Company is allowed to add more files to customize/ folder if that is required for better structuring of their code as soon as it is invoked by the methods of ```Customizer```

here is an example of ```customizer.py```

```python
"""contains the Customizer class with method overrides per company specification"""

from .customizer_base import CustomizerBase

class Customizer(CustomizerBase):
    """
    the Customizer class inherits CustomizerBase that is owned by ONAP

    :Customizer: class is owned by the company that needs to customize the policy-handler

    :override: any method defined in the CustomizerBase class to customize the behavior of the policy-handler
    """
    def __init__(self):
        """class that contains the customization"""
        super().__init__()

    def get_service_url(self, audit, service_name, service):
        """
        returns the service url when called from DiscoveryClient

        this is just a sample code - replace it with the real customization
        """
        service_url = super().get_service_url(audit, service_name, service)
        audit.info("TODO: customization for service_url on {0}".format(service_name))
        return service_url
```

----------
