# ONAP DCAE policy-handler

See [wiki for DCAE gen2 architecture of policy-handling by DCAE-controller](https://wiki.onap.org/display/DW/DCAE+gen2+architecture+of+policy-handling+by+DCAE-controller)

## web-service for policies to be used by DCAE-Controller

- GET `/policy_latest/<policy_id>` -- get the latest policy from policy-engine that is identified by `policy_id`
- POST `/policies_latest` -- gets the latest policies that match to the **policy-filter** provided in the body of the request.  The policy-filter mimics the body of the /getConfig on policy-engine.

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
