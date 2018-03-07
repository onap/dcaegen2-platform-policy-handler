# policy_handler

## web-service for policies to be used by DCAE-Controller

- GET **/policy\_latest/***\<policy-id>* -- get the latest policy from policy-engine
- receives the **push notifications** from policy-engine through the web-socket, filters and gets the full policy-configs, and delivers that to deploy-handler

## manual http API

- GET **/catch_up** -- catch up with the latest state of the policy-engine
- GET **/policies_latest** -- get all the latest policies in policy-engine through web-service API
- GET **/shutdown** -- shutdown the server

----------

## installation

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

## configure

in folder `policy_handler`:

    - `config.json` contains
        - `"scope_prefixes" : ["DCAE.Config_"]` - the list of policy-scope-class values
        - `"policy_engine"` - the http connect info to ONAP **policy-engine**
            - headers.ClientAuth : base64(<mech-id with namespace>:<password>)
            - headers.Authorization : base64(<policy-engine server auth>)
        - `"deploy_handler"` - the http connect info to _policy part_ of the **deploy-handler**
    - `policy_engine.properties` contains config info for the client lib of ONAP **policy-engine** that receives push notifications from the ONAP **policy-engine** server
        - CLIENT_ID is the mech-id with the namespace - need to register with policy-engine team thru email
        - CLIENT_KEY is the base64 of the mech-id password - separate passwords for TEST versus PROD

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

contains ```CustomizeBase``` and ```Customize``` classes

- ```CustomizeBase``` defines the interface and the default=ONAP behavior

- ```CustomizeBase``` is owned by ONAP and should not be changed by the company

- ```Customize``` inherits ```CustomizeBase```

- policy-handler instantiates ```Customize``` to get the customized behavior

- ```Customize``` is owned by the company and should be changed by the company
- ONAP is not going to change ```Customize```

- the methods of ```Customize``` are expected to be overridden by the company to change the behavior of the policy-handler

- samples are provided for methods in ```Customize``` class as the commented out lines

- Company is allowed to add more files to customize/ folder if that is required for better structuring of their code as soon as it is invoked by the methods of ```Customize```

----------
