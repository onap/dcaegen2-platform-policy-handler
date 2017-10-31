"""
PolicyEngine API for Python

@author: Tarun, Mike
@version: 0.9
@change:
    added Enum 'Other' Type and supported it in PolicyConfig class - 1/13
    supporting Remote URL capability to the PolicyEngine as the parameter - 1/13
    Request format has been updated accordingly. No need to send the PDP URLs anymore - 1/26
    Feature where the PolicyEngine chooses available PyPDP among different URLs. 1/26
    Major feature addition required for Notifications 2/17 , Fixed Session issues. 2/25
    Major change in API structure for combining results 3/4.
    Added Security support for Notifications and clearNotification Method 3/18
    newMethod for retrieving configuration using policyFileName 3/20
    logging 3/24
    Notification Bug Fixes 7/21
    basic Auth 7/22
    Notification Changes 9/3
    ECOMP Error codes included 10/1
    -2016
    Major Changes to the Policy Engine API 3/29
    DeletePolicy API and Changes to pushPolicy and getConfig 5/27
    ConfigRequestParmeters and Error code Change 7/11
    New Environment Variable and Client Authorizations Change 7/21
    Changes to the Policy Parameters 8/21
    Allow Clients to use their own Password Protection.
    Dictionary Types and its Fixes.
"""

# org.onap.dcae
# ================================================================================
# Copyright (c) 2017 AT&T Intellectual Property. All rights reserved.
# ================================================================================
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ============LICENSE_END=========================================================
#
# ECOMP is a trademark and service mark of AT&T Intellectual Property.

import json,sys, os, collections, websocket , logging, time, base64, uuid
from websocket import create_connection
from enum import Enum
from xml.etree.ElementTree import XML
try:
    # For Python 3.0 and Later
    from pip._vendor import requests
except ImportError:
    # For backend Support to Python 2's urllib2
    import requests
try:
    # For Python 3.0 and Later
    from urllib.request import urlopen
except ImportError:
    # Fall back for Python 2.*
    from urllib2 import urlopen
try:
    import thread
except ImportError:
    #Fall Back for Python 2.x
    import _thread as thread

PolicyConfigStatus = Enum('PolicyConfigStatus', 'CONFIG_NOT_FOUND CONFIG_RETRIEVED')
PolicyType = Enum('PolicyType', 'JSON XML PROPERTIES OTHER')
PolicyResponseStatus = Enum('PolicyResponseStatus', 'ACTION_ADVISED ACTION_TAKEN NO_ACTION_REQUIRED')
NotificationType = Enum('NotificationType', 'BOTH UPDATE REMOVE')
UpdateType = Enum('UpdateType', 'UPDATE NEW')
NotificationScheme = Enum('NotificationScheme', 'AUTO_ALL_NOTIFICATIONS AUTO_NOTIFICATIONS MANUAL_ALL_NOTIFICATIONS MANUAL_NOTIFICATIONS')
AttributeType = Enum('AttributeType', 'MATCHING MICROSERVICE RULE SETTINGS')
PolicyClass = Enum('PolicyClass', 'Action Config Decision')
PolicyConfigType = Enum('PolicyConfigType', 'Base BRMS_PARAM BRMS_RAW ClosedLoop_Fault ClosedLoop_PM Firewall MicroService Extended')
DeletePolicyCondition = Enum('DeletePolicyCondition', 'ONE ALL')
RuleProvider = Enum('RuleProvider', 'Custom AAF GUARD_YAML')
DictionaryType = Enum('DictionaryType', 'Common Action ClosedLoop Firewall Decision BRMS GOC MicroService DescriptiveScope PolicyScope Enforcer SafePolicy' )
ImportType = Enum('ImportType', 'MICROSERVICE')

class PolicyEngine:
    """
    PolicyEngine is the Class which needs to be instantiated to call the PDP server.
    It needs the *.properties* file path as the parameter to the constructor.
    """
    def __init__(self, filename, scheme=None, handler=None, clientKey=None, basic_client_auth=True):
        """
        @param filename: String format of the path location of .properties file Could also be A remote URL eg: http://localhost:8080/config.properties
        @param scheme: NotificationScheme to select the scheme required for notification updates.
        @param handler: NotificationHandler object which will be called when an event is occurred.
        @param clientKey: Decoded Client Key to be used by PolicyEngine.
        @attention:The .properties file must contain the PYPDP_URL parameter in it. The parameter can have multiple URLs the PolicyEngine chooses the available PyPDP among them.
        """
        self.filename = filename
        self.urldict = {}
        self.matchStore = []
        self.autoURL = None
        self.scheme = None
        self.handler = None
        self.thread = thread
        self.autows = None
        self.mclose = False
        self.restart = False
        self.logger = logging.getLogger()
        self.resturl= []
        self.encoded= []
        self.clientInfo = None
        self.environment = None
        self.policyheader = {}
        if(filename.startswith("http")):
            try:
                policy_data = urlopen(filename)
                for line in policy_data :
                    line = line.decode('utf-8')
                    line = line.rstrip() # removes trailing whitespace and '\n' chars
                    line = line.replace(" ","") # removing spaces
                    if "=" not in line: continue #skips blanks and comments w/o =
                    if line.startswith("#"): continue  #skips comments which contain =
                    key, value = line.split("=",1)
                    key = key.rstrip().lstrip()
                    value = value.lstrip()
                    #print("key= "+key+" Value =" +value )
                    self.urldict[key] = value
            except:
                self.logger.error("PE300 - Data Issue: Error with the Config URL: %s" , filename )
                print("PE300 - Data Issue: Config Properties URL Error")
                sys.exit(0)
        else :
            fileExtension = os.path.splitext(filename)
            if(fileExtension[1]!=".properties"):
                self.logger.error("PE300 - Data Issue: File is not in properties format: %s", filename)
                print("PE300 - Data Issue: Not a .properties file!")
                sys.exit(0)
            try :
                with open(self.filename, 'r') as f:
                    for line in f:
                        line = line.rstrip() # removes trailing whitespace and '\n' chars
                        line = line.replace(" ","") # removing spaces
                        if "=" not in line: continue #skips blanks and comments w/o =
                        if line.startswith("#"): continue  #skips comments which contain =
                        key, value = line.split("=",1)
                        key = key.rstrip().lstrip()
                        value = value.lstrip()
                        # self.logger.info("key=%s Value=%s", key, value)
                        self.urldict[key] = value
            except FileNotFoundError:
                self.logger.error("PE300 - Data Issue: File Not found: %s", filename)
                print("PE300 - Data Issue: File Doesn't exist in the given Location")
                sys.exit(0)
        #TODO logic for best available PyPDP servers
        try:
            self.urldict = collections.OrderedDict(sorted(self.urldict.items()))
            clientID = self.urldict.get("CLIENT_ID")
            # self.logger.info("clientID decoded %s", base64.b64decode(clientID).decode("utf-8"))
            # client_parts = base64.b64decode(clientID).split(":")
            # client_parts = clientID.split(":")
            # self.logger.info("ClientAuth:Basic %s", base64.b64encode(clientID))
            # self.logger.info("CLIENT_ID[0] = %s", client_parts[0])
            # self.logger.info("CLIENT_ID[0] base64 = %s", base64.b64encode(client_parts[0]))
            # self.logger.info("CLIENT_KEY base64 = %s", base64.b64encode(client_parts[1]))
            if(clientKey is None):
                try:
                    client = base64.b64decode(self.urldict.get("CLIENT_KEY")).decode("utf-8")
                except Exception:
                    self.logger.warn("PE300 - Data Issue: CLIENT_KEY parameter is not in the required encoded Format taking Value as clear Text")
                    client = self.urldict.get("CLIENT_KEY")
            else:
                client = clientKey
            if(clientID is None or client is None):
                self.logger.error("PE300 - Data Issue: No CLIENT_ID and/or CLIENT_KEY parameter found in the properties file: %s ", filename)
                print("PE300 - Data Issue: No CLIENT_ID and/or CLIENT_KEY parameter found in the properties file")
                sys.exit(0)
            else:
                uid = clientID.encode('ascii')
                password = client.encode('ascii')
                self.clientInfo = base64.b64encode(uid+ b':'+password).decode('utf-8')
            self.environment = self.urldict.get("ENVIRONMENT")
            if(self.environment is None):
                self.logger.info("Missing Environment Variable setting to Default Value.")
                self.environment = "DEVL"
            self.policyheader = {
                "Content-type" : "application/json",
                "Accept" : "application/json",
                "ClientAuth" : ("Basic " if basic_client_auth else "") + self.clientInfo,
                "Environment" : self.environment
            }
            for key in self.urldict.keys():
                if(key.startswith("PYPDP_URL")):
                    pypdpVal = self.urldict.get(key)
                    if pypdpVal is None:
                        self.logger.error("PE300 - Data Issue: No PYPDP_URL Parameter found in the properties file: %s ", filename)
                        print("PE300 - Data Issue: No PYPDP_URL parameter found in the properties file")
                        sys.exit(0)
                    if ";" in pypdpVal:
                        pdpDefault = pypdpVal.split(";")
                        if pdpDefault is None:
                            self.logger.error("PE300 - Data Issue: No PYPDP_URL Parameter found in the properties file: %s ", filename)
                            print("PE300 - Data Issue: No PYPDP_URL parameter found in the properties file")
                            sys.exit(0)
                        else:
                            for count in range(0, len(pdpDefault)):
                                self.__pdpParam(pdpDefault[count])
                    else:
                        self.__pdpParam(pypdpVal)

            self.logger.info("PolicyEngine url: %s policyheader: %s urldict: %s", \
                             self.resturl, json.dumps(self.policyheader), json.dumps(self.urldict))
            if len(self.resturl)==0:
                self.logger.error("PE300 - Data Issue: No PYPDP_URL Parameter found in the properties file: %s ", filename)
                print("PE300 - Data Issue: No PYPDP_URL parameter found in the properties file")
                sys.exit(0)
        except:
            self.logger.error("PE300 - Data Issue: missing parameter(s) in the properties file: %s ", filename)
            print("PE300 - Data Issue: missing parameter(s) in the properties file")
            sys.exit(0)
        # Scheme and Handler code to be handled from here.
        if handler is not None:
            #if type(handler) is NotificationHandler:
            self.handler = handler
            #else:
            #    print("handler should be a object of NotificationHandler class")
            #    sys.exit(0)
        if scheme is not None:
            if ((scheme == NotificationScheme.AUTO_ALL_NOTIFICATIONS.name)or(scheme == NotificationScheme.AUTO_NOTIFICATIONS.name)):
                # setup the Auto settings.
                self.scheme = scheme
            elif ((scheme == NotificationScheme.MANUAL_ALL_NOTIFICATIONS.name)or(scheme == NotificationScheme.MANUAL_NOTIFICATIONS.name)):
                # setup the Manual Settings
                self.scheme = scheme
            else:
                self.logger.error("PE300 - Data Issue: Scheme not a type of NotificationScheme: %s", scheme.name)
                print("PE300 - Data Issue: scheme must be a Type of NotificationScheme Enumeration ")
                sys.exit(0)

    def __pdpParam(self,pdpValue):
        """
        Internal Usage for reading PyPDP Parameters
        """
        if pdpValue is None:
            self.logger.error("PE100 - Permissions Error: No Enough Credentials to send Request")
            print("PE100 - Permissions Error: No Enough Credentials to send Request")
            sys.exit(0)
        elif "," in pdpValue:
            pdpValues = pdpValue.split(",")
            if (len(pdpValues)==3):
                # 0 is pypdp URL
                self.resturl.append(pdpValues[0])
                # 1 and 2 are user name password
                if pdpValues[1] and pdpValues[2]:
                    uid = pdpValues[1].encode('ascii')
                    password = pdpValues[2].encode('ascii')
                    encoded = base64.b64encode(uid+ b':'+password).decode('utf-8')
                    self.encoded.append(encoded)
                else:
                    self.logger.error("PE100 - Permissions Error: No Enough Credentials to send Request")
                    print("PE100 - Permissions Error: No Enough Credentials to send Request")
                    sys.exit(0)
            else:
                self.logger.error("PE100 - Permissions Error: No Enough Credentials to send Request")
                print("PE100 - Permissions Error: No Enough Credentials to send Request")
                sys.exit(0)
        else:
            self.logger.error("PE100 - Permissions Error: No Enough Credentials to send Request")
            print("PE100 - Permissions Error: No Enough Credentials to send Request")
            sys.exit(0)

    def getConfigByPolicyName(self, policyName, requestID=None):
        """
        @param policyName: String format of the PolicyFile Name whose configuration is required.
        @return: Returns a List of PolicyConfig Object(s).
        @deprecated: use getConfig instead.
        """
        __policyNameURL = "/getConfigByPolicyName"
        __headers = self.policyheader
        if requestID is not None:
            __headers["X-ECOMP-RequestID"] = str(requestID)
        else:
            __headers["X-ECOMP-RequestID"] = str(uuid.uuid4())
        self.__policyNamejson = {}
        self.__policyNamejson['policyName'] = policyName
        self.__cpnResponse = self.__callPDP(__policyNameURL, json.dumps(self.__policyNamejson), __headers, "POST")
        self.__cpnJSON = self.__cpnResponse.json()
        policyConfigs= self.__configResponse(self.__cpnJSON)
        return policyConfigs

    def listConfig(self, eCOMPComponentName=None, configName=None, configAttributes=None, policyName=None, unique= False, requestID=None):
        """
        listConfig function calls the PDP for the configuration required using the parameters and returns the PDP response.
        @param eCOMPComponentName: String of the eCOMPComponentName whose configuration is required.
        @param configName: String of the configName whose configuration is required. Not Mandatory field.
        @param configAttributes: Dictionary of the config attributes in Key and Value String format. Not mandatory field.
        @param policyName: String of the policyName whose configuration is required.
        @param unique: Boolean value which can be set to True if Unique results are required.
        @param requestID: unique UUID for the request. Not mandatory field. If not provided, a value will be automatically generated.
        @return: Returns a List of PolicyNames.
        """
        __configURL = "/listConfig"
        __headers = self.policyheader
        if requestID is not None:
            __headers["X-ECOMP-RequestID"] = str(requestID)
        else:
            __headers["X-ECOMP-RequestID"] = str(uuid.uuid4())
        __configjson = self.__configRequestParametersJSON(eCOMPComponentName, configName, configAttributes, policyName, unique)
        #self.__configjson['pdp_URL'] = self.pdp_url
        __cResponse = self.__callPDP(__configURL, json.dumps(__configjson), __headers, "POST")
        return __cResponse.json()


    def getConfig(self, eCOMPComponentName=None, configName=None, configAttributes=None, policyName=None, unique= False, requestID=None):
        """
        getConfig function calls the PDP for the configuration required using the parameters and returns the PDP response.
        @param eCOMPComponentName: String of the eCOMPComponentName whose configuration is required.
        @param configName: String of the configName whose configuration is required. Not Mandatory field.
        @param configAttributes: Dictionary of the config attributes in Key and Value String format. Not mandatory field.
        @param policyName: String of the policyName whose configuration is required.
        @param unique: Boolean value which can be set to True if Unique results are required.
        @param requestID: unique UUID for the request. Not mandatory field. If not provided, a value will be automatically generated.
        @return: Returns a List of PolicyConfig Object(s).
        """
        __configURL = "/getConfig"
        __headers = self.policyheader
        if requestID is not None:
            __headers["X-ECOMP-RequestID"] = str(requestID)
        else:
            __headers["X-ECOMP-RequestID"] = str(uuid.uuid4())
        self.__configjson = self.__configRequestParametersJSON(eCOMPComponentName, configName, configAttributes, policyName, unique)
        #self.__configjson['pdp_URL'] = self.pdp_url
        self.__cResponse = self.__callPDP(__configURL, json.dumps(self.__configjson), __headers, "POST")
        #self.__configURL = self.resturl+__configURL
        #self.__cResponse = requests.post(self.__configURL, data=json.dumps(self.__configjson), headers = __headers)
        self.__cJSON = self.__cResponse.json()
        policyConfigs= self.__configResponse(self.__cJSON)
        # if we have successfully retrieved a policy we will store the match values.
        matchFound = False
        for policyConfig in policyConfigs:
            if policyConfig._policyConfigStatus == PolicyConfigStatus.CONFIG_RETRIEVED.name:
                # self.logger.info("Policy has been Retrieved !!")
                matchFound = True
        if matchFound:
            __match = {}
            __match["ECOMPName"] = eCOMPComponentName
            if configName is not None:
                __match["ConfigName"] = configName
            if configAttributes is not None:
                __match.update(configAttributes)
            if not self.matchStore:
                self.matchStore.append(__match)
            else:
                __booMatch = False
                for eachDict in self.matchStore:
                    if eachDict==__match:
                        __booMatch = True
                        break
                if __booMatch==False:
                    self.matchStore.append(__match)
        return policyConfigs

    def __configRequestParametersJSON(self, eCOMPComponentName=None, configName=None, configAttributes=None, policyName=None, unique= False):
        """ Internal Function to set JSON from configRequestParameters
        """
        json= {}
        if eCOMPComponentName is not None:
            json['ecompName'] = eCOMPComponentName
        if configName is not None:
            json['configName'] = configName
        if configAttributes is not None:
            json['configAttributes'] = configAttributes
        if policyName is not None:
            json['policyName'] = policyName
        json['unique'] = unique
        return json

    def __configResponse(self, cJSON):
        """
        Internal function to take the convert JSON to Response Object.
        """
        policyConfigs=[]
        for configJSON in cJSON:
            policyConfig = PolicyConfig()
            policyConfig._policyConfigMessage = configJSON['policyConfigMessage']
            policyConfig._policyConfigStatus = configJSON['policyConfigStatus']
            policyConfig._policyType = configJSON['type']
            policyConfig._policyName = configJSON['policyName']
            policyConfig._policyVersion = configJSON['policyVersion']
            policyConfig._matchingConditions = configJSON['matchingConditions']
            policyConfig._responseAttributes = configJSON['responseAttributes']
            if PolicyType.JSON.name == policyConfig._policyType:
                policyConfig._json = configJSON['config']
            elif PolicyType.XML.name == policyConfig._policyType:
                policyConfig._xml = XML(configJSON['config'])
            elif PolicyType.PROPERTIES.name == policyConfig._policyType:
                policyConfig._properties = configJSON['property']
            elif PolicyType.OTHER.name == policyConfig._policyType:
                policyConfig._other = configJSON['config']
            policyConfigs.append(policyConfig)
        return policyConfigs

    def getDecision(self, decisionAttributes, ecompcomponentName, requestID = None):
        """
        getDecision function sends the Decision Attributes to the PDP server and gets the response to the client from PDP.
        @param decisionAttributes: Dictionary of Decision Attributes in Key and Value String formats.
        @param ecompcomponentName:
        @param requestID: unique UUID for the request. Not mandatory field. If not provided, a value will be automatically generated.
        @return: Returns a DecisionResponse Object.
        """
        __decisionurl = "/getDecision"
        __headers = self.policyheader
        if requestID is not None:
            __headers["X-ECOMP-RequestID"] = str(requestID)
        else:
            __headers["X-ECOMP-RequestID"] = str(uuid.uuid4())
        self.__decisionjson={}
        self.__decisionjson['decisionAttributes'] = decisionAttributes
        self.__decisionjson['ecompcomponentName'] = ecompcomponentName
        self.__dResponse = self.__callPDP(__decisionurl, json.dumps(self.__decisionjson), __headers, "POST")
        self.__dJSON = self.__dResponse.json()
        decisionResponse = DecisionResponse()
        decisionResponse._decision = self.__dJSON['decision']
        decisionResponse._details = self.__dJSON['details']
        return decisionResponse

    def sendEvent(self, eventAttributes, requestID=None):
        """
        sendEvent function sends the Event to the PDP server and gets the response to the client from the PDP.
        @param eventAttributes:Dictonary of the EventAttributes in Key and Value String formats.
        @param requestID: unique UUID for the request. Not mandatory field. If not provided, a value will be automatically generated.
        @return: Returns a List of PolicyResponse Object(s).
        """
        __eventurl = "/sendEvent"
        __headers = self.policyheader
        if requestID is not None:
            __headers["X-ECOMP-RequestID"] = str(requestID)
        else:
            __headers["X-ECOMP-RequestID"] = str(uuid.uuid4())
        self.__eventjson = {}
        self.__eventjson['eventAttributes'] = eventAttributes
        #self.__eventjson['pdp_URL'] = self.pdp_url
        self.__eResponse = self.__callPDP(__eventurl, json.dumps(self.__eventjson), __headers, "POST")
        #self.__eventurl = self.resturl+__eventurl
        #self.__eResponse = requests.post(self.__eventurl, data=json.dumps(self.__eventjson), headers = __headers)
        self.__eJSON = self.__eResponse.json()
        policyResponses=[]
        for eventJSON in self.__eJSON:
            policyResponse = PolicyResponse()
            policyResponse._policyResponseMessage = eventJSON['policyResponseMessage']
            policyResponse._policyResponseStatus = eventJSON['policyResponseStatus']
            policyResponse._actionAdvised = eventJSON['actionAdvised']
            policyResponse._actionTaken = eventJSON['actionTaken']
            policyResponse._requestAttributes = eventJSON['requestAttributes']
            policyResponses.append(policyResponse)
        return policyResponses

    def createPolicy(self, policyParameters):
        """
        'createPolicy creates Policy using the policyParameters sent'
        @param policyParameters: This is an object of PolicyParameters which is required as a parameter to this method.
        @return: Returns a PolicyChangeResponse Object
        """
        __createurl = "/createPolicy"
        __headers = self.policyheader
        try:
            if policyParameters._requestID is None:
                policyParameters._requestID = str(uuid.uuid4())
            self.__createJson = {}
            self.__createJson = self.__policyParametersJSON(policyParameters)
            self.__createResponse = self.__callPDP(__createurl, json.dumps(self.__createJson), __headers, "PUT")
            policyChangeResponse = PolicyChangeResponse()
            policyChangeResponse._responseCode = self.__createResponse.status_code
            policyChangeResponse._responseMessage = self.__createResponse.text
            return policyChangeResponse
        except:
            self.logger.error("PE300 - Data Issue: Error with the policyParameters Object. It needs to be object of PolicyParameters ")
            print("PE300 - Data Issue: policyParamters object Error")

    def updatePolicy(self, policyParameters):
        """
        'updatePolicy updates Policy using the policyParameters sent.'
        @param policyParameters: This is an object of PolicyParameters which is required as a parameter to this method.
        @return: Returns a PolicyChangeResponse Object
        """
        __updateurl = "/updatePolicy"
        __headers = self.policyheader
        try:
            if policyParameters._requestID is None:
                policyParameters._requestID = str(uuid.uuid4())
            self.__updateJson = {}
            self.__updateJson = self.__policyParametersJSON(policyParameters)
            self.__updateResponse = self.__callPDP(__updateurl, json.dumps(self.__updateJson), __headers, "PUT")
            policyChangeResponse = PolicyChangeResponse()
            policyChangeResponse._responseCode = self.__updateResponse.status_code
            policyChangeResponse._responseMessage = self.__updateResponse.text
            return policyChangeResponse
        except:
            self.logger.error("PE300 - Data Issue: Error with the policyParameters Object. It needs to be object of PolicyParameters ")
            print("PE300 - Data Issue: policyParamters object Error")

    def __policyParametersJSON(self, policyParameters):
        """ Internal Function to set JSON from policyParameters Object
        """
        json= {}
        if policyParameters._actionAttribute is not None:
            json['actionAttribute'] = policyParameters._actionAttribute
        if policyParameters._actionPerformer is not None:
            json['actionPerformer'] = policyParameters._actionPerformer
        if policyParameters._attributes is not None:
            json['attributes'] = policyParameters._attributes
        if policyParameters._configBody is not None:
            json['configBody'] = policyParameters._configBody
        if policyParameters._configBodyType is not None:
            json['configBodyType'] = policyParameters._configBodyType
        if policyParameters._configName is not None:
            json['configName'] = policyParameters._configName
        if policyParameters._controllerName is not None:
            json['controllerName'] = policyParameters._controllerName
        if policyParameters._dependencyNames is not None:
            json['dependencyNames'] = policyParameters._dependencyNames
        if policyParameters._dynamicRuleAlgorithmLabels is not None:
            json['dynamicRuleAlgorithmLabels'] = policyParameters._dynamicRuleAlgorithmLabels
        if policyParameters._dynamicRuleAlgorithmField1 is not None:
            json['dynamicRuleAlgorithmField1'] = policyParameters._dynamicRuleAlgorithmField1
        if policyParameters._dynamicRuleAlgorithmField2 is not None:
            json['dynamicRuleAlgorithmField2'] = policyParameters._dynamicRuleAlgorithmField2
        if policyParameters._dynamicRuleAlgorithmFunctions is not None:
            json['dynamicRuleAlgorithmFunctions'] = policyParameters._dynamicRuleAlgorithmFunctions
        if policyParameters._ecompName is not None:
            json['ecompName'] = policyParameters._ecompName
        if policyParameters._extendedOption is not None:
			json['extendedOption'] = policyParameters._extendedOption
        if policyParameters._guard is not None:
            json['guard'] = policyParameters._guard
        if policyParameters._policyClass is not None:
            json['policyClass'] = policyParameters._policyClass
        if policyParameters._policyConfigType is not None:
            json['policyConfigType'] = policyParameters._policyConfigType
        if policyParameters._policyName is not None:
            json['policyName'] = policyParameters._policyName
        if policyParameters._policyDescription is not None:
            json['policyDescription'] = policyParameters._policyDescription
        if policyParameters._priority is not None:
            json['priority'] = policyParameters._priority
        if policyParameters._requestID is not None:
            json['requestID'] = policyParameters._requestID
        if policyParameters._riskLevel is not None:
            json['riskLevel'] = policyParameters._riskLevel
        if policyParameters._riskType is not None:
            json['riskType'] = policyParameters._riskType
        if policyParameters._ruleProvider is not None:
            json['ruleProvider'] = policyParameters._ruleProvider
        if policyParameters._ttlDate is not None:
            json['ttlDate'] = policyParameters._ttlDate
        return json

    def pushPolicy(self, pushPolicyParameters, requestID = None):
        """
        'pushPolicy pushes a policy based on the given Push Policy Parameters. '
        @param pushPolicyParameters: This is an object of PushPolicyParameters which is required as a parameter to this method.
        @param requestID: unique UUID for the request. Not mandatory field. If not provided, a value will be automatically generated.
        @return: Returns a PolicyChangeResponse Object
        """
        __pushurl = "/pushPolicy"
        __headers = self.policyheader
        if requestID is not None:
            __headers["X-ECOMP-RequestID"] = str(requestID)
        else:
            __headers["X-ECOMP-RequestID"] = str(uuid.uuid4())
        try:
            self.__pushJson = {}
            self.__pushJson['pdpGroup'] = pushPolicyParameters._pdpGroup
            self.__pushJson['policyName'] = pushPolicyParameters._policyName
            self.__pushJson['policyType'] = pushPolicyParameters._policyType
            self.__pushResponse = self.__callPDP(__pushurl, json.dumps(self.__pushJson), __headers, "PUT")
            policyChangeResponse = PolicyChangeResponse()
            policyChangeResponse._responseCode = self.__pushResponse.status_code
            policyChangeResponse._responseMessage = self.__pushResponse.text
            return policyChangeResponse
        except:
            self.logger.error("PE300 - Data Issue: Error with the pushPolicyParameters Object. It needs to be object of PushPolicyParameters ")
            print("PE300 - Data Issue: pushPolicyParamters object Error")

    def deletePolicy(self, deletePolicyParameters):
        """
        'deletePolicy Deletes a policy or all its version according to the given deletePolicyParameters'
        @param deletePolicyParameters: This is an Object of DeletePolicyParameters which is required as a parameter to this method.
        @return: Returns a PolicyChangeResponse Object
        """
        __deleteurl = "/deletePolicy"
        __createdictionaryurl = "/createDictionaryItem"
        __headers = self.policyheader
        try:
            if deletePolicyParameters._requestID is None:
                deletePolicyParameters._requestID = str(uuid.uuid4())
            self.__deleteJson = {}
            self.__deleteJson['deleteCondition'] = deletePolicyParameters._deleteCondition
            self.__deleteJson['pdpGroup'] = deletePolicyParameters._pdpGroup
            self.__deleteJson['policyComponent'] = deletePolicyParameters._policyComponent
            self.__deleteJson['policyName'] = deletePolicyParameters._policyName
            self.__deleteJson['policyType'] = deletePolicyParameters._policyType
            self.__deleteJson['requestID'] = deletePolicyParameters._requestID
            self.__deleteResponse = self.__callPDP(__deleteurl, json.dumps(self.__deleteJson), self.policyheader, "DELETE")
            policyChangeResponse = PolicyChangeResponse()
            policyChangeResponse._responseCode = self.__deleteResponse.status_code
            policyChangeResponse._responseMessage = self.__deleteResponse.text
            return policyChangeResponse
        except:
            self.logger.error("PE300 - Data Issue: Error with the deletePolicyParameters Object. It needs to be object of DeletePolicyParameters ")
            print("PE300 - Data Issue: deletePolicyParameters object Error")

    def createDictionaryItems(self, dictionaryParameters):
        """
        'createDictionaryItems adds dictionary items to the database for a specific dictionary'
        @param dictionaryParameters: This is an Object of DictionaryParameters which is required as a parameter to this method
        @return: Returns a DictionaryResponse object
        """
        __createdictionaryurl = '/createDictionaryItem'
        __headers = self.policyheader
        try:
            if dictionaryParameters._requestID is None:
                dictionaryParameters._requestID = str(uuid.uuid4())
            self.__json={}
            self.__json['dictionaryType'] = dictionaryParameters._dictionaryType
            self.__json['dictionary'] = dictionaryParameters._dictionary
            self.__json['dictionaryJson'] = dictionaryParameters._dictionaryJson
            self.__json['requestID'] = dictionaryParameters._requestID
            self.__createResponse = self.__callPDP(__createdictionaryurl, json.dumps(self.__json), __headers, "PUT")
            dictionaryResponse = DictionaryResponse()
            dictionaryResponse._responseCode = self.__createResponse.status_code
            dictionaryResponse._responseMessage = self.__createResponse.text
            return dictionaryResponse
        except:
            self.logger.error("PE300 - Data Issue:  Error with the dictionaryParameters object.  It needs to be object of DictionaryParameters ")
            print("PE300 - Data Issue:  dictionaryParameters object Error")


    def updateDictionaryItems(self, dictionaryParameters):
        """
        'updateDictionaryItems edits dictionary items in the database for a specific dictionary'
        @param dictionaryParameters: This is an Object of DictionaryParameters which is required as a parameter to this method
        @return: Returns a DictionaryResponse object
        """
        __updatedictionaryurl = '/updateDictionaryItem'
        __headers = self.policyheader
        try:
            if dictionaryParameters._requestID is None:
                dictionaryParameters._requestID = str(uuid.uuid4())
            self.__json={}
            self.__json['dictionaryType'] = dictionaryParameters._dictionaryType
            self.__json['dictionary'] = dictionaryParameters._dictionary
            self.__json['dictionaryJson'] = dictionaryParameters._dictionaryJson
            self.__json['requestID'] = dictionaryParameters._requestID
            self.__updateResponse = self.__callPDP(__updatedictionaryurl, json.dumps(self.__json), __headers, "PUT")
            dictionaryResponse = DictionaryResponse()
            dictionaryResponse._responseCode = self.__updateResponse.status_code
            dictionaryResponse._responseMessage = self.__updateResponse.text
            return dictionaryResponse
        except:
            self.logger.error("PE300 - Data Issue:  Error with the dictionaryParameters object.  It needs to be object of DictionaryParameters ")
            print("PE300 - Data Issue:  dictionaryParameters object Error")

    def getDictionaryItems(self, dictionaryParameters):
        """
        'getDictionaryItems gets all the dictionary items stored in the database for a specified dictionary'
        @param dictionaryParameters:  This is an Object of DictionaryParameters which is required as a parameter to this method.
        @return: Returns a DictionaryResponse object
        """
        __retrievedictionaryurl  = "/getDictionaryItems"
        __headers = self.policyheader
        try:
            if dictionaryParameters._requestID is None:
                dictionaryParameters._requestID = str(uuid.uuid4())
            self.__json = {}
            self.__json['dictionaryType'] = dictionaryParameters._dictionaryType
            self.__json['dictionary'] = dictionaryParameters._dictionary
            self.__json['requestID'] = dictionaryParameters._requestID
            self.__getResponse = self.__callPDP(__retrievedictionaryurl, json.dumps(self.__json), __headers, "POST")
            dictionaryResponse = DictionaryResponse()
            dictionaryResponse._responseCode = self.__getResponse.status_code
            dictionaryResponse._responseMessage = self.__getResponse.text
            return dictionaryResponse
        except:
            self.logger.error("PE300 - Data Issue:  Error with the dictionaryParameters object.  It needs to be object of DictionaryParameters ")
            print("PE300 - Data Issue:  dictionaryParameters object Error")

    def getNotification(self):
        """
        gets the PDPNotification if the appropriate NotificationScheme is selected.
        @return: Returns a PDPNotification Object.
        """
        if ((self.scheme == NotificationScheme.MANUAL_ALL_NOTIFICATIONS.name)or(self.scheme == NotificationScheme.MANUAL_NOTIFICATIONS.name)):
            # Manual Client for websocket Code in here.
            if(self.resturl[0].startswith("https")):
                __man_url = self.resturl[0].replace("https","wss")+"notifications"
            else:
                __man_url = self.resturl[0].replace("http","ws")+"notifications"
            __result = self.__manualRequest(__man_url)
            self.logger.debug("Manual Notification with server: %s \n result is: %s" , __man_url , __result)
            # TODO convert the result to PDP Notifications.
            if (self.scheme == NotificationScheme.MANUAL_ALL_NOTIFICATIONS.name):
                # need to add all the values to the PDPNotification..
                pDPNotification = PDPNotification()
                boo_Remove = False
                boo_Update = False
                if __result is None:
                    return None
                if __result['removedPolicies']:
                    removedPolicies = []
                    for removed in __result['removedPolicies']:
                        removedPolicy = RemovedPolicy()
                        removedPolicy._policyName = removed['policyName']
                        removedPolicy._policyVersion = removed['versionNo']
                        removedPolicies.append(removedPolicy)
                    pDPNotification._removedPolicies= removedPolicies
                    boo_Remove = True
                if __result['loadedPolicies']:
                    updatedPolicies = []
                    for updated in __result['loadedPolicies']:
                        updatedPolicy = LoadedPolicy()
                        updatedPolicy._policyName = updated['policyName']
                        updatedPolicy._policyVersion = updated['versionNo']
                        updatedPolicy._matchingConditions = updated['matches']
                        updatedPolicy._updateType = updated['updateType']
                        updatedPolicies.append(updatedPolicy)
                    pDPNotification._loadedPolicies= updatedPolicies
                    boo_Update = True
                if (boo_Update and boo_Remove):
                    pDPNotification._notificationType = NotificationType.BOTH.name
                elif boo_Update:
                    pDPNotification._notificationType = NotificationType.UPDATE.name
                elif boo_Remove:
                    pDPNotification._notificationType = NotificationType.REMOVE.name
                return pDPNotification
            elif (self.scheme == NotificationScheme.MANUAL_NOTIFICATIONS.name):
                return self.__checkNotification(__result)
        else:
            return None

    def setNotification(self, scheme, handler = None):
        """
        setNotification allows changes to the NotificationScheme and the NotificationHandler.
        @param scheme: NotificationScheme to select the scheme required for notification updates.
        @param handler: NotificationHandler object which will be called when an event is occurred.
        """
        if handler is not None:
            #if type(handler) is NotificationHandler:
            self.handler = handler
            #else:
            #    print("Error: handler should be a object of NotificationHandler class")
        if scheme is not None:
            if ((scheme == NotificationScheme.AUTO_ALL_NOTIFICATIONS.name)or(scheme == NotificationScheme.AUTO_NOTIFICATIONS.name)):
                # setup the Auto settings.
                self.scheme = scheme
                self.__startAuto()
            elif ((scheme == NotificationScheme.MANUAL_ALL_NOTIFICATIONS.name)or(scheme == NotificationScheme.MANUAL_NOTIFICATIONS.name)):
                # setup the Manual Settings
                self.scheme = scheme
            else:
                print("PE300 - Data Issue: scheme must be a Type of NotificationScheme Enumeration ")

    def clearNotification(self):
        """
        clearNotification ShutsDown the AutoNotification service if running.
        """
        if self.scheme is not None:
            if((self.scheme == NotificationScheme.AUTO_ALL_NOTIFICATIONS.name)or(self.scheme == NotificationScheme.AUTO_NOTIFICATIONS.name)):
                if self.autows.sock is not None:
                    if(self.autows.sock.connected):
                        self.mclose = True
                        self.autows.close()
                        self.logger.info("Notification Service Stopped.")
                        print("Notification Service is Stopped!!")

    def __callPDP(self,urlFunction, jsonData, headerData,method, files= None, params = None):
        """
        This function call is for internal usage purpose only.
        Calls the available PyPDP
        """
        connected = False
        response = None
        errormessage = ''
        for count in range(0, len(self.resturl)):
            try:
                logging.basicConfig(level=logging.DEBUG)
                request_url = self.resturl[0]+ urlFunction
                self.logger.debug("--- Sending Request to : %s",request_url)
                try:
                    self.logger.debug("Request ID %s :",headerData["X-ECOMP-RequestID"])
                except:
                    if jsonData is not None:
                        self.logger.debug("Request ID %s :",json.loads(jsonData)['requestID'])
                self.logger.debug("Request Data is: %s" ,jsonData)
                headerData["Authorization"]= "Basic " + self.encoded[0]
                if(method=="PUT"):
                    response = requests.put(request_url, data = jsonData, headers = headerData)
                elif(method=="DELETE"):
                    response = requests.delete(request_url, data = jsonData, headers = headerData)
                elif(method=="POST"):
                    if params is not None:
                        # files = files, params = params,
                        response = requests.post(request_url, params = params, headers = headerData)
                    else:
                        response = requests.post(request_url, data = jsonData, headers = headerData)
                # when using self-signed server certificate, comment previous line and uncomment following:
                #response = requests.post(request_url, data = jsonData, headers = headerData, verify=False)
                self.logger.debug("--- Response is : ---")
                self.logger.debug(response.status_code)
                self.logger.debug(response.headers)
                self.logger.debug(response.text)
                if(response.status_code == 200) :
                    connected = True
                    self.logger.info("connected to the PyPDP: %s", request_url)
                    break
                elif(response.status_code == 202) :
                    connected = True
                    break
                elif(response.status_code == 400):
                    self.logger.debug("PE400 - Schema Issue: Incorrect Params passed: %s %s", self.resturl[0], response.status_code)
                    errormessage+="\n PE400 - Schema Issue: Incorrect Params passed: "+ self.resturl[0]
                    self.__rotatePDP()
                elif(response.status_code == 401):
                    self.logger.debug("PE100 - Permissions Error: PyPDP Error: %s %s", self.resturl[0], response.status_code)
                    errormessage+="\n PE100 - Permissions Error: PyPDP Error: "+ self.resturl[0]
                    self.__rotatePDP()
                elif(response.status_code == 403):
                    self.logger.debug("PE100 - Permissions Error: PyPDP Error: %s %s", self.resturl[0], response.status_code)
                    errormessage+="\n PE100 - Permissions Error: PyPDP Error: "+ self.resturl[0]
                    self.__rotatePDP()
                else:
                    self.logger.debug("PE200 - System Error: PyPDP Error: %s %s", self.resturl[0], response.status_code)
                    errormessage+="\n PE200 - System Error: PyPDP Error: "+ self.resturl[0]
                    self.__rotatePDP()
            except Exception as e:
                print(str(e));
                self.logger.debug("PE200 - System Error: PyPDP Error: %s", self.resturl[0])
                errormessage+="\n PE200 - System Error: PyPDP Error: "+ self.resturl[0]
                self.__rotatePDP()
        if(connected):
            if(self.autoURL==None):
                self.__startAuto()
            elif(self.autoURL!= self.resturl[0]):
                self.__startAuto()
            return response
        else:
            self.logger.error("PE200 - System Error: cannot connect to given PYPDPServer(s) %s", self.resturl)
            print(errormessage)
            sys.exit(0)

    def __rotatePDP(self):
        self.resturl = collections.deque(self.resturl)
        self.resturl.rotate(-1)
        self.encoded = collections.deque(self.encoded)
        self.encoded.rotate(-1)

    def __checkNotification(self, resultJson):
        """
        This function call is for Internal usage purpose only.
        Checks the Notification JSON compares it with the MatchStore and returns the PDPNotification object.
        """
        if not resultJson:
            return None
        if not self.matchStore:
            return None
        pDPNotification = PDPNotification()
        boo_Remove = False
        boo_Update = False
        if resultJson['removedPolicies']:
            removedPolicies = []
            for removed in resultJson['removedPolicies']:
                removedPolicy = RemovedPolicy()
                removedPolicy._policyName = removed['policyName']
                removedPolicy._policyVersion = removed['versionNo']
                removedPolicies.append(removedPolicy)
            pDPNotification._removedPolicies= removedPolicies
            boo_Remove = True
        if resultJson['updatedPolicies']:
            updatedPolicies = []
            for updated in resultJson['updatedPolicies']:
                updatedPolicy = LoadedPolicy()
                # check if it has matches then it is a Config Policy and compare it with Match Store.
                if updated['matches']:
                    # compare the matches with our Stored Matches
                    for eachDict in self.matchStore:
                        if eachDict==updated['matches']:
                            updatedPolicy._policyName = updated['policyName']
                            updatedPolicy._policyVersion = updated['versionNo']
                            updatedPolicy._matchingConditions = updated['matches']
                            updatedPolicy._updateType = updated['updateType']
                            updatedPolicies.append(updatedPolicy)
                            boo_Update = True
                else:
                    updatedPolicy._policyName = updated['policyName']
                    updatedPolicy._policyVersion = updated['versionNo']
                    updatedPolicies.append(updatedPolicy)
                    boo_Update = True
            pDPNotification._loadedPolicies= updatedPolicies
        if (boo_Update and boo_Remove):
            pDPNotification._notificationType = NotificationType.BOTH.name
        elif boo_Update:
            pDPNotification._notificationType = NotificationType.UPDATE.name
        elif boo_Remove:
            pDPNotification._notificationType = NotificationType.REMOVE.name
        return pDPNotification

    def __startAuto(self):
        """
        Starts the Auto Notification Feature..
        """
        if self.scheme is not None:
            if ((self.scheme == NotificationScheme.AUTO_ALL_NOTIFICATIONS.name)or(self.scheme == NotificationScheme.AUTO_NOTIFICATIONS.name)):
                if self.handler is None:
                    if self.autows.sock is not None:
                        if(self.autows.sock.connected):
                            self.mclose= True
                            self.autows.close()
                else:
                    if self.autoURL is None:
                        self.autoURL = self.resturl[0]
                    elif self.autoURL != self.resturl[0]:
                        self.autoURL = self.resturl[0]
                        if self.autows.sock is not None:
                            if(self.autows.sock.connected):
                                self.mclose= True
                                self.autows.close()
                        else:
                            self.autows = None
                    if self.autows is None:
                        if(self.autoURL.startswith("https")):
                            __auto_url = self.autoURL.replace("https","wss")+"notifications"
                        else:
                            __auto_url = self.autoURL.replace("http","ws")+"notifications"
                        def run(*args):
                            self.__autoRequest(__auto_url)
                        self.logger.info("Starting AutoNotification Service with : %s" , __auto_url)
                        self.thread.start_new_thread(run , ())
                    elif self.autows.sock is not None:
                        if not (self.autows.sock.connected):
                            self.mclose = True
                            self.autows.close()
                            self.restart = True
                            self.__rotatePDP()
                            if(self.autoURL.startswith("https")):
                                __auto_url = self.autoURL.replace("https","wss")+"notifications"
                            else:
                                __auto_url = self.autoURL.replace("http","ws")+"notifications"
                            def run(*args):
                                self.__autoRequest(__auto_url)
                            self.logger.info("Starting AutoNotification Service with : %s" , __auto_url)
                            self.thread.start_new_thread(run , ())

            else:
                #stop the Auto Notification Service if it is running.
                if self.autows.sock is not None:
                    if(self.autows.sock.connected):
                        self.mclose= True
                        self.autows.close()

    def __onEvent(self, message):
        """
        Handles the event Notification received.
        """
        message = json.loads(message)
        if self.handler is not None:
            if (self.scheme == NotificationScheme.AUTO_ALL_NOTIFICATIONS.name):
                pDPNotification = PDPNotification()
                boo_Remove = False
                boo_Update = False
                if message['removedPolicies']:
                    removedPolicies = []
                    for removed in message['removedPolicies']:
                        removedPolicy = RemovedPolicy()
                        removedPolicy._policyName = removed['policyName']
                        removedPolicy._policyVersion = removed['versionNo']
                        removedPolicies.append(removedPolicy)
                    pDPNotification._removedPolicies= removedPolicies
                    boo_Remove = True
                if message['loadedPolicies']:
                    updatedPolicies = []
                    for updated in message['loadedPolicies']:
                        updatedPolicy = LoadedPolicy()
                        updatedPolicy._policyName = updated['policyName']
                        updatedPolicy._policyVersion = updated['versionNo']
                        updatedPolicy._matchingConditions = updated['matches']
                        updatedPolicy._updateType = updated['updateType']
                        updatedPolicies.append(updatedPolicy)
                    pDPNotification._loadedPolicies= updatedPolicies
                    boo_Update = True
                if (boo_Update and boo_Remove):
                    pDPNotification._notificationType = NotificationType.BOTH.name
                elif boo_Update:
                    pDPNotification._notificationType = NotificationType.UPDATE.name
                elif boo_Remove:
                    pDPNotification._notificationType = NotificationType.REMOVE.name
                # call the Handler.
                self.handler.notificationReceived(pDPNotification)
            elif (self.scheme == NotificationScheme.AUTO_NOTIFICATIONS.name):
                # call the handler
                self.handler(self.__checkNotification(message))

    def __manualRequest(self,request_url):
        """
        Takes the request_URL given and returns the JSON response back to the Caller.
        """
        ws = create_connection(request_url)
        # when using self-signed server certificate, comment previous line and uncomment following:
        #ws = create_connection(request_url, sslopt={"cert_reqs": ssl.CERT_NONE})
        ws.send("Manual")
        try:
            return json.loads(ws.recv())
        except:
            return None
        ws.close()
        ws.shutdown()

    def __onMessage(self, ws,message):
        """Occurs on Event
        """
        self.logger.info("Received AutoNotification message: %s" , message)
        self.__onEvent(message)

    def __onError(self, ws, error):
        """Self Restart the Notification Service on Error
        """
        self.logger.error("PE500 - Process Flow Issue: Auto Notification service Error!! : %s" , error)

    def __onclose(self, ws):
        """Occurs on Close ? Try to start again in case User didn't do it.
        """
        self.logger.debug("Connection has been Closed. ")
        if not self.mclose:
            self.__startAuto()
        self.mclose = False

    def __autoRequest(self, request_url):
        """
        Takes the request_URL and invokes the PolicyEngine method on any receiving a Message
        """
        websocket.enableTrace(True)
        self.autows = websocket.WebSocketApp(request_url, on_message= self.__onMessage, on_close= self.__onclose, on_error= self.__onError)
        # wait for to 5 seconds to restart
        if self.restart:
            time.sleep(5)
        self.autows.run_forever()

class NotificationHandler:
    """
    'Defines the methods which need to run when an Event or a Notification is received.'
    """
    def notificationReceived(self, notification):
        """
        Will be triggered automatically whenever a Notification is received by the PEP
        @param notification: PDPNotification object which has the information of the Policies.
        @attention: This method must be implemented by the user for AUTO type NotificationScheme
        """
        raise Exception("Unimplemented abstract method: %s" % __functionId(self, 1))

def __functionId(obj, nFramesUp):
    """ Internal Usage only..
    Create a string naming the function n frames up on the stack. """
    fr = sys._getframe(nFramesUp+1)
    co = fr.f_code
    return "%s.%s" % (obj.__class__, co.co_name)

class PolicyConfig:
    """
    'PolicyConfig is the return object resulted by getConfig Call.'
    """
    def __init__(self):
        self._policyConfigMessage = None
        self._policyConfigStatus = None
        self._policyName = None
        self._policyVersion = None
        self._matchingConditions = None
        self._responseAttributes = None
        self._policyType = None
        self._json = None
        self._xml = None
        self._prop = None
        self._other = None

class PolicyResponse:
    """
    'PolicyResponse is the return object resulted by sendEvent Call.'
    """
    def __init__(self):
        self._policyResponseStatus = None
        self._policyResponseMessage = None
        self._requestAttributes = None
        self._actionTaken = None
        self._actionAdvised= None

class PDPNotification:
    """
    'Defines the Notification Event sent from the PDP to PEP Client.'
    """
    def __init__(self):
        self._removedPolicies = None
        self._loadedPolicies = None
        self._notificationType = None

class RemovedPolicy:
    """
    'Defines the structure of the Removed Policy'
    """
    def __init__(self):
        self._policyName = None
        self._policyVersion = None

class LoadedPolicy:
    """
    'Defines the Structure of the Loaded Policy'
    """
    def __init__(self):
        self._policyName = None
        self._policyVersion = None
        self._matchingConditions = None
        self._updateType = None

class PolicyParameters:
    """
    'Defines the Structure of the Policy to Create or Update'
    """
    def __init__(self):
        self._actionPerformer = None
        self._actionAttribute = None
        self._attributes = None
        self._configBody = None
        self._configBodyType = None
        self._configName = None
        self._controllerName = None
        self._dependencyNames = None
        self._dynamicRuleAlgorithmLabels = None
        self._dynamicRuleAlgorithmFunctions = None
        self._dynamicRuleAlgorithmField1 = None
        self._dynamicRuleAlgorithmField2 = None
        self._ecompName = None
        self._extendedOption = None
        self._guard = None
        self._policyClass = None
        self._policyConfigType = None
        self._policyName = None
        self._policyDescription = None
        self._priority = None
        self._requestID = None
        self._riskLevel = None
        self._riskType = None
        self._ruleProvider = None
        self._ttlDate = None

class PushPolicyParameters:
    """
    'Defines the Structure of the Push Policy Parameters'
    """
    def __init__(self):
        self._pdpGroup = None
        self._policyName = None
        self._policyType = None

class PolicyChangeResponse:
    """
    'Defines the Structure of the policy Changes made from PDP'
    """
    def __init__(self):
        self._responseMessage = None
        self._responseCode = None

class DeletePolicyParameters:
    """
    'Defines the Structure of the Delete Policy Parameters'
    """
    def __init__(self):
        self._deleteCondition = None
        self._pdpGroup = None
        self._policyComponent = None
        self._policyName = None
        self._policyType = None
        self._requestID = None

class DictionaryParameters:
    """
    'Defines the Structure of the Dictionary Parameters'
    """
    def __init__(self):
        self._dictionaryType = None
        self._dictionary = None
        self._dictionaryJson = None
        self._requestID = None

class DictionaryResponse:
    """
    'Defines the Structure of the dictionary response'
    """
    def __init__(self):
        self._responseMessage = None
        self._responseCode = None
        self._dictionaryJson = None
        self._dictionaryData = None

class DecisionResponse:
    """
    'Defines the Structure of Decision Response'
    """
    def __init__(self):
        self._decision = None
        self._details = None

class ImportParameters:
    """
    'Defines the Structure of Policy Model Import'
    """
    def __init__(self):
        self._serviceName = None
        self._description = None
        self._requestID = None
        self._filePath = None
        self._importBody = None
        self._version = None
        self._importType = None
