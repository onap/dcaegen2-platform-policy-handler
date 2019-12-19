# ============LICENSE_START=======================================================
 # policy-handler
 #  ================================================================================
 #  Copyright (C) 2019 Wipro Limited.
 #  ==============================================================================
 #   Licensed under the Apache License, Version 2.0 (the "License");
 #   you may not use this file except in compliance with the License.
 #   You may obtain a copy of the License at
 #
 #        http://www.apache.org/licenses/LICENSE-2.0
 #
 #   Unless required by applicable law or agreed to in writing, software
 #   distributed under the License is distributed on an "AS IS" BASIS,
 #   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 #   See the License for the specific language governing permissions and
 #   limitations under the License.
 #   ============LICENSE_END=========================================================


import requests as r
import threading
from urllib.parse import urljoin

class DMaaPError(Exception):
	pass



class Subscribe:
	"""Subscribe to DMaap to listen for policy change message"""
	def __init__(self):
		self.server_info = ""
		self.topic=""
		self.group=""
		self.group_id=""
		self.http_retries = 10
		self.username=""
		self.passwd=""

	def url_join(host, version, *additional_path):
		return urlparse.urljoin(host, os.path.join(version, *additional_path))

	def receive(self):
		http_headers = {"Accept": "application/json"}
		retry_count=0
		dmaap_sub_success=False
		path= ("events/"+self.topic+"/"+self.group+"/"+self.group_id)
		url = urljoin(self.server_info,path)

		while not dmaap_sub_success and retry_count < (self.http_retries):
			try:
				if(self.username==""):
					http_resp=r.get(url,http_headers)
					if http_resp.status_code == r.codes.ok:
						resp= http_resp.json()

						while http_resp.status_code == r.codes.ok and (resp is None or resp is ""):

							http_resp=r.get(url,http_headers)
							resp= http_resp.json()

						return resp,http_resp.status_code


					else:
						return msg, http_resp.status_code

			except OSError as e:
				msg = "OS exception while attempting to post: %s" % (str(e))
				raise OSError(msg)

			retry_count+=1

		if not dmaap_sub_success:
		   mssg = "ALL subscribe attempts failed"
		   raise DMaaPError(mssg)
