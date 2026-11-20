def connect(url, ca_bundle):
    return request(url, verify=ca_bundle)
