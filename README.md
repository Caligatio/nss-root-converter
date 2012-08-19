Extracting Mozilla's NSS Root Certificates
==========================================

With Python 3.2 now natively supporting SSL certificate validation, a Pythonic way is needed to create a PEM formatted certificate chain file.  While many people use the file made available by the cURL project (http://curl.haxx.se/ca/cacert.pem), it is not served via HTTPS and is therefore insecure to download.  Fortunately, the source of the cURL's certificate authority bundle is available over HTTPS but unfortunately is in a difficult-to-use format:

    https://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1

These Python scripts will download the Mozilla NSS-friendly file (unless the script itself is given a PEM-formatted CA file, the download will be unvalidated) and convert it into the PEM format which then can be used by Python, cURL, php_curl, Apache/mod_ssl, etc.

Note that this functionality is available already in a few other languages:
	Go - https://github.com/agl/extract-nss-root-certs
	Perl - https://github.com/bagder/curl/blob/master/lib/mk-ca-bundle.pl
