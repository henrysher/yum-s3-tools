#!/usr/bin/env python
# Copyright 2014, Henry Huang
# Copyright 2012, Julius Seporaitis
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

__version__ = "0.0.1"

import base64
import hashlib
import hmac
import json
import re
import socket
import time
import urllib2
import urlparse

import yum.plugins
from yum.yumRepo import YumRepository

__all__ = ['requires_api_version',
           'plugin_type',
           'init_hook']

requires_api_version = '2.5'
plugin_type = yum.plugins.TYPE_CORE

timeout = 60
retries = 5
metadata_server = "http://169.254.169.254"


class CredentialError(Exception):

    """
    Credential Error"
    """
    pass


def _check_s3_urls(urls):
    pattern = "s3.*\.amazonaws\.com"
    if isinstance(urls, basestring):
        if re.compile(pattern).findall(urls) != []:
            return True
    elif isinstance(urls, list):
        for url in urls:
            if re.compile(pattern).findall(url) != []:
                break
        else:
            # Only for the list with all non-S3 URLs
            return False
    return True


def retry_url(url, retry_on_404=False, num_retries=retries, timeout=timeout):
    """
    Retry a url.  This is specifically used for accessing the metadata
    service on an instance.  Since this address should never be proxied
    (for security reasons), we create a ProxyHandler with a NULL
    dictionary to override any proxy settings in the environment.
    """

    original = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)

    for i in range(0, num_retries):
        try:
            proxy_handler = urllib2.ProxyHandler({})
            opener = urllib2.build_opener(proxy_handler)
            req = urllib2.Request(url)
            r = opener.open(req)
            result = r.read()
            return result
        except urllib2.HTTPError as e:
            # in 2.6 you use getcode(), in 2.5 and earlier you use code
            if hasattr(e, 'getcode'):
                code = e.getcode()
            else:
                code = e.code
            if code == 404 and not retry_on_404:
                return None
        except Exception as e:
            pass
        print '[ERROR] Caught exception reading instance data'
        # If not on the last iteration of the loop then sleep.
        if i + 1 != num_retries:
            time.sleep(2 ** i)
    print '[ERROR] Unable to read instance data, giving up'
    return None


def get_iam_role(url=metadata_server, version="latest",
                 params="meta-data/iam/security-credentials/"):
    """
    Read IAM role from AWS metadata store.
    """
    url = urlparse.urljoin(url, "/".join([version, params]))
    result = retry_url(url)
    if result is None:
        # print "No IAM role found in the machine"
        return None
    else:
        return result


def get_credentials_from_iam_role(url=metadata_server,
                                  version="latest",
                                  params="meta-data/iam/security-credentials/",
                                  iam_role=None):
    """
    Read IAM credentials from AWS metadata store.
    """
    url = urlparse.urljoin(url, "/".join([version, params, iam_role]))
    result = retry_url(url)
    if result is None:
        # print "No IAM credentials found in the machine"
        return None
    try:
        data = json.loads(result)
    except ValueError as e:
        # print "Corrupt data found in IAM credentials"
        return None

    access_key = data.get('AccessKeyId', None)
    secret_key = data.get('SecretAccessKey', None)
    token = data.get('Token', None)

    if access_key and secret_key and token:
        return (access_key, secret_key, token)
    else:
        return None


def init_hook(conduit):
    """
    Setup the S3 repositories
    """
    corrupt_repos = []
    s3_repos = {}

    repos = conduit.getRepos()
    for key, repo in repos.repos.iteritems():
        if isinstance(repo, YumRepository) and repo.enabled:
            if repo.baseurl and _check_s3_urls(repo.baseurl):
                s3_repos.update({key: repo})

    for key, repo in s3_repos.iteritems():
        try:
            new_repo = S3Repository(repo.id, repo, conduit)
        except CredentialError as e:
            # Credential Error is a general problem
            # will affect all S3 repos
            corrupt_repos = s3_repos.keys()
            break
        except Exception as e:
            corrupt_repos.append(key)
            continue

        # Correct yum repo on S3
        repos.delete(key)
        repos.add(new_repo)

    # Delete the incorrect yum repo on S3
    for repo in corrupt_repos:
        repos.delete(repo)


class S3Repository(YumRepository):

    """
    Repository object for Amazon S3
    """

    def __init__(self, repoid, repo, conduit):
        super(S3Repository, self).__init__(repoid)
        self.repoid = repoid
        self.conduit = conduit

        # FIXME: dirty code here
        self.__dict__.update(repo.__dict__)

        # Inherited from YumRepository <-- Repository
        self.enable()
        self.set_credentials()

    def _getFile(self, url=None, relative=None, local=None,
                 start=None, end=None,
                 copy_local=None, checkfunc=None, text=None,
                 reget='simple', cache=True, size=None, **kwargs):
        """
        Patched _getFile func via AWS S3 REST API
        """
        mirrors = self.grab.mirrors
        # mirrors always exists as a list
        # and each element (dict) with a key named "mirror"
        for mirror in mirrors:
            baseurl = mirror["mirror"]
            super(S3Repository, self).grab.mirrors = [mirror]
            if _check_s3_urls(baseurl):
                self.http_headers = self.fetch_headers(baseurl, relative)
            else:
                # non-S3 URL
                self.http_headers = tuple(
                    self.__headersListFromDict(cache=cache))
            try:
                return super(S3Repository, self)._getFile(url, relative, local,
                                                          start, end,
                                                          copy_local,
                                                          checkfunc, text,
                                                          reget, cache,
                                                          size, **kwargs)
            except Exception as e:
                self.conduit.info(3, str(e))

    __get = _getFile

    def set_credentials(self):

        # Fetch params from local config file
        global timeout, retries, metadata_server
        timeout = self.conduit.confInt('aws', 'timeout', default=timeout)
        retries = self.conduit.confInt('aws', 'retries', default=retries)
        metadata_server = self.conduit.confString(
            'aws', 'metadata_server', default=metadata_server)

        # Fetch credentials from local config file
        self.access_key = self.conduit.confString(
            'aws', 'access_key', default=None)
        self.secret_key = self.conduit.confString(
            'aws', 'secret_key', default=None)
        self.token = self.conduit.confString('aws', 'token', default=None)
        if self.access_key and self.secret_key:
            return True

        iam_role = get_iam_role()
        if iam_role is None:
            self.conduit.info(3, "[ERROR] No credentials in the plugin conf "
                                 "for the repo '%s'" % self.repoid)
            raise CredentialError

        # Fetch credentials from iam role meta data
        credentials = get_credentials_from_iam_role(iam_role=iam_role)
        if credentials is None:
            self.conduit.info(3, "[ERROR] Fail to get IAM credentials"
                                 "for the repo '%s'" % self.repoid)
            raise CredentialError

        self.access_key, self.secret_key, self.token = credentials
        return True

    def fetch_headers(self, url, path):
        headers = {}
        if self.token is not None:
            headers.update({'x-amz-security-token': self.token})
        date = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
        headers.update({'Date': date})

        # FIXME: need to support "mirrorlist" and multiple baseurls
        url = urlparse.urljoin(url, path)
        signature = self.sign(url, date)
        headers.update({'Authorization':
                        "AWS {0}:{1}".format(self.access_key,
                                             signature)})
        return headers

    def sign(self, url, date):
        """Attach a valid S3 signature to request.
        request - instance of Request
        """
        # TODO: bucket name finding is ugly, I should find a way to support
        # both naming conventions: http://bucket.s3.amazonaws.com/ and
        # http://s3.amazonaws.com/bucket/
        host = urlparse.urlparse(url).netloc
        url = urlparse.urlparse(url).path
        pos = host.find(".s3")
        bucket = host[:pos]

        resource = "/%s%s" % (bucket, url)
        if self.token is not None:
            amz_headers = 'x-amz-security-token:%s\n' % self.token
            sigstring = ("%(method)s\n\n\n%(date)s\n"
                         "%(canon_amzn_headers)s"
                         "%(canon_amzn_resource)s") % ({
                'method': 'GET',
                'date': date,
                'canon_amzn_headers': amz_headers,
                'canon_amzn_resource': resource})
        else:
            sigstring = ("%(method)s\n\n\n%(date)s\n"
                         "%(canon_amzn_resource)s") % ({
                'method': 'GET',
                'date': date,
                'canon_amzn_resource': resource})
        digest = hmac.new(
            str(self.secret_key),
            str(sigstring),
            hashlib.sha1).digest()
        signature = digest.encode('base64')
        return signature

if __name__ == '__main__':
    pass
