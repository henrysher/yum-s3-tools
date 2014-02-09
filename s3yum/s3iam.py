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
import ConfigParser
import hashlib
import hmac
import json
import re
import time
import urllib2
import urlparse

import yum.plugins
from yum.yumRepo import YumRepository

CONFIG_PATH = "/etc/s3yum.cfg"

__all__ = ['requires_api_version',
           'plugin_type',
           'init_hook']

requires_api_version = '2.5'
plugin_type = yum.plugins.TYPE_CORE


def _check_s3_urls(urls):
    pattern = "s3.*\.amazonaws\.com"
    if isinstance(urls, basestring):
        if re.compile(pattern).findall(urls) != []:
            return True
    elif isinstance(urls, list):
        for url in urls:
            if re.compile(pattern).findall(url) == []:
                break
        else:
            return True
    return False


def init_hook(conduit):
    """
    Setup the S3 repositories
    """

    repos = conduit.getRepos()
    for key, repo in repos.repos.iteritems():
        if isinstance(repo, YumRepository) and repo.enabled:
            # mirrorlist with no baseurl
            if not repo.baseurl:
                continue
            # non-S3 baseurl
            if not _check_s3_urls(repo.baseurl):
                continue
            new_repo = S3Repository(repo.id, repo.baseurl)
            new_repo.name = repo.name
            new_repo.basecachedir = repo.basecachedir
            new_repo.base_persistdir = repo.base_persistdir
            new_repo.gpgcheck = repo.gpgcheck
            new_repo.proxy = repo.proxy
            new_repo.enablegroups = repo.enablegroups
            repos.delete(key)
            repos.add(new_repo)


class S3Repository(YumRepository):
    """
    Repository object for Amazon S3
    """

    def __init__(self, repoid, baseurl):
        super(S3Repository, self).__init__(repoid)
        self.iamrole = None
        self.token = None
        self.baseurl = baseurl

        # Inherited from YumRepository <-- Repository
        self.enable()
        self.set_credentials()

    def fetch_headers(self, path):
        headers = {}
        if self.token is not None:
            headers.update({'x-amz-security-token': self.token})
        date = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
        headers.update({'Date': date})
        url = urlparse.urljoin(self.baseurl[0], path)
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
        try:
            pos = host.find(".s3")
            assert pos != -1
            bucket = host[:pos]
        except AssertionError:
            raise yum.plugins.PluginYumExit(
                "s3iam: baseurl hostname should be in format: "
                "'<bucket>.s3<aws-region>.amazonaws.com'; "
                "found '%s'" % host)

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

    def set_credentials(self):
        if not self.get_credentials_from_config():
            if not self.get_role():
                raise Exception("Failed to get credentials from" +
                                " IAM Role or config file: %s"
                                % CONFIG_PATH)
            else:
                self.get_credentials_from_iamrole()

    def get_role(self):
        """Read IAM role from AWS metadata store."""
        request = urllib2.Request(
            urlparse.urljoin(
                "http://169.254.169.254",
                "/latest/meta-data/iam/security-credentials/"
            ))

        response = None
        try:
            response = urllib2.urlopen(request)
            self.iamrole = (response.read())
        except Exception as msg:
            if "HTTP Error 404" in msg:
                return False
        finally:
            if response:
                response.close()
                return True

    def get_credentials_from_config(self):
        """Read S3 credentials from local configuration file.
        Note: This method should be explicitly called after constructing new
              object, as in 'explicit is better than implicit'.
        """
        configInfo = {}
        config = ConfigParser.ConfigParser()
        try:
            config.read(CONFIG_PATH)
        except:
            msgerr = "cannot find this file %s" % CONFIG_PATH
            return False, msgerr

        for section in config.sections():
            configInfo[section] = {}

        for section in config.sections():
            for option in config.options(section):
                configInfo[section][option] = config.get(section, option)

        if configInfo:
            try:
                self.access_key = configInfo["Credentials"]["access_key"]
                self.secret_key = configInfo["Credentials"]["secret_key"]
                self.token = None
            finally:
                if self.access_key and self.secret_key:
                    return True
        return False

    def get_credentials_from_iamrole(self):
        """Read IAM credentials from AWS metadata store.
        Note: This method should be explicitly called after constructing new
              object, as in 'explicit is better than implicit'.
        """
        request = urllib2.Request(
            urlparse.urljoin(
                urlparse.urljoin(
                    "http://169.254.169.254/",
                    "latest/meta-data/iam/security-credentials/",
                ), self.iamrole))

        response = None
        try:
            response = urllib2.urlopen(request)
            data = json.loads(response.read())
        finally:
            if response:
                response.close()

        self.access_key = data['AccessKeyId']
        self.secret_key = data['SecretAccessKey']
        self.token = data['Token']

    def _getFile(self, url=None, relative=None, local=None,
                 start=None, end=None,
                 copy_local=None, checkfunc=None, text=None,
                 reget='simple', cache=True, size=None, **kwargs):
        """
        Patched _getFile func via AWS S3 REST API
        """
        self.http_headers = self.fetch_headers(relative)
        return super(S3Repository, self)._getFile(url, relative, local,
                                                  start, end,
                                                  copy_local, checkfunc, text,
                                                  reget, cache, size, **kwargs)
    __get = _getFile

if __name__ == '__main__':
    pass
