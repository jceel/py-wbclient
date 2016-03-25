# cython: c_string_type=unicode, c_string_encoding=ascii
#
# Copyright 2016 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################

import enum
import pwd
import grp
from libc.stdint cimport *
cimport defs


class WinbindErrorCode(enum.IntEnum):
    SUCCESS = defs.WBC_ERR_SUCCESS
    NOT_IMPLEMENTED = defs.WBC_ERR_NOT_IMPLEMENTED
    UNKNOWN_FAILURE = defs.WBC_ERR_UNKNOWN_FAILURE
    NO_MEMORY = defs.WBC_ERR_NO_MEMORY
    INVALID_SID = defs.WBC_ERR_INVALID_SID
    INVALID_PARAM = defs.WBC_ERR_INVALID_PARAM
    WINBIND_NOT_AVAILABLE = defs.WBC_ERR_WINBIND_NOT_AVAILABLE
    DOMAIN_NOT_FOUND = defs.WBC_ERR_DOMAIN_NOT_FOUND
    INVALID_RESPONSE = defs.WBC_ERR_INVALID_RESPONSE
    NSS_ERROR = defs.WBC_ERR_NSS_ERROR
    AUTH_ERROR = defs.WBC_ERR_AUTH_ERROR
    UNKNOWN_USER = defs.WBC_ERR_UNKNOWN_USER
    UNKNOWN_GROUP = defs.WBC_ERR_UNKNOWN_GROUP
    PWD_CHANGE_FAILED = defs.WBC_ERR_PWD_CHANGE_FAILED


class WinbindException(Exception):
    def __init__(self, code):
        if not (isinstance(code, WinbindErrorCode)):
            raise ValueError('code must be instance of WinbindErrorCode')

        self.code = code

    def __str__(self):
        return self.code.name


cdef class Context(object):
    cdef defs.wbcContext *context

    def __init__(self):
        self.context = defs.wbcCtxCreate()

    def __dealloc__(self):
        defs.wbcCtxFree(self.context)

    property interface:
        def __get__(self):
            cdef InterfaceDetails ret

            ret = InterfaceDetails.__new__(InterfaceDetails)
            defs.wbcGetInterfaceDetails(&ret.details)
            return ret

    def ping_dc(self):
        pass

    def list_users(self, domain_name):
        cdef const char **users
        cdef uint32_t num_users

        defs.wbcListUsers(domain_name, &num_users, &users)
        for i in range(0, num_users):
            yield users[i]

        defs.wbcFreeMemory(users)

    def list_groups(self, domain_name):
        cdef const char **groups
        cdef uint32_t num_groups

        defs.wbcListGroups(domain_name, &num_groups, &groups)
        for i in range(0, num_groups):
            yield groups[i]

        defs.wbcFreeMemory(groups)

    def query_users(self, domain_name):
        cdef User user
        cdef SID sid
        cdef defs.passwd *pwdent
        cdef defs.wbcErr err

        defs.wbcCtxSetpwent(self.context)
        while True:
            err = defs.wbcCtxGetpwent(self.context, &pwdent)
            if err != defs.WBC_ERR_SUCCESS:
                break

            user = User.__new__(User)
            sid = SID.__new__(SID)
            defs.wbcUidToSid(pwdent.pw_uid, &sid.sid)
            user.pwdent = pwdent
            user.context = self
            user.sid = sid
            yield user

    def query_groups(self, domain_name):
        cdef Group group
        cdef SID sid
        cdef defs.group *grent
        cdef defs.wbcErr err

        defs.wbcCtxSetgrent(self.context)
        while True:
            err = defs.wbcCtxGetgrent(self.context, &grent)
            if err != defs.WBC_ERR_SUCCESS:
                break

            group = Group.__new__(Group)
            sid = SID.__new__(SID)
            defs.wbcGidToSid(grent.gr_gid, &sid.sid)
            group.grent = grent
            group.context = self
            group.sid = sid
            yield group


cdef class InterfaceDetails(object):
    cdef defs.wbcInterfaceDetails *details

    def __dealloc__(self):
        pass

    property netbios_name:
        def __get__(self):
            return self.details.netbios_name

    property netbios_domain:
        def __get__(self):
            return self.details.netbios_domain

    property dns_domain:
        def __get__(self):
            return self.details.dns_domain


cdef class DomainInfo(object):
    cdef defs.wbcDomainInfo dinfo

    property short_name:
        def __get__(self):
            return self.dinfo.short_name

    property dns_name:
        def __get__(self):
            return self.dinfo.dns_name


cdef class SID(object):
    cdef defs.wbcDomainSid sid

    def __str__(self):
        cdef char sid_str[defs.WBC_SID_STRING_BUFLEN]

        defs.wbcSidToStringBuf(&self.sid, sid_str, defs.WBC_SID_STRING_BUFLEN)
        return sid_str

    def __repr__(self):
        return str(self)


cdef class User(object):
    cdef readonly Context context
    cdef readonly SID sid
    cdef defs.passwd *pwdent

    def __dealloc__(self):
        defs.wbcFreeMemory(self.pwdent)

    def __str__(self):
        return "<wbclient.User name '{0}' sid '{1}'>".format(self.name, str(self.sid))

    def __repr__(self):
        return str(self)

    property name:
        def __get__(self):
            return self.pwdent.pw_name

    property passwd:
        def __get__(self):
            return pwd.struct_passwd((
                self.pwdent.pw_name,
                self.pwdent.pw_passwd,
                self.pwdent.pw_uid,
                self.pwdent.pw_gid,
                self.pwdent.pw_gecos,
                self.pwdent.pw_dir,
                self.pwdent.pw_shell
            ))

    property groups:
        def __get__(self):
            cdef SID sid
            cdef defs.wbcErr err
            cdef uint32_t num_sids
            cdef defs.wbcDomainSid *sids

            err = defs.wbcCtxLookupUserSids(
                self.context.context,
                &self.sid.sid,
                True,
                &num_sids,
                &sids
            )

            if err != defs.WBC_ERR_SUCCESS:
                raise WinbindException(WinbindErrorCode(<int>err))

            for i in range(0, num_sids):
                sid = SID.__new__(SID)
                sid.sid = sids[i]
                yield sid


cdef class Group(object):
    cdef readonly Context context
    cdef readonly SID sid
    cdef defs.group *grent

    def __dealloc__(self):
        defs.wbcFreeMemory(self.grent)

    def __str__(self):
        return "<wbclient.Group name '{0}' sid '{1}'>".format(self.name, str(self.sid))

    def __repr__(self):
        return str(self)

    property name:
        def __get__(self):
            return self.grent.gr_name

    property group:
        def __get__(self):
            return grp.struct_group((
                self.grent.gr_name,
                self.grent.gr_passwd,
                self.grent.gr_gid,
                []
            ))
