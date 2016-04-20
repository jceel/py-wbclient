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
from posix.unistd cimport uid_t, gid_t
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
    def __init__(self, code, message=None):
        if not isinstance(code, WinbindErrorCode):
            raise ValueError('code must be instance of WinbindErrorCode')

        self.message = message
        self.code = code

    def __str__(self):
        return self.code.name


class AuthException(WinbindException):
    pass


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
            with nogil:
                defs.wbcGetInterfaceDetails(&ret.details)

            if ret.details == NULL:
                return None

            return ret

    cdef marshal_user(self, defs.passwd *pwdent):
        cdef User user
        cdef SID sid

        user = User.__new__(User)
        sid = SID.__new__(SID)
        defs.wbcUidToSid(pwdent.pw_uid, &sid.sid)
        user.pwdent = pwdent
        user.context = self
        user.sid = sid
        return user

    cdef marshal_group(self, defs.group *grent):
        cdef Group group
        cdef SID sid

        group = Group.__new__(Group)
        sid = SID.__new__(SID)
        defs.wbcGidToSid(grent.gr_gid, &sid.sid)
        group.grent = grent
        group.context = self
        group.sid = sid
        return group

    def ping_dc(self, domain_name):
        cdef const char *c_domain_name = domain_name
        cdef defs.wbcAuthErrorInfo *error_info = NULL
        cdef char *dcname = NULL
        cdef int err

        with nogil:
            err = defs.wbcCtxPingDc2(self.context, c_domain_name, &error_info, &dcname)

        if err == defs.WBC_ERR_SUCCESS:
            dc_name = dcname
            defs.wbcFreeMemory(dcname)
            return dc_name

        exc = AuthException(WinbindErrorCode(err))
        if error_info != NULL:
            exc.message = error_info.display_string
            exc.nt_string = error_info.nt_string
            exc.nt_status = error_info.nt_status
            exc.pam_error = error_info.pam_error
            defs.wbcFreeMemory(error_info)

        if dcname != NULL:
            exc.dc_name = dcname
            defs.wbcFreeMemory(dcname)

        raise exc

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
        cdef int err

        with nogil:
            defs.wbcCtxSetpwent(self.context)

        while True:
            with nogil:
                err = defs.wbcCtxGetpwent(self.context, &pwdent)

            if err != defs.WBC_ERR_SUCCESS:
                break

            yield self.marshal_user(pwdent)

    def query_groups(self, domain_name):
        cdef Group group
        cdef SID sid
        cdef defs.group *grent

        with nogil:
            defs.wbcCtxSetgrent(self.context)

        while True:
            err = defs.wbcCtxGetgrent(self.context, &grent)
            if err != defs.WBC_ERR_SUCCESS:
                break


            yield self.marshal_group(grent)

    def get_user(self, uid=None, sid=None, name=None):
        cdef User user
        cdef SID usid
        cdef defs.passwd *pwent
        cdef int err
        cdef uid_t c_uid
        cdef const char *c_name = name

        if uid:
            uid = <uid_t>uid
            with nogil:
                err = defs.wbcCtxGetpwuid(self.context, c_uid, &pwent)

        if sid:
            usid = <SID>sid
            with nogil:
                err = defs.wbcCtxGetpwsid(self.context, &usid.sid, &pwent)

        if name:
            with nogil:
                err = defs.wbcCtxGetpwnam(self.context, c_name, &pwent)

        if err != defs.WBC_ERR_SUCCESS:
            raise WinbindException(WinbindErrorCode(err))

        return self.marshal_user(pwent)

    def get_group(self, gid=None, sid=None, name=None):
        cdef User user
        cdef SID gsid
        cdef gid_t ggid
        cdef defs.group *grent
        cdef uid_t c_gid
        cdef const char *c_name = name
        cdef int err

        if gid:
            gid = <uid_t>gid
            with nogil:
                err = defs.wbcCtxGetgrgid(self.context, c_gid, &grent)

        if sid:
            gsid = <SID>sid
            with nogil:
                err = defs.wbcCtxSidToGid(self.context, &gsid.sid, &ggid)

            if err != defs.WBC_ERR_SUCCESS:
                raise WinbindException(WinbindErrorCode(err))

            with nogil:
                err = defs.wbcCtxGetgrgid(self.context, ggid, &grent)

        if name:
            with nogil:
                err = defs.wbcCtxGetgrnam(self.context, c_name, &grent)

        if err != defs.WBC_ERR_SUCCESS:
            raise WinbindException(WinbindErrorCode(err))

        return self.marshal_group(grent)


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
            cdef uint32_t num_sids
            cdef defs.wbcDomainSid *sids
            cdef int err

            with nogil:
                err = defs.wbcCtxLookupUserSids(
                    self.context.context,
                    &self.sid.sid,
                    True,
                    &num_sids,
                    &sids
                )

            if err != defs.WBC_ERR_SUCCESS:
                raise WinbindException(WinbindErrorCode(err))

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
