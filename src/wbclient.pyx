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
import cython
from libc.stdint cimport *
from libc.string cimport memcpy
cimport defs


cdef class Context(object):
    cdef defs.wbcContext *context

    def __init__(self):
        self.context = defs.wbcCtxCreate()

    property interface:
        def __get__(self):
            cdef InterfaceDetails ret

            ret = InterfaceDetails.__new__(InterfaceDetails)
            defs.wbcGetInterfaceDetails(&ret.details)
            return ret

    def list_users(self, domain_name):
        cdef const char **users
        cdef uint32_t num_users

        defs.wbcListUsers(domain_name, &num_users, &users)
        for i in range(0, num_users):
            yield users[i]


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
