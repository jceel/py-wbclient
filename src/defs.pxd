#+
# Copyright 2015 iXsystems, Inc.
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

from libc.stdint cimport *
from posix.unistd cimport uid_t, gid_t, pid_t


cdef extern from "pwd.h":
    cdef struct passwd:
        char    *pw_name
        char    *pw_passwd
        uid_t   pw_uid
        gid_t   pw_gid
        time_t  pw_change
        char    *pw_class
        char    *pw_gecos
        char    *pw_dir
        char    *pw_shell
        time_t  pw_expire
        int     pw_fields


cdef extern from "grp.h":
    cdef struct group:
        char    *gr_name
        char    *gr_passwd
        gid_t   gr_gid
        char    **gr_mem


cdef extern from "wbclient.h":
    cdef struct wbcContext:
        pass

    ctypedef enum wbcErr:
        WBC_ERR_SUCCESS
        WBC_ERR_NOT_IMPLEMENTE
        WBC_ERR_UNKNOWN_FAILURE
        WBC_ERR_NO_MEMORY
        WBC_ERR_INVALID_SID
        WBC_ERR_INVALID_PARAM
        WBC_ERR_WINBIND_NOT_AVAILABLE
        WBC_ERR_DOMAIN_NOT_FOUND
        WBC_ERR_INVALID_RESPONSE
        WBC_ERR_NSS_ERROR
        WBC_ERR_AUTH_ERROR
        WBC_ERR_UNKNOWN_USE
        WBC_ERR_UNKNOWN_GROUP,
        WBC_ERR_PWD_CHANGE_FAILED

    const char *wbcErrorString(wbcErr error)

    enum:
        WBCLIENT_MAJOR_VERSION
        WBCLIENT_MINOR_VERSION
        WBCLIENT_VENDOR_VERSION

    cdef struct wbcLibraryDetails:
        uint16_t major_version
        uint16_t minor_version
        const char *vendor_version

    cdef struct wbcInterfaceDetails:
        uint32_t interface_version
        char *winbind_version
        char winbind_separator
        char *netbios_name
        char *netbios_domain
        char *dns_domain

    enum:
        WBC_MAXSUBAUTHS

    cdef struct wbcDomainSid:
        uint8_t   sid_rev_num
        uint8_t   num_auths
        uint8_t   id_auth[6]
        uint32_t  sub_auths[WBC_MAXSUBAUTHS]

    enum wbcSidType:
        WBC_SID_NAME_USE_NONE
        WBC_SID_NAME_USER
        WBC_SID_NAME_DOM_GRP
        WBC_SID_NAME_DOMAIN
        WBC_SID_NAME_ALIAS
        WBC_SID_NAME_WKN_GRP
        WBC_SID_NAME_DELETED
        WBC_SID_NAME_INVALID
        WBC_SID_NAME_UNKNOWN
        WBC_SID_NAME_COMPUTER

    cdef struct wbcSidWithAttr:
        wbcDomainSid sid
        uint32_t attributes

    enum:
        WBC_SID_ATTR_GROUP_MANDATORY
        WBC_SID_ATTR_GROUP_ENABLED_BY_DEFAULT
        WBC_SID_ATTR_GROUP_ENABLED
        WBC_SID_ATTR_GROUP_OWNER
        WBC_SID_ATTR_GROUP_USEFOR_DENY_ONLY
        WBC_SID_ATTR_GROUP_RESOURCE
        WBC_SID_ATTR_GROUP_LOGON_ID

    cdef struct wbcGuid:
        uint32_t time_low
        uint16_t time_mid
        uint16_t time_hi_and_version
        uint8_t clock_seq[2]
        uint8_t node[6]


    cdef struct wbcDomainInfo:
        char *short_name
        char *dns_name
        wbcDomainSid sid
        uint32_t domain_flags
        uint32_t trust_flags
        uint32_t trust_type

    enum:
        WBC_DOMINFO_DOMAIN_UNKNOWN
        WBC_DOMINFO_DOMAIN_NATIVE
        WBC_DOMINFO_DOMAIN_AD
        WBC_DOMINFO_DOMAIN_PRIMARY
        WBC_DOMINFO_DOMAIN_OFFLINE
        WBC_DOMINFO_TRUST_TRANSITIVE
        WBC_DOMINFO_TRUST_INCOMING
        WBC_DOMINFO_TRUST_OUTGOING
        WBC_DOMINFO_TRUSTTYPE_NONE
        WBC_DOMINFO_TRUSTTYPE_FOREST
        WBC_DOMINFO_TRUSTTYPE_IN_FOREST
        WBC_DOMINFO_TRUSTTYPE_EXTERNAL

    cdef struct wbcBlob:
        uint8_t *data
        size_t length

    cdef struct wbcNamedBlob:
        const char *name
        uint32_t flags
        wbcBlob blob

    cdef struct wbcAuthUserParams:
        const char *account_name
        const char *domain_name
        const char *workstation_name
        uint32_t flags
        uint32_t parameter_control
        wbcAuthUserLevel level

    cdef struct wbcLogonUserParams:
        const char *username
        const char *password
        size_t num_blobs
        wbcNamedBlob *blobs

    enum wbcAuthUserLevel:
		WBC_AUTH_USER_LEVEL_PLAIN
		WBC_AUTH_USER_LEVEL_HASH
		WBC_AUTH_USER_LEVEL_RESPONSE
		WBC_AUTH_USER_LEVEL_PAC

    enum wbcChangePasswordLevel:
        WBC_CHANGE_PASSWORD_LEVEL_PLAIN
        WBC_CHANGE_PASSWORD_LEVEL_RESPONSE

    enum:
        WBC_MSV1_0_CLEARTEXT_PASSWORD_ALLOWED
        WBC_MSV1_0_UPDATE_LOGON_STATISTICS
        WBC_MSV1_0_RETURN_USER_PARAMETERS
        WBC_MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT
        WBC_MSV1_0_RETURN_PROFILE_PATH
        WBC_MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT
        WBC_AUTH_PARAM_FLAGS_INTERACTIVE_LOGON

    cdef struct wbcAuthUserInfo:
        uint32_t user_flags

        char *account_name
        char *user_principal
        char *full_name
        char *domain_name
        char *dns_domain_name

        uint32_t acct_flags
        uint8_t user_session_key[16]
        uint8_t lm_session_key[8]

        uint16_t logon_count
        uint16_t bad_password_count

        uint64_t logon_time
        uint64_t logoff_time
        uint64_t kickoff_time
        uint64_t pass_last_set_time
        uint64_t pass_can_change_time
        uint64_t pass_must_change_time

        char *logon_server
        char *logon_script
        char *profile_path
        char *home_directory
        char *home_drive

        uint32_t num_sids
        wbcSidWithAttr *sids

    cdef struct wbcLogonUserInfo:
        wbcAuthUserInfo *info
        size_t num_blobs
        wbcNamedBlob *blobs

    enum:
        WBC_AUTH_USER_INFO_GUEST
        WBC_AUTH_USER_INFO_NOENCRYPTION
        WBC_AUTH_USER_INFO_CACHED_ACCOUNT
        WBC_AUTH_USER_INFO_USED_LM_PASSWORD
        WBC_AUTH_USER_INFO_EXTRA_SIDS
        WBC_AUTH_USER_INFO_SUBAUTH_SESSION_KEY
        WBC_AUTH_USER_INFO_SERVER_TRUST_ACCOUNT
        WBC_AUTH_USER_INFO_NTLMV2_ENABLED
        WBC_AUTH_USER_INFO_RESOURCE_GROUPS
        WBC_AUTH_USER_INFO_PROFILE_PATH_RETURNED
        WBC_AUTH_USER_INFO_GRACE_LOGON

    enum:
        WBC_ACB_DISABLED
        WBC_ACB_HOMDIRREQ
        WBC_ACB_PWNOTREQ
        WBC_ACB_TEMPDUP
        WBC_ACB_NORMAL
        WBC_ACB_MNS
        WBC_ACB_DOMTRUST
        WBC_ACB_WSTRUST
        WBC_ACB_SVRTRUST
        WBC_ACB_PWNOEXP
        WBC_ACB_AUTOLOCK
        WBC_ACB_ENC_TXT_PWD_ALLOWED
        WBC_ACB_SMARTCARD_REQUIRED
        WBC_ACB_TRUSTED_FOR_DELEGATION
        WBC_ACB_NOT_DELEGATED
        WBC_ACB_USE_DES_KEY_ONLY
        WBC_ACB_DONT_REQUIRE_PREAUTH
        WBC_ACB_PW_EXPIRED
        WBC_ACB_NO_AUTH_DATA_REQD

    cdef struct wbcAuthErrorInfo:
        uint32_t nt_status
        char *nt_string
        int32_t pam_error
        char *display_string

    enum:
        WBC_DOMAIN_PASSWORD_COMPLEX
        WBC_DOMAIN_PASSWORD_NO_ANON_CHANGE
        WBC_DOMAIN_PASSWORD_NO_CLEAR_CHANGE
        WBC_DOMAIN_PASSWORD_LOCKOUT_ADMINS
        WBC_DOMAIN_PASSWORD_STORE_CLEARTEXT
        WBC_DOMAIN_REFUSE_PASSWORD_CHANGE

    cdef struct wbcUserPasswordPolicyInfo:
        uint32_t min_length_password
        uint32_t password_history
        uint32_t password_properties
        uint64_t expire
        uint64_t min_passwordage

    enum wbcPasswordChangeRejectReason:
        WBC_PWD_CHANGE_NO_ERROR
        WBC_PWD_CHANGE_PASSWORD_TOO_SHORT
        WBC_PWD_CHANGE_PWD_IN_HISTORY
        WBC_PWD_CHANGE_USERNAME_IN_PASSWORD
        WBC_PWD_CHANGE_FULLNAME_IN_PASSWORD
        WBC_PWD_CHANGE_NOT_COMPLEX
        WBC_PWD_CHANGE_MACHINE_NOT_DEFAULT
        WBC_PWD_CHANGE_FAILED_BY_FILTER
        WBC_PWD_CHANGE_PASSWORD_TOO_LONG

    enum:
        WBC_PWD_CHANGE_REJECT_OTHER
        WBC_PWD_CHANGE_REJECT_TOO_SHORT
        WBC_PWD_CHANGE_REJECT_IN_HISTORY
        WBC_PWD_CHANGE_REJECT_COMPLEXITY

    cdef struct wbcLogoffUserParams:
        const char *username
        size_t num_blobs
        wbcNamedBlob *blobs

    enum wbcCredentialCacheLevel:
        WBC_CREDENTIAL_CACHE_LEVEL_NTLMSSP

    cdef struct wbcCredentialCacheParams:
            const char *account_name
            const char *domain_name

            wbcCredentialCacheLevel level
            size_t num_blobs
            wbcNamedBlob *blobs

    cdef struct wbcCredentialCacheInfo:
        size_t num_blobs
        wbcNamedBlob *blobs

    cdef struct wbcDomainControllerInfo:
        char *dc_name

    cdef struct wbcDomainControllerInfoEx:
        const char *dc_unc
        const char *dc_address
        uint16_t dc_address_type
        wbcGuid *domain_guid
        const char *domain_name
        const char *forest_name
        uint32_t dc_flags
        const char *dc_site_name
        const char *client_site_name

    void wbcFreeMemory(void*)
    wbcContext *wbcCtxCreate(void)
    void wbcCtxFree(wbcContext *ctx)
    const char* wbcSidTypeString(wbcSidType type)
    int wbcSidToStringBuf(const wbcDomainSid *sid, char *buf, int buflen)
    wbcErr wbcSidToString(const wbcDomainSid *sid, char **sid_string)
    wbcErr wbcStringToSid(const char *sid_string, wbcDomainSid *sid)
    wbcErr wbcGuidToString(const wbcGuid *guid, char **guid_string)
    wbcErr wbcStringToGuid(const char *guid_string, wbcGuid *guid)
    wbcErr wbcCtxPing(wbcContext *ctx)
    wbcErr wbcPing(void)
    wbcErr wbcLibraryDetails(wbcLibraryDetails **details)
    wbcErr wbcCtxInterfaceDetails(wbcContext *ctx, wbcInterfaceDetails **details)
    wbcErr wbcInterfaceDetails(wbcInterfaceDetails **details)
    wbcErr wbcCtxLookupName(wbcContext *ctx, const char *dom_name, const char *name, wbcDomainSid *sid, wbcSidType *name_type)
    wbcErr wbcLookupName(const char *dom_name,
                 const char *name,
                 wbcDomainSid *sid,
                 wbcSidType *name_type)

    wbcErr wbcCtxLookupSid(wbcContext *ctx, const wbcDomainSid *sid, char **domain, char **name, wbcSidType *name_type)

    wbcErr wbcLookupSid(const wbcDomainSid *sid,
                char **domain,
                char **name,
                wbcSidType *name_type)

    cdef struct wbcTranslatedName:
        wbcSidType type
        char *name
        int domain_index

    wbcErr wbcCtxLookupSids(wbcContext *ctx,
                const wbcDomainSid *sids, int num_sids,
                wbcDomainInfo **domains, int *num_domains,
                wbcTranslatedName **names)

    wbcErr wbcLookupSids(const wbcDomainSid *sids, int num_sids,
                 wbcDomainInfo **domains, int *num_domains,
                 wbcTranslatedName **names)

    wbcErr wbcCtxLookupRids(wbcContext *ctx,
                wbcDomainSid *dom_sid,
                int num_rids,
                uint32_t *rids,
                const char **domain_name,
                const char ***names,
                wbcSidType **types)

    wbcErr wbcLookupRids(wbcDomainSid *dom_sid,
                 int num_rids,
                 uint32_t *rids,
                 const char **domain_name,
                 const char ***names,
                 wbcSidType **types)


    wbcErr wbcCtxLookupUserSids(wbcContext *ctx,
                    const wbcDomainSid *user_sid,
                    bool domain_groups_only,
                    uint32_t *num_sids,
                    wbcDomainSid **sids)


    wbcErr wbcLookupUserSids(const wbcDomainSid *user_sid,
                 bool domain_groups_only,
                 uint32_t *num_sids,
                 wbcDomainSid **sids)


    wbcErr wbcCtxGetSidAliases(wbcContext *ctx,
                   const wbcDomainSid *dom_sid,
                   wbcDomainSid *sids,
                   uint32_t num_sids,
                   uint32_t **alias_rids,
                   uint32_t *num_alias_rids)

    wbcErr wbcGetSidAliases(const wbcDomainSid *dom_sid,
                wbcDomainSid *sids,
                uint32_t num_sids,
                uint32_t **alias_rids,
                uint32_t *num_alias_rids)

    wbcErr wbcCtxListUsers(wbcContext *ctx,
                   const char *domain_name,
                   uint32_t *num_users,
                   const char ***users)

    wbcErr wbcListUsers(const char *domain_name,
                uint32_t *num_users,
                const char ***users)

    wbcErr wbcCtxListGroups(wbcContext *ctx,
                const char *domain_name,
                uint32_t *num_groups,
                const char ***groups)

    wbcErr wbcListGroups(const char *domain_name,
                 uint32_t *num_groups,
                 const char ***groups)

    wbcErr wbcCtxGetDisplayName(wbcContext *ctx,
                    const wbcDomainSid *sid,
                    char **pdomain,
                    char **pfullname,
                    wbcSidType *pname_type)

    wbcErr wbcGetDisplayName(const wbcDomainSid *sid,
                 char **pdomain,
                 char **pfullname,
                 wbcSidType *pname_type)

    wbcErr wbcCtxSidToUid(wbcContext *ctx,
                  const wbcDomainSid *sid,
                  uid_t *puid)

    wbcErr wbcSidToUid(const wbcDomainSid *sid,
               uid_t *puid)

    wbcErr wbcQuerySidToUid(const wbcDomainSid *sid,
                uid_t *puid)

    wbcErr wbcCtxUidToSid(wbcContext *ctx, uid_t uid,
                  wbcDomainSid *sid)

    wbcErr wbcUidToSid(uid_t uid,
               wbcDomainSid *sid)

    wbcErr wbcQueryUidToSid(uid_t uid,
                wbcDomainSid *sid)

    wbcErr wbcCtxSidToGid(wbcContext *ctx,
                  const wbcDomainSid *sid,
                  gid_t *pgid)

    wbcErr wbcSidToGid(const wbcDomainSid *sid,
               gid_t *pgid)

    wbcErr wbcQuerySidToGid(const wbcDomainSid *sid,
                gid_t *pgid)

    wbcErr wbcCtxGidToSid(wbcContext *ctx, gid_t gid,
               wbcDomainSid *sid)

    wbcErr wbcGidToSid(gid_t gid,
               wbcDomainSid *sid)

    wbcErr wbcQueryGidToSid(gid_t gid,
                wbcDomainSid *sid)

    enum wbcIdType:
        WBC_ID_TYPE_NOT_SPECIFIED
        WBC_ID_TYPE_UID
        WBC_ID_TYPE_GID
        WBC_ID_TYPE_BOTH

    cdef union wbcUnixIdContainer:
        uid_t uid
        gid_t gid

    cdef struct wbcUnixId:
        wbcIdType type
        wbcUnixIdContainer id

    wbcErr wbcCtxSidsToUnixIds(wbcContext *ctx,
                   const wbcDomainSid *sids, uint32_t num_sids,
                   wbcUnixId *ids)

    wbcErr wbcSidsToUnixIds(const wbcDomainSid *sids, uint32_t num_sids,
                wbcUnixId *ids)

    wbcErr wbcCtxAllocateUid(wbcContext *ctx, uid_t *puid)

    wbcErr wbcAllocateUid(uid_t *puid)

    wbcErr wbcCtxAllocateGid(wbcContext *ctx, gid_t *pgid)

    wbcErr wbcAllocateGid(gid_t *pgid)

    wbcErr wbcSetUidMapping(uid_t uid, const wbcDomainSid *sid)

    wbcErr wbcSetGidMapping(gid_t gid, const wbcDomainSid *sid)

    wbcErr wbcRemoveUidMapping(uid_t uid, const wbcDomainSid *sid)

    wbcErr wbcRemoveGidMapping(gid_t gid, const wbcDomainSid *sid)

    wbcErr wbcSetUidHwm(uid_t uid_hwm)

    wbcErr wbcSetGidHwm(gid_t gid_hwm)

    wbcErr wbcCtxGetpwnam(wbcContext *ctx,
                  const char *name, passwd **pwd)

    wbcErr wbcGetpwnam(const char *name, passwd **pwd)

    wbcErr wbcCtxGetpwuid(wbcContext *ctx,
                  uid_t uid, passwd **pwd)

    wbcErr wbcGetpwuid(uid_t uid, passwd **pwd)

    wbcErr wbcCtxGetpwsid(wbcContext *ctx,
                  wbcDomainSid * sid, passwd **pwd)

    wbcErr wbcGetpwsid(wbcDomainSid * sid, passwd **pwd)

    wbcErr wbcCtxGetgrnam(wbcContext *ctx,
                  const char *name, group **grp)

    wbcErr wbcGetgrnam(const char *name, group **grp)

    wbcErr wbcCtxGetgrgid(wbcContext *ctx,
                  gid_t gid, group **grp)

    wbcErr wbcGetgrgid(gid_t gid, group **grp)

    wbcErr wbcCtxSetpwent(wbcContext *ctx)

    wbcErr wbcSetpwent(void)

    wbcErr wbcCtxEndpwent(wbcContext *ctx)

    wbcErr wbcEndpwent(void)

    wbcErr wbcCtxGetpwent(wbcContext *ctx, passwd **pwd)

    wbcErr wbcGetpwent(passwd **pwd)

    wbcErr wbcCtxSetgrent(wbcContext *ctx)

    wbcErr wbcSetgrent(void)

    wbcErr wbcCtxEndgrent(wbcContext *ctx)

    wbcErr wbcEndgrent(void)

    wbcErr wbcCtxGetgrent(wbcContext *ctx, group **grp)

    wbcErr wbcGetgrent(group **grp)

    wbcErr wbcCtxGetgrlist(wbcContext *ctx, group **grp)

    wbcErr wbcGetgrlist(group **grp)

    wbcErr wbcCtxGetGroups(wbcContext *ctx,
                   const char *account,
                   uint32_t *num_groups,
                   gid_t **_groups)

    wbcErr wbcGetGroups(const char *account,
                uint32_t *num_groups,
                gid_t **_groups)

    wbcErr wbcCtxDomainInfo(wbcContext *ctx,
                const char *domain,
                wbcDomainInfo **dinfo)

    wbcErr wbcDomainInfo(const char *domain,
                 wbcDomainInfo **dinfo)

    wbcErr wbcCtxDcInfo(wbcContext *ctx,
                const char *domain, size_t *num_dcs,
                const char ***dc_names, const char ***dc_ips)

    wbcErr wbcDcInfo(const char *domain, size_t *num_dcs,
             const char ***dc_names, const char ***dc_ips)

    wbcErr wbcCtxListTrusts(wbcContext *ctx,
                wbcDomainInfo **domains,
                size_t *num_domains)

    wbcErr wbcListTrusts(wbcDomainInfo **domains,
                 size_t *num_domains)

    enum:
        WBC_LOOKUP_DC_FORCE_REDISCOVERY
        WBC_LOOKUP_DC_DS_REQUIRED
        WBC_LOOKUP_DC_DS_PREFERRED
        WBC_LOOKUP_DC_GC_SERVER_REQUIRED
        WBC_LOOKUP_DC_PDC_REQUIRED
        WBC_LOOKUP_DC_BACKGROUND_ONLY
        WBC_LOOKUP_DC_IP_REQUIRED
        WBC_LOOKUP_DC_KDC_REQUIRED
        WBC_LOOKUP_DC_TIMESERV_REQUIRED
        WBC_LOOKUP_DC_WRITABLE_REQUIRED
        WBC_LOOKUP_DC_GOOD_TIMESERV_PREFERRED
        WBC_LOOKUP_DC_AVOID_SELF
        WBC_LOOKUP_DC_ONLY_LDAP_NEEDED
        WBC_LOOKUP_DC_IS_FLAT_NAME
        WBC_LOOKUP_DC_IS_DNS_NAME
        WBC_LOOKUP_DC_TRY_NEXTCLOSEST_SITE
        WBC_LOOKUP_DC_DS_6_REQUIRED
        WBC_LOOKUP_DC_RETURN_DNS_NAME
        WBC_LOOKUP_DC_RETURN_FLAT_NAME

    wbcErr wbcCtxLookupDomainController(wbcContext *ctx,
                        const char *domain,
                        uint32_t flags,
                        wbcDomainControllerInfo **dc_info)

    wbcErr wbcLookupDomainController(const char *domain,
                     uint32_t flags,
                     wbcDomainControllerInfo **dc_info)

    wbcErr wbcCtxLookupDomainControllerEx(wbcContext *ctx,
                          const char *domain,
                          wbcGuid *guid,
                          const char *site,
                          uint32_t flags,
                          wbcDomainControllerInfoEx **dc_info)

    wbcErr wbcLookupDomainControllerEx(const char *domain,
                       wbcGuid *guid,
                       const char *site,
                       uint32_t flags,
                       wbcDomainControllerInfoEx **dc_info)

    wbcErr wbcCtxAuthenticateUser(wbcContext *ctx,
                      const char *username,
                      const char *password)

    wbcErr wbcAuthenticateUser(const char *username,
                   const char *password)

    wbcErr wbcCtxAuthenticateUserEx(wbcContext *ctx,
                    const wbcAuthUserParams *params,
                    wbcAuthUserInfo **info,
                    wbcAuthErrorInfo **error)

    wbcErr wbcAuthenticateUserEx(const wbcAuthUserParams *params,
                     wbcAuthUserInfo **info,
                     wbcAuthErrorInfo **error)

    wbcErr wbcCtxLogonUser(wbcContext *ctx,
                   const wbcLogonUserParams *params,
                   wbcLogonUserInfo **info,
                   wbcAuthErrorInfo **error,
                   wbcUserPasswordPolicyInfo **policy)

    wbcErr wbcLogonUser(const wbcLogonUserParams *params,
                wbcLogonUserInfo **info,
                wbcAuthErrorInfo **error,
                wbcUserPasswordPolicyInfo **policy)

    wbcErr wbcCtxLogoffUser(wbcContext *ctx,
                const char *username, uid_t uid,
                const char *ccfilename)

    wbcErr wbcLogoffUser(const char *username,
                 uid_t uid,
                 const char *ccfilename)

    wbcErr wbcCtxLogoffUserEx(wbcContext *ctx,
                  const wbcLogoffUserParams *params,
                      wbcAuthErrorInfo **error)

    wbcErr wbcLogoffUserEx(const wbcLogoffUserParams *params,
                   wbcAuthErrorInfo **error)

    wbcErr wbcCtxChangeUserPassword(wbcContext *ctx,
                    const char *username,
                    const char *old_password,
                    const char *new_password)

    wbcErr wbcChangeUserPassword(const char *username,
                     const char *old_password,
                     const char *new_password)

    wbcErr wbcCtxChangeUserPasswordEx(wbcContext *ctx,
                      const wbcChangePasswordParams *params,
                      wbcAuthErrorInfo **error,
                      wbcPasswordChangeRejectReason *reject_reason,
                      wbcUserPasswordPolicyInfo **policy)

    wbcErr wbcChangeUserPasswordEx(const wbcChangePasswordParams *params,
                       wbcAuthErrorInfo **error,
                       wbcPasswordChangeRejectReason *reject_reason,
                       wbcUserPasswordPolicyInfo **policy)

    wbcErr wbcCtxCredentialCache(wbcContext *ctx,
                     wbcCredentialCacheParams *params,
                                 wbcCredentialCacheInfo **info,
                                 wbcAuthErrorInfo **error)

    wbcErr wbcCredentialCache(wbcCredentialCacheParams *params,
                              wbcCredentialCacheInfo **info,
                              wbcAuthErrorInfo **error)

    wbcErr wbcCtxCredentialSave(wbcContext *ctx,
                    const char *user, const char *password)

    wbcErr wbcCredentialSave(const char *user, const char *password)

    wbcErr wbcCtxResolveWinsByName(wbcContext *ctx,
                       const char *name, char **ip)

    wbcErr wbcResolveWinsByName(const char *name, char **ip)

    wbcErr wbcCtxResolveWinsByIP(wbcContext *ctx,
                     const char *ip, char **name)

    wbcErr wbcResolveWinsByIP(const char *ip, char **name)

    wbcErr wbcCtxCheckTrustCredentials(wbcContext *ctx, const char *domain,
                       wbcAuthErrorInfo **error)

    wbcErr wbcCheckTrustCredentials(const char *domain,
                    wbcAuthErrorInfo **error)

    wbcErr wbcCtxChangeTrustCredentials(wbcContext *ctx, const char *domain,
                        wbcAuthErrorInfo **error)

    wbcErr wbcChangeTrustCredentials(const char *domain,
                     wbcAuthErrorInfo **error)

    wbcErr wbcCtxPingDc(wbcContext *ctx, const char *domain,
                wbcAuthErrorInfo **error)

    wbcErr wbcPingDc(const char *domain, wbcAuthErrorInfo **error)

    wbcErr wbcCtxPingDc2(wbcContext *ctx, const char *domain,
                 wbcAuthErrorInfo **error,
                 char **dcname)

    wbcErr wbcPingDc2(const char *domain, wbcAuthErrorInfo **error,
              char **dcname)

    wbcErr wbcAddNamedBlob(size_t *num_blobs,
                   wbcNamedBlob **blobs,
                   const char *name,
                   uint32_t flags,
                   uint8_t *data,
                   size_t length)
