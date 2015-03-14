/* ============================================================
 * Copyright (c) 2010, Ricardo Iván Vieitez Parra
 * Copyright (c) 2003-2004, Ondrej Sury
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */
/* Parts of this are (c) 2010, Ricardo I. Vieitez Parra. The original file was
modified. This is based on mod_vhost_ldap. Modifications integrate it with
mod_suphp (also modified), improve the code in several ways (e.g., protection
against unalocated memory use (as when malloc returns NULL)), adds support
to transfer limit per customer, etc.

* Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/*
 * mod_dynhost_limit.c --- read virtual host config from LDAP directory
 */

#define CORE_PRIVATE

#include <unistd.h>

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "apr_version.h"
#include "apr_ldap.h"
#include "apr_strings.h"
#include "apr_reslist.h"
#include "util_ldap.h"

#if !defined(APU_HAS_LDAP) && !defined(APR_HAS_LDAP)
#error mod_dynhost_limit requires APR-util to have LDAP support built in
#endif

#if !defined(WIN32) && !defined(OS2) && !defined(BEOS) && !defined(NETWARE)
#define HAVE_UNIX_SUEXEC
#endif

#ifdef HAVE_UNIX_SUEXEC
#include "unixd.h"              /* Contains the suexec_identity hook used on Unix */
#endif

#if defined(CGI) & !defined(CGI_PATH)
#define CGI_PATH "cgi-bin"
#endif

#define MIN_UID 997
#define MIN_GID 997

#define VERSION "1.1"
#define MOD_NAME "mod_dynhost_limit"

/* Module version to report */
#ifndef REPORTMOD
#define REPORTMOD MOD_NAME "/" VERSION
#endif

/* userHome base path. Mostly for security reasons. Every userHome should be set relative to this.
E.g., userHome "example" will be translated to "/home/example" if this is set to "/home/"
Points after and before a slash in paths _will_ be filtered out. Any non-ASCII character will be removed, too. */
#ifndef VHOST_BPATH
#define VHOST_BPATH "/home"
#endif

/* path in which Apache docs are saved within a user accound. E.g., public_html, wwwroot, htdocs */
#ifndef VHOST_DOCROOT
#define VHOST_DOCROOT "/htdocs"
#endif

/* path in which scripts will be found. E.g., cgi-bin, cgi, VHOST_DOCROOT/cgi-bin */
#ifndef VHOST_SCRIPTALIAS
#define VHOST_SCRIPTALIAS VHOST_DOCROOT"/cgi-bin"
#endif

/* path in which logs will be stored. E.g., logs, access,  */
#ifndef VHOST_LOGS
#define VHOST_LOGS "/logs"
#endif

/* path in which subdomains are placed (inside base path) */
#ifndef SUBDOMAIN_PATH
#define SUBDOMAIN_PATH "/sub"
#endif

#ifndef DEFAULT_OBJECTCLASS
#define DEFAULT_OBJECTCLASS "vhostConfig"
#endif

#ifdef SUPHP_USELESS_CODE
APR_DECLARE_OPTIONAL_FN(void, suphp_user_group_external, (request_rec*, const char*, const char*));
static int mod_dynhost_limit_get_suphp_id_doer(request_rec*);
#endif

module AP_MODULE_DECLARE_DATA vhost_ldap_module;

typedef enum {
    MVL_UNSET, MVL_DISABLED, MVL_ENABLED
} mod_dynhost_limit_status_e;

typedef struct mod_dynhost_limit_config_t {
    mod_dynhost_limit_status_e enabled;			/* Is vhost_ldap enabled? */

    /* These parameters are all derived from the VhostLDAPURL directive */
    char *url;				/* String representation of LDAP URL */

    char *host;				/* Name of the LDAP server (or space separated list) */
    int port;				/* Port of the LDAP server */
    char *basedn;			/* Base DN to do all searches from */
    int scope;				/* Scope of the search */
    char *filter;			/* Filter to further limit the search  */
    deref_options deref;		/* how to handle alias dereferening */

    char *binddn;			/* DN to bind to server (can be NULL) */
    char *bindpw;			/* Password to bind to server (can be NULL) */

    int have_deref;                     /* Set if we have found an Deref option */
    int have_ldap_url;			/* Set if we have found an LDAP url */

    int secure;				/* True if SSL connections are requested */

    char *fallback;                     /* Fallback virtual host */

} mod_dynhost_limit_config_t;

typedef struct mod_dynhost_limit_request_t {
    char *dn;				/* The saved dn from a successful search */
    char *name;				/* ServerName. */
    char *admin;			/* ServerAdmin */
    char *basepath;			/* Base path (user home) to set DocumentRoot, ScriptAlias, Log Path, etc. */
    char *uid;				/* Suexec, suphp, etc Uid */
    char *gid;				/* Suexec, suphp, etc Gid */
    char *transferlimit;		/* Monthly transfer limit for virtualhost, in MiB (Mebibytes) */
} mod_dynhost_limit_request_t;

char *attributes[] =
  { "vhostServerName", "vhostServerAlias", "apacheServerAdmin", "userHome", "vhostUID", "vhostGID", "apacheTransfLimit", "vhostSubDomain", 0 };

/* Please note that userHome should be relative to /home, or whatever VHOST_BPATH is set to */

#if (APR_MAJOR_VERSION >= 1)
static APR_OPTIONAL_FN_TYPE(uldap_connection_close) *util_ldap_connection_close;
static APR_OPTIONAL_FN_TYPE(uldap_connection_find) *util_ldap_connection_find;
static APR_OPTIONAL_FN_TYPE(uldap_cache_comparedn) *util_ldap_cache_comparedn;
static APR_OPTIONAL_FN_TYPE(uldap_cache_compare) *util_ldap_cache_compare;
static APR_OPTIONAL_FN_TYPE(uldap_cache_checkuserid) *util_ldap_cache_checkuserid;
static APR_OPTIONAL_FN_TYPE(uldap_cache_getuserdn) *util_ldap_cache_getuserdn;
static APR_OPTIONAL_FN_TYPE(uldap_ssl_supported) *util_ldap_ssl_supported;

static void ImportULDAPOptFn(void)
{
    util_ldap_connection_close  = APR_RETRIEVE_OPTIONAL_FN(uldap_connection_close);
    util_ldap_connection_find   = APR_RETRIEVE_OPTIONAL_FN(uldap_connection_find);
    util_ldap_cache_comparedn   = APR_RETRIEVE_OPTIONAL_FN(uldap_cache_comparedn);
    util_ldap_cache_compare     = APR_RETRIEVE_OPTIONAL_FN(uldap_cache_compare);
    util_ldap_cache_checkuserid = APR_RETRIEVE_OPTIONAL_FN(uldap_cache_checkuserid);
    util_ldap_cache_getuserdn   = APR_RETRIEVE_OPTIONAL_FN(uldap_cache_getuserdn);
    util_ldap_ssl_supported     = APR_RETRIEVE_OPTIONAL_FN(uldap_ssl_supported);
}
#endif 

static int mod_dynhost_limit_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    /* make sure that mod_ldap (util_ldap) is loaded */
    if (ap_find_linked_module("util_ldap.c") == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, s,
                     "Module mod_ldap missing. Mod_ldap (aka. util_ldap) "
                     "must be loaded in order for mod_dynhost_limit to function properly");
        return HTTP_INTERNAL_SERVER_ERROR;

    }

    ap_add_version_component(p, REPORTMOD);

    return OK;
}

static void *
mod_dynhost_limit_create_server_config (apr_pool_t *p, server_rec *s)
{
    mod_dynhost_limit_config_t *conf =
	(mod_dynhost_limit_config_t *)apr_palloc(p, sizeof (mod_dynhost_limit_config_t));
    if (conf) {
	memset(conf, 0, sizeof(mod_dynhost_limit_config_t));

	conf->enabled = MVL_UNSET;
	conf->have_ldap_url = 0;
	conf->have_deref = 0;
	conf->binddn = NULL;
	conf->bindpw = NULL;
	conf->deref = always;
	conf->fallback = NULL;
    }
    return conf;
}

static void *
mod_dynhost_limit_merge_server_config(apr_pool_t *p, void *parentv, void *childv)
{
    mod_dynhost_limit_config_t *parent = (mod_dynhost_limit_config_t *) parentv;
    mod_dynhost_limit_config_t *child  = (mod_dynhost_limit_config_t *) childv;
    mod_dynhost_limit_config_t *conf =
	(mod_dynhost_limit_config_t *)apr_palloc(p, sizeof(mod_dynhost_limit_config_t));
    if (conf == NULL) return child;
    memset(conf, 0, sizeof(mod_dynhost_limit_config_t));

    if (child->enabled == MVL_UNSET) {
	conf->enabled = parent->enabled;
    } else {
	conf->enabled = child->enabled;
    }

    if (child->have_ldap_url) {
	conf->have_ldap_url = child->have_ldap_url;
	conf->url = child->url;
	conf->host = child->host;
	conf->port = child->port;
	conf->basedn = child->basedn;
	conf->scope = child->scope;
	conf->filter = child->filter;
	conf->secure = child->secure;
    } else {
	conf->have_ldap_url = parent->have_ldap_url;
	conf->url = parent->url;
	conf->host = parent->host;
	conf->port = parent->port;
	conf->basedn = parent->basedn;
	conf->scope = parent->scope;
	conf->filter = parent->filter;
	conf->secure = parent->secure;
    }
    if (child->have_deref) {
	conf->have_deref = child->have_deref;
	conf->deref = child->deref;
    } else {
	conf->have_deref = parent->have_deref;
	conf->deref = parent->deref;
    }

    conf->binddn = (child->binddn ? child->binddn : parent->binddn);
    conf->bindpw = (child->bindpw ? child->bindpw : parent->bindpw);

    conf->fallback = (child->fallback ? child->fallback : parent->fallback);

    return conf;
}

/* 
 * Use the ldap url parsing routines to break up the ldap url into
 * host and port.
 */
static const char *mod_dynhost_limit_parse_url(cmd_parms *cmd, 
					    void *dummy,
					    const char *url)
{
    int result;
    apr_ldap_url_desc_t *urld;
#if (APR_MAJOR_VERSION >= 1)
    apr_ldap_err_t *result_err;
#endif

    mod_dynhost_limit_config_t *conf =
	(mod_dynhost_limit_config_t *)ap_get_module_config(cmd->server->module_config,
							&vhost_ldap_module);

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
	         cmd->server, "["__FILE__"] url parse: `%s'", 
	         url);
    
#if (APR_MAJOR_VERSION >= 1)    /* for apache >= 2.2 */
    result = apr_ldap_url_parse(cmd->pool, url, &(urld), &(result_err));
    if (result != LDAP_SUCCESS) {
        return result_err->reason;
    }
#else
    result = apr_ldap_url_parse(url, &(urld));
    if (result != LDAP_SUCCESS) {
        switch (result) {
            case LDAP_URL_ERR_NOTLDAP:
                return "LDAP URL does not begin with ldap://";
            case LDAP_URL_ERR_NODN:
                return "LDAP URL does not have a DN";
            case LDAP_URL_ERR_BADSCOPE:
                return "LDAP URL has an invalid scope";
            case LDAP_URL_ERR_MEM:
                return "Out of memory parsing LDAP URL";
            default:
                return "Could not parse LDAP URL";
        }
    }
#endif
    conf->url = apr_pstrdup(cmd->pool, url);

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
	         cmd->server, "["__FILE__"] url parse: Host: %s", urld->lud_host);
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
	         cmd->server, "["__FILE__"] url parse: Port: %d", urld->lud_port);
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
	         cmd->server, "["__FILE__"] url parse: DN: %s", urld->lud_dn);
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
	         cmd->server, "["__FILE__"] url parse: attrib: %s", urld->lud_attrs? urld->lud_attrs[0] : "(null)");
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
	         cmd->server, "["__FILE__"] url parse: scope: %s", 
	         (urld->lud_scope == LDAP_SCOPE_SUBTREE? "subtree" : 
		 urld->lud_scope == LDAP_SCOPE_BASE? "base" : 
		 urld->lud_scope == LDAP_SCOPE_ONELEVEL? "onelevel" : "unknown"));
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
	         cmd->server, "["__FILE__"] url parse: filter: %s", urld->lud_filter);

    /* Set all the values, or at least some sane defaults */
    if (conf->host) {
	/* Space-separated hosts */
        char *p = apr_palloc(cmd->pool, strlen(conf->host) + strlen(urld->lud_host) + 2);
	if (p) {
		strcpy(p, urld->lud_host);
		strcat(p, " ");
		strcat(p, conf->host);
		conf->host = p;
	}
    }
    else {
        conf->host = urld->lud_host? apr_pstrdup(cmd->pool, urld->lud_host) : "localhost";
    }
    conf->basedn = urld->lud_dn? apr_pstrdup(cmd->pool, urld->lud_dn) : "";

    conf->scope = urld->lud_scope == LDAP_SCOPE_ONELEVEL ?
        LDAP_SCOPE_ONELEVEL : LDAP_SCOPE_SUBTREE;

    if (urld->lud_filter) {
        if (urld->lud_filter[0] == '(') {
            /* 
	     * Get rid of the surrounding parens; later on when generating the
	     * filter, they'll be put back.
             */
            conf->filter = apr_pstrdup(cmd->pool, urld->lud_filter+1);
            conf->filter[strlen(conf->filter)-1] = '\0';
        }
        else {
            conf->filter = apr_pstrdup(cmd->pool, urld->lud_filter);
        }
    }
    else {
        conf->filter = "objectClass="DEFAULT_OBJECTCLASS;
    }

      /* "ldaps" indicates secure ldap connections desired
      */
    if (strncasecmp(url, "ldaps", 5) == 0)
    {
        conf->secure = 1;
        conf->port = urld->lud_port? urld->lud_port : LDAPS_PORT;
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, cmd->server,
                     "LDAP: vhost_ldap using SSL connections");
    }
    else if (strncasecmp(url, "ldapi", 5) == 0)
    {
        conf->secure = 0;
        conf->port = 0;
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, cmd->server,
                     "LDAP: vhost_ldap using SSL connections");
    } else
    {
        conf->secure = 0;
        conf->port = urld->lud_port? urld->lud_port : LDAP_PORT;
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, cmd->server, 
                     "LDAP: vhost_ldap not using SSL connections");
    }

    conf->have_ldap_url = 1;
#if (APR_MAJOR_VERSION < 1) /* free only required for older apr */
    apr_ldap_free_urldesc(urld);
#endif
    return NULL;
}

static const char *mod_dynhost_limit_set_enabled(cmd_parms *cmd, void *dummy, int enabled)
{
    mod_dynhost_limit_config_t *conf =
	(mod_dynhost_limit_config_t *)ap_get_module_config(cmd->server->module_config,
							&vhost_ldap_module);

    conf->enabled = (enabled) ? MVL_ENABLED : MVL_DISABLED;

    return NULL;
}

static const char *mod_dynhost_limit_set_binddn(cmd_parms *cmd, void *dummy, const char *binddn)
{
    mod_dynhost_limit_config_t *conf =
	(mod_dynhost_limit_config_t *)ap_get_module_config(cmd->server->module_config,
							&vhost_ldap_module);

    conf->binddn = apr_pstrdup(cmd->pool, binddn);
    return NULL;
}

static const char *mod_dynhost_limit_set_bindpw(cmd_parms *cmd, void *dummy, const char *bindpw)
{
    mod_dynhost_limit_config_t *conf =
	(mod_dynhost_limit_config_t *)ap_get_module_config(cmd->server->module_config,
							&vhost_ldap_module);

    conf->bindpw = apr_pstrdup(cmd->pool, bindpw);
    return NULL;
}

static const char *mod_dynhost_limit_set_deref(cmd_parms *cmd, void *dummy, const char *deref)
{
    mod_dynhost_limit_config_t *conf = 
	(mod_dynhost_limit_config_t *)ap_get_module_config (cmd->server->module_config,
							 &vhost_ldap_module);

    if (strcmp(deref, "never") == 0 || strcasecmp(deref, "off") == 0) {
        conf->deref = never;
	conf->have_deref = 1;
    }
    else if (strcmp(deref, "searching") == 0) {
        conf->deref = searching;
	conf->have_deref = 1;
    }
    else if (strcmp(deref, "finding") == 0) {
        conf->deref = finding;
	conf->have_deref = 1;
    }
    else if (strcmp(deref, "always") == 0 || strcasecmp(deref, "on") == 0) {
        conf->deref = always;
	conf->have_deref = 1;
    }
    else {
        return "Unrecognized value for VhostLDAPAliasDereference directive";
    }
    return NULL;
}

static const char *mod_dynhost_limit_set_fallback(cmd_parms *cmd, void *dummy, const char *fallback)
{
    mod_dynhost_limit_config_t *conf =
	(mod_dynhost_limit_config_t *)ap_get_module_config(cmd->server->module_config,
							&vhost_ldap_module);

    conf->fallback = apr_pstrdup(cmd->pool, fallback);
    return NULL;
}

command_rec mod_dynhost_limit_cmds[] = {
    AP_INIT_TAKE1("VhostLDAPURL", mod_dynhost_limit_parse_url, NULL, RSRC_CONF,
                  "URL to define LDAP connection. This should be an RFC 2255 compliant\n"
                  "URL of the form ldap://host[:port]/basedn[?attrib[?scope[?filter]]].\n"
                  "<ul>\n"
                  "<li>Host is the name of the LDAP server. Use a space separated list of hosts \n"
                  "to specify redundant servers.\n"
                  "<li>Port is optional, and specifies the port to connect to.\n"
                  "<li>basedn specifies the base DN to start searches from\n"
                  "</ul>\n"),

    AP_INIT_TAKE1 ("VhostLDAPBindDN", mod_dynhost_limit_set_binddn, NULL, RSRC_CONF,
		   "DN to use to bind to LDAP server. If not provided, will do an anonymous bind."),
    
    AP_INIT_TAKE1("VhostLDAPBindPassword", mod_dynhost_limit_set_bindpw, NULL, RSRC_CONF,
                  "Password to use to bind to LDAP server. If not provided, will do an anonymous bind."),

    AP_INIT_FLAG("VhostLDAPEnabled", mod_dynhost_limit_set_enabled, NULL, RSRC_CONF,
                 "Set to off to disable vhost_ldap, even if it's been enabled in a higher tree"),

    AP_INIT_TAKE1("VhostLDAPDereferenceAliases", mod_dynhost_limit_set_deref, NULL, RSRC_CONF,
                  "Determines how aliases are handled during a search. Can be one of the"
                  "values \"never\", \"searching\", \"finding\", or \"always\". "
                  "Defaults to always."),

    AP_INIT_TAKE1("VhostLDAPFallback", mod_dynhost_limit_set_fallback, NULL, RSRC_CONF,
		  "Set default virtual host which will be used when requested hostname"
		  "is not found in LDAP database. This option can be used to display"
		  "\"virtual host not found\" type of page."),

    {NULL}
};

static int mod_dynhost_limit_translate_name(request_rec *r)
{
    request_rec *top = (r->main)?r->main:r;
    mod_dynhost_limit_request_t *reqc;
    apr_table_t *e;
    char failures = 0;
    const char **vals = NULL;
    char *filtbuf;
    unsigned int filter_length;
    mod_dynhost_limit_config_t *conf =
	(mod_dynhost_limit_config_t *)ap_get_module_config(r->server->module_config, &vhost_ldap_module);
    core_server_config * core =
	(core_server_config *) ap_get_module_config(r->server->module_config, &core_module);
    util_ldap_connection_t *ldc = NULL;
    int result = 0;
    const char *dn = NULL;
#ifdef CGI
    char *cgi=NULL;
#endif
    const char *hostname = NULL;
    char is_fallback = 0, is_subdomain = 0;

    reqc =
	(mod_dynhost_limit_request_t *)apr_palloc(r->pool, sizeof(mod_dynhost_limit_request_t));
    if (reqc == NULL) return DECLINED;
    memset(reqc, 0, sizeof(mod_dynhost_limit_request_t)); 

    ap_set_module_config(r->request_config, &vhost_ldap_module, reqc);

    // mod_dynhost_limit is disabled or we don't have LDAP Url
    if ((conf->enabled != MVL_ENABLED)||(!conf->have_ldap_url)) {
	return DECLINED;
    }

    hostname = r->hostname;

    /* Estimate filter length */
    filter_length=strlen(hostname);
    if (conf->fallback && strlen(conf->fallback)>filter_length)
	filter_length=strlen(conf->fallback);
    /* Assume that strlen(attributes[0]) + strlen(attributes[1]) >= strlen(attributes[7]) */
    filter_length=15 /* filter chars + 2 */ + (2*filter_length)+ strlen(conf->filter) + strlen(attributes[0]) + strlen(attributes[1]);
    
     ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
		   "["__FILE__"]: filter_length estimated in %d", filter_length);
    
    /* Allocate memory */
    if (filter_length>(2*MAX_STRING_LEN) || (filtbuf=malloc(filter_length))==NULL) return DECLINED;
    
    /* sanity check - if server is down, retry it up to 5 times */
    while (failures++ <= 5) {
	if (conf->host) {
		ldc = util_ldap_connection_find(r, conf->host, conf->port,
			conf->binddn, conf->bindpw, conf->deref,
			conf->secure);
	} else {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r, 
		"["__FILE__"] translate: no conf->host - weird...?");
		return DECLINED;
	}
	for (;;is_subdomain = 0) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
			"["__FILE__"]: translating %s", r->uri);

#ifdef DEBUG
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
			"["__FILE__"]: generating LDAP search filter...");
#endif

		apr_snprintf(filtbuf, filter_length, "(&(%s)(|(%s=%s)(%s=%s)))", conf->filter, attributes[0], hostname, attributes[1], hostname);	    

		ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
			   "["__FILE__"]: LDAP search filter ready: %s", filtbuf);
		    
		result = util_ldap_cache_getuserdn(r, ldc, conf->url, conf->basedn, conf->scope,
					       attributes, filtbuf, &dn, &vals);

		if (result == LDAP_NO_SUCH_OBJECT) {
			apr_snprintf(filtbuf, filter_length, "(&(%s)(%s=%s))", conf->filter, attributes[7], hostname);
			result = util_ldap_cache_getuserdn(r, ldc, conf->url, conf->basedn, conf->scope,
					attributes, filtbuf, &dn, &vals);
			is_subdomain=1;
		}
		
#ifdef DEBUG
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
			"["__FILE__"]: 0xffff9c");
#endif			
			
		if (result == LDAP_NO_SUCH_OBJECT) {
			
			ap_log_rerror(APLOG_MARK, APLOG_NOTICE|APLOG_NOERRNO, 0, r,
				"["__FILE__"] translate: "
				"virtual host (%d) %s not found.",
				is_fallback, hostname);
			
			if (conf->fallback && hostname!=conf->fallback && !is_fallback) {
#ifdef DEBUG
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
					"["__FILE__"]: 0xfff3f");
#endif
				is_fallback=1;
				
				hostname=conf->fallback;
				
				ap_log_rerror(APLOG_MARK, APLOG_NOTICE|APLOG_NOERRNO, 0, r,
					"["__FILE__"] translate: "
					"Trying fallback %s",
					hostname);
				continue;
			}
		}
		break;
	}

	if (result == LDAP_SERVER_DOWN) {
		continue;
	} else break;
    }
    
    free(filtbuf);

#ifdef DEBUG
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
		   "["__FILE__"]: 0xfff40");
#endif
    util_ldap_connection_close(ldc);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
		   "["__FILE__"]: LDAP connection closed");

    /* handle bind failure */
    if (result != LDAP_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r, 
                      "["__FILE__"] translate: "
                      "translate failed; virtual host %s; URI %s [%s]",
		      hostname, r->uri, ldap_err2string(result));
	return DECLINED;
    }

    /* mark the user and DN */
    reqc->dn = apr_pstrdup(r->pool, dn);
#define I (int) i
#define VAL_APR_PSTRDUP(N) reqc->N = apr_pstrdup (r->pool, vals[I])
    /* Optimize */
    if (vals) {
	char i = 0;
	while (attributes[I]) {
	    switch(i) {
		case 0: // vhostServerName
	    		VAL_APR_PSTRDUP(name);
#ifdef DEBUG
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
				"["__FILE__"]: 0xfff5%d %s",I, vals[I]);
#endif
			break;
		case 1: // vhostServerAlias
#ifdef DEBUG
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
				"["__FILE__"]: 0xfff5%d %s",I, vals[I]);
#endif
			break;
		case 2: // vhostServerAdmin
			VAL_APR_PSTRDUP(admin);
#ifdef DEBUG
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
				"["__FILE__"]: 0xfff5%d %s",I, vals[I]);
#endif
			break;
		case 3: // userHome
			reqc->basepath = apr_palloc(r->pool, strlen(VHOST_BPATH) + strlen(vals[I]) +
					(is_subdomain? strlen(hostname) + strlen(SUBDOMAIN_PATH"//") : 2));
					/* "//" is there to avoid writing '+ 1' */
			if (reqc->basepath) {
				strcpy(reqc->basepath, VHOST_BPATH);
				strcat(reqc->basepath, "/");
				strcat(reqc->basepath, vals[I]);
				if (is_subdomain) {
					strcat(reqc->basepath, SUBDOMAIN_PATH"/");
					strcat(reqc->basepath, hostname);
				}
			} else return DECLINED;
#ifdef DEBUG
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
				"["__FILE__"]: 0xfff5%d %s",I, vals[I]);
#endif
			break;
		case 4: // vhostUID
			VAL_APR_PSTRDUP(uid);
#ifdef DEBUG
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
				"["__FILE__"]: 0xfff5%d %s",I, vals[I]);
#endif
			break;
		case 5: // vhostGID
			VAL_APR_PSTRDUP(gid);
#ifdef DEBUG
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
				"["__FILE__"]: 0xfff5%d %s",I, vals[I]);
#endif
			break;
#ifdef TRANSFER
		case 6: // apacheTransfLimit
			VAL_APR_PSTRDUP(transferlimit);
#ifdef DEBUG
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
				"["__FILE__"]: 0xfff5%d %s",I, vals[I]);
#endif
			break;
#endif
	    }
	    i++;
	}
    }
#undef VAL_APR_PSTRDUP
#undef I

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
		  "["__FILE__"]: loaded from ldap: "
		  "%s: %s"
		  ", %s: %s"
		  ", %s: %s"
		  ", %s: %s"
		  ", %s: %s"
#ifdef TRANSFER
		  ", %s (MiB): %s",
#endif
		  attributes[0], reqc->name,
    attributes[2], reqc->admin,
    attributes[3], reqc->basepath,
    attributes[4], reqc->uid,
    attributes[5], reqc->gid
#ifdef TRANSFER
		  , attributes[6], reqc->transferlimit
#endif
		  );

    char *docroot=NULL;
#ifdef LOG    
    char *logpath=NULL;
#endif    
#ifdef CGI
    char *cgiroot=NULL;
#endif

    if ((reqc->name == NULL)||(reqc->basepath == NULL)||(reqc->uid == NULL)||(reqc->gid == NULL)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, 
                      "["__FILE__"] translate: "
                      "translate failed; %s, %s, %s and/or %s is/are not defined",
			attributes[0], attributes[3], attributes[4], attributes[5]);
	return DECLINED;
    } else {
	docroot = apr_palloc(r->pool, strlen(reqc->basepath) + strlen(VHOST_DOCROOT) + 1);
	if (docroot != NULL) {
		strcpy(docroot, reqc->basepath);
		strcat(docroot, VHOST_DOCROOT);
	} else return DECLINED;
#ifdef LOG
	logpath = apr_palloc(r->pool, strlen(reqc->basepath) + strlen(VHOST_LOGS) + 1);
	if (logpath != NULL) {
		strcpy(logpath, reqc->basepath);
		strcat(logpath, VHOST_LOGS);
	} else logpath=reqc->basepath;
#endif
#ifdef CGI
	cgiroot = apr_palloc(r->pool, strlen(reqc->basepath) + strlen(VHOST_SCRIPTALIAS) + 1);
	if (cgiroot != NULL) {
		strcpy(cgiroot, reqc->basepath);
		strcat(cgiroot, VHOST_SCRIPTALIAS);
	}
#endif
    }

#ifdef CGI    
    if (cgiroot) {
	cgi = strstr(r->uri, CGI_PATH"/");
	if (cgi && (cgi != r->uri + strspn(r->uri, "/"))) {
	    cgi = NULL;
	}
    }
    if (cgi) {
	r->filename = apr_pstrcat (r->pool, cgiroot, cgi + strlen(CGI_PATH), NULL);
	r->handler = "cgi-script";
	apr_table_setn(r->notes, "alias-forced-type", r->handler);
    } else
#endif
    if (r->uri[0] == '/') {
	r->filename = apr_pstrcat (r->pool, docroot, r->uri, NULL);
    } else {
	return DECLINED;
    }

    top->server->server_hostname = apr_pstrdup (top->pool, reqc->name);

    if (reqc->admin) {
	top->server->server_admin = apr_pstrdup (top->pool, reqc->admin);
    }

    // set environment variables
    e = top->subprocess_env;
    apr_table_addn (e, "SERVER_ROOT", docroot);
#ifdef DEBUG
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
			"["__FILE__"]: 0xfff9f");
#endif
#ifdef LOG
    apr_table_addn (e, "LOG_PATH", logpath);
    apr_table_addn (top->notes, "LOG_PATH", logpath);
#endif

    core->ap_document_root = apr_pstrdup(top->pool, docroot);

#ifdef SUPHP
#ifdef DEBUG
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
			"["__FILE__"]: 0xfffa0");
#endif
    if (ap_find_linked_module("mod_suphp.c") != NULL) {
	/*USELESS:
	mod_dynhost_limit_get_suphp_id_doer(top);
	*/

	
	long uid = -1;
	long gid = -1;
	for (;;) {
		uid = atol(reqc->uid);
		if ((uid < MIN_UID)) {
			break;
		}
		gid = atol(reqc->gid);
		if ((uid < MIN_GID)) {
			break;
		}

		char **buf=malloc(2*sizeof(char *));
				
		if (buf!=NULL) {
				
			buf[0]=apr_palloc(r->pool, strlen(r->server->server_hostname) + 12); /* = strlen("SUPHP_USER_") + 1 */
			buf[1]=apr_palloc(r->pool, strlen(r->server->server_hostname) + 12); /* = strlen("SUPHP_GROUP") + 1 */
				
			if (buf[0]!=NULL && buf[1]!=NULL) {
				strcpy(buf[0], "SUPHP_USER_");
				strcat(buf[0],r->server->server_hostname);
				
				apr_table_addn (top->notes, buf[0], apr_psprintf(r->pool, "#%ld", uid));
#ifdef DEBUG
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
					"["__FILE__"]: 0xfffa1 u%s res:%s", buf[0],
					apr_table_get(top->notes, (char *)buf[0]));
#endif
				strcpy(buf[1], "SUPHP_GROUP");
				strcat(buf[1],r->server->server_hostname);

				apr_table_addn (top->notes, buf[1], apr_psprintf(r->pool, "#%ld", gid));
#ifdef DEBUG
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
					"["__FILE__"]: 0xfffa1 g%s res:%s", buf[1],
					apr_table_get(top->notes, (char *)buf[1]));
#endif
			}
		}
		free(buf);
		break;
	}
    }
#endif
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
		  "["__FILE__"]: translated to %s", r->filename);

    return OK;
}

/*
Preserve environment even when an internal redirect takes place
*/
static int mod_dynhost_limit_preserve_env(request_rec *r)
{
	const char *m;
	apr_table_t *e;
	request_rec *top = (r->main)?r->main:r;
	
	e = top->subprocess_env;

	if (r->prev && (m = apr_table_get(r->subprocess_env, "REDIRECT_SERVER_ROOT"))) {
		apr_table_setn(e, "SERVER_ROOT", m);
	}

#ifdef LOG	
	if (r->prev && (m = apr_table_get(r->subprocess_env, "REDIRECT_LOG_PATH"))) {
		apr_table_setn(e, "LOG_PATH", m);
		apr_table_setn(top->notes, "LOG_PATH", m);
	}
#endif

	return OK;
}

#ifdef HAVE_UNIX_SUEXEC
static ap_unix_identity_t *mod_dynhost_limit_get_suexec_id_doer(const request_rec * r)
{
  ap_unix_identity_t *ugid = NULL;
  mod_dynhost_limit_config_t *conf = 
      (mod_dynhost_limit_config_t *)ap_get_module_config(r->server->module_config,
						      &vhost_ldap_module);
  mod_dynhost_limit_request_t *req =
      (mod_dynhost_limit_request_t *)ap_get_module_config(r->request_config,
						       &vhost_ldap_module);

  uid_t uid = -1;
  gid_t gid = -1;

  // mod_dynhost_limit is disabled or we don't have LDAP Url
  if ((conf->enabled != MVL_ENABLED)||(!conf->have_ldap_url)) {
      return NULL;
  }

  if ((req == NULL)||(req->uid == NULL)||(req->gid == NULL)) {
      return NULL;
  }

  if ((ugid = apr_palloc(r->pool, sizeof(ap_unix_identity_t))) == NULL) {
      return NULL;
  }

  uid = (uid_t) atol(req->uid);
  gid = (gid_t) atol(req->gid);

  if ((uid < MIN_UID)||(gid < MIN_GID)) {
      return NULL;
  }

  ugid->uid = uid;
  ugid->gid = gid;
  ugid->userdir = 0;
  
  return ugid;
}
#endif

#if defined(SUPHP_USELESS_CODE)
static int mod_dynhost_limit_get_suphp_id_doer(request_rec * r)
{
  mod_dynhost_limit_config_t *conf = 
      (mod_dynhost_limit_config_t *)ap_get_module_config(r->server->module_config,
						      &vhost_ldap_module);
  mod_dynhost_limit_request_t *req =
      (mod_dynhost_limit_request_t *)ap_get_module_config(r->request_config,
						       &vhost_ldap_module);
  static APR_OPTIONAL_FN_TYPE(suphp_user_group_external) *suphp_ug;

  // mod_dynhost_limit is disabled or we don't have LDAP Url
  if ((conf->enabled != MVL_ENABLED)||(!conf->have_ldap_url)) {
      return DECLINED;
  }

  if ((req == NULL)||(req->uid == NULL)||(req->gid == NULL)) {
      return DECLINED;
  }
  
  suphp_ug = APR_RETRIEVE_OPTIONAL_FN(suphp_user_group_external);
  
  if (suphp_ug) {
	suphp_ug(r,req->uid,req->gid);
	return OK;
  }
  
  return DECLINED;
}
#endif

static void
mod_dynhost_limit_register_hooks (apr_pool_t * p)
{
    ap_hook_post_config(mod_dynhost_limit_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_translate_name(mod_dynhost_limit_translate_name, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(mod_dynhost_limit_preserve_env, NULL, NULL, APR_HOOK_MIDDLE);
#ifdef HAVE_UNIX_SUEXEC
    ap_hook_get_suexec_identity(mod_dynhost_limit_get_suexec_id_doer, NULL, NULL, APR_HOOK_FIRST);
#endif
#if (APR_MAJOR_VERSION >= 1)
    ap_hook_optional_fn_retrieve(ImportULDAPOptFn,NULL,NULL,APR_HOOK_MIDDLE);
#endif
}

module AP_MODULE_DECLARE_DATA vhost_ldap_module = {
  STANDARD20_MODULE_STUFF,
  NULL,
  NULL,
  mod_dynhost_limit_create_server_config,
  mod_dynhost_limit_merge_server_config,
  mod_dynhost_limit_cmds,
  mod_dynhost_limit_register_hooks,
};
