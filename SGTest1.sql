/* DATABASE SECURITY RISK ASSESSMENT SCRIPT		      */
/* risk_assessment_main.sql			              */
/* Last Updated 23-Jan-2015			              */
/* 						              */
/* Be sure to run this script as 'sys as SYSDBA'              */
/*  CHANGE LOG
Version: 3.13
01 - modified object audit query to correct error in return values
02 - modified privilege query to recursively include role priviles
03 - modified OS checks to look for TNS POISON mitigation CVE-2012-1675
04 - added query to check for 05LOGON vulnerability issues in 11g CVE-2012-3137
05 - added query to check for usernames same as password
06 - added queries to show database info at start of script
07 - added legal disclaimer at start of script
08 - added test for ShellShock BASH Bug vulnerability
09 - added addtional option and policy tests for data redaction
10 - added check for OJVM mitigation patch CVE-2014-6546-7,CVE-2014-6545, CVE-2014-6453, CVE-2014-6450, CVE-2014-6537 
11 - added check to see what the HTTPPORT is for XDB/Apex
12 - modified queries on who has access to sensitive data to order by table instead of grantee
13 - added test for Dual Public privileges CVE-2015-0393
*/
PROMPT The Database Security Risk Overview script you are about to run gathers data 
PROMPT and information about your system.  This data and info, rmation is gathered for 
PROMPT the express purpose of identifying some areas of potential security risk that
PROMPT might provide an avenue for a successful penetration attempt, potentially
PROMPT contributing to data breach ("Purpose").  This script is not designed or guaranteed
PROMPT to identify all potential or possible security risks.
PROMPT 
PROMPT Prior to continuing with the execution of this script, you are strongly advised 
PROMPT to validate that the checksum for this script matches the information provided to 
PROMPT you by Oracle with the script.  If the checksum does NOT match that information, 
PROMPT please exit the script without continuing and contact your Oracle account representative 
PROMPT for assistance.  As with any script, you are also strongly advised to first
PROMPT execute the script in a non-production environment to validate that the script 
PROMPT does not negatively or adversely impact your system.

PROMPT The information and data gathered by this script includes, among other things, system 
PROMPT configuration data and information that a skilled attacker may be able to use to 
PROMPT attempt to penetrate, or to penetrate, your system. You should handle the scripts 
PROMPT output in accordance with your companys policy for dealing with sensitive data. You 
PROMPT remain solely responsible for your system, the data and information gathered by this 
PROMPT script, and the output of this script.  You are also solely responsible for the execution 
PROMPT of, and the effect and results of the execution of (including, without limitation, any 
PROMPT damage or data loss), this script.

PROMPT By continuing with the execution of this script, you consent to the use for the Purpose, 
PROMPT by Oracle, of the information and data gathered by the script.

PROMPT Press the <ENTER> key to continue with the execution of this script. Press <CTRL>-C
PROMPT to exit.
PROMPT
PAUSE
connect / as sysdba
alter session set nls_date_format="DD-MON-YYYY HH24:MI";
TTITLE "Database Security Risk Assessment (Main)"

set lines 250
set pages 66
set verif off
set trims on
set tab off
set escape on
set heading off
col host for a40
col table_name format a30
col object_name format a30
col privilege format a35
col account_status format a16
col default_tablespace format a15
col external_name format a25
col username format a22
col user_name format a22
col grantor format a22
col owner format a22
col object_type format a15
col object_name format a25
col object_schema format a22
col grantee format a27
col type_name format a25
col type_schema format a17
col policy_text format a50
col directory_path format a100
spool dbra_main_$ORACLE_SID.out

SELECT '********** Database Security Risk Assessment '||sysdate||' FOR DATABASE: '||name||' **********' FROM v$database;
set heading on
PROMPT ****TABLE OF CONTENTS****
PROMPT QUICK LOOK - QUICK LOOK - QUICK LOOK - QUICK LOOK
PROMPT -----Check for users with DBA privs
PROMPT -----Check for roles with DBA privs
PROMPT -----Check users with Create, Alter, OR Drop User privileges
PROMPT -----Check for users with Alter Session
PROMPT -----Database users with deadly system privileges assigned to them.
PROMPT -----Check for users with EXPORT FULL DATABASE
PROMPT -----Database users with deadly roles assigned to them.
PROMPT -----Security related initialization parameters
PROMPT -----Security related feature usage
PROMPT -----What is being audited in the database?
PROMPT -----List directories
PROMPT ROLES ROLES ROLES ROLES ROLES ROLES ROLES
PROMPT -----Roles in this database
PROMPT -----Count of System level privileges granted to roles
PROMPT -----System Privileges granted to roles
PROMPT -----OBJECT-level Privileges on SYS, SYSTEM, DVSYS, OR LBACSYS objects granted to roles
PROMPT -----EXECUTE privileges on sensitive packages granted to roles
PROMPT -----Users assigned to roles
PROMPT USERS USERS USERS USERS USERS USERS USERS
PROMPT -----Top Role Owners
PROMPT -----Number of Roles granted to users
PROMPT -----Roles granted to users
PROMPT -----Users with SYSTEM as default tablespace
PROMPT -----Users in this database
PROMPT -----Potential Root Kits - users not visible in DBA_USERS
PROMPT -----Users whose passwords never expire
PROMPT -----Users not subject to failed login limits
PROMPT -----Roles granted to users
PROMPT -----Count of System level privileges granted to users
PROMPT -----Object level Privileges on SYS, SYSTEM, OR DVSYS objects granted to users
PROMPT -----Object level Privileges on SYS *$ tables granted to users
PROMPT -----EXECUTE privileges on sensitive packages granted to users
PROMPT -----Sample Schemas in this database
PROMPT PUBLIC PUBLIC PUBLIC PUBLIC PUBLIC
PROMPT -----Roles Granted To Public
PROMPT -----System Privileges Granted To Public
PROMPT -----Object Privileges Granted To Public
PROMPT -----Column Privileges Granted To Public
PROMPT PASSWORDS PASSWORDS PASSWORDS PASSWORDS PASSWORDS
PROMPT -----Password file users
PROMPT -----Count of Password Profile Users
PROMPT -----List of Password Profiles
PROMPT -----List of Password Verify Functions
PROMPT -----List Resource Profiles
PROMPT -----Check for passwords in database links
PROMPT -----Check for 11g databases without 10g verifiers CVE-2012-3137
PROMPT -----Check for default passwords using rainbow table
PROMPT -----Check for default passwords using dba_users_with_defpwd
PROMPT -----Check for passwords that are the same as the user name
PROMPT OBJECTS OBJECTS OBJECTS
PROMPT -----Which constraints have been disabled
PROMPT -----Which tables have names columns names like password
PROMPT -----Which tables have names columns names like SSN
PROMPT -----Which tables have names columns names like credit card numbers
PROMPT LOGIN TRIGGERS LOGIN TRIGGERS LOGIN TRIGGERS
PROMPT -----Which logon triggers exist?
PROMPT VPD VPD VPD VPD VPD VPD VPD VPD VPD
PROMPT -----Which VPD policies exist?
PROMPT REDACTION REDACTION REDACTION REDACTION REDACTION
PROMPT -----Which Data Redaction policies exist?
PROMPT ENCRYPTION ENCRYPTION ENCRYPTION ENCRYPTION
PROMPT -----Encryption Wallet
PROMPT -----Encrypted Columns
PROMPT -----Encrypted Tablespaces
PROMPT -----Tables in Encrypted Tablespaces
PROMPT CONFIGURATION CONFIGURATION CONFIGURATION CONFIGURATION
PROMPT -----Listing of parameters
PROMPT -----Listing of Java Permissions
PROMPT NETWORKING NETWORKING NETWORKING
PROMPT -----Check for external procedures
PROMPT -----Check status of network permissions (11g)
PROMPT PATCHING PATCHING PATCHING
PROMPT -----Check for PSU/CPU
PROMPT -----Patchsets from sysman.mgmt$applied_patchsets
PROMPT -----Patches from sysman.mgmt.applied_patches
PROMPT -----Tests for specific vulnerabilities
PROMPT OS level checks
PROMPT -----Check for ShellShock BASH bug
PROMPT -----Check patches applied to the database
PROMPT -----Check file permissions
PROMPT -----Who runs Oracle Processes?
PROMPT -----Check for OS Users that can startup, shutdown AND admin Oracle Databases
PROMPT -----/etc/passwd
PROMPT -----/etc/group
PROMPT -----Check listener security level
PROMPT -----Default Listener Status
PROMPT -----SQLNET.ORA FROM ORACLE_HOME 
PROMPT -----SQLNET.ORA FROM TNS_ADMIN
PROMPT -----LISTENER.ORA FROM ORACLE_HOME 
PROMPT -----LISTENER.ORA FROM TNS_ADMIN
PROMPT -----Check DB Password File Permissions 
PROMPT -----Check network listeners
PROMPT -----Check VNC servers
PROMPT
PROMPT
PROMPT #######################################################################
PROMPT DATABASE INFORMATION - DATABASE INFORMATION - DATABASE INFORMATION
PROMPT #######################################################################
column name format a8
column log_mode format a12
column platform_name format a30
column guard_status format a10 heading Guard|Status
column dataguard_broker format a10 heading Dataguard|Broker
column flashback_on format a9 heading flashbank|on
column controlfile_type format a11 heading controlfile|type
select name, created, log_mode, platform_name, guard_status, DATAGUARD_BROKER, flashback_on, controlfile_type 
from v$database;
column name clear
column log_mode clear
column platform_name clear
column guard_status clear
column dataguard_broker clear
column flashback_on clear
column controlfile_type clear
PROMPT #######################################################################
PROMPT Database Version
PROMPT #######################################################################
column banner format a80 
select * from v$version;
column banner clear
PROMPT #######################################################################
PROMPT QUICK LOOK - QUICK LOOK - QUICK LOOK - QUICK LOOK
PROMPT #######################################################################
PROMPT #######################################################################
PROMPT Check for users with DBA privs
PROMPT #######################################################################
SELECT a.grantee "GRANTEE", a.admin_option "ADMIN", a.default_role "DEFAULT", b.account_status "ACCOUNT_STATUS"
FROM dba_role_privs a, dba_users b
WHERE a.grantee=b.username
AND grantee NOT IN ('SYS','SYSTEM')
AND grantee NOT IN (SELECT role FROM dba_roles)
AND granted_role='DBA'
/
PROMPT #######################################################################
PROMPT Check for roles with DBA privs
PROMPT #######################################################################
SELECT * FROM dba_role_privs
WHERE grantee IN (SELECT role FROM dba_roles)
AND granted_role='DBA'
/
PROMPT #######################################################################
PROMPT Check users with Create, Alter, OR Drop User privileges
PROMPT #######################################################################
SELECT a.grantee "GRANTEE", a.privilege "PRIVILEGE", a.admin_option "ADMIN_OPTION", b.account_status "ACCOUNT_STATUS"
FROM dba_sys_privs a, dba_users b
WHERE (privilege LIKE '%DROP%USER'
      OR privilege LIKE '%ALTER%USER%'
      OR privilege LIKE '%CREATE%USER%')
AND grantee NOT IN ('IMP_FULL_DATABASE', 'DBA')
AND a.grantee=b.username
ORDER BY 4,1,2
/
PROMPT #######################################################################
PROMPT Check for users with Alter Session
PROMPT #######################################################################
SELECT a.grantee "GRANTEE", a.privilege "PRIVILEGE", a.admin_option "ADMIN_OPTION", b.account_status "ACCOUNT_STATUS"
FROM dba_sys_privs a, dba_users b
WHERE a.privilege = 'ALTER SESSION'
AND grantee <> 'DBA'
AND a.grantee=b.username
ORDER BY 4,1
/
PROMPT #######################################################################
PROMPT Database users with deadly system privileges assigned to them.
PROMPT #######################################################################
SELECT a.privilege "PRIVILEGE", a.grantee "GRANTEE", a.admin_option "ADMIN_OPTION", b.account_status "ACCOUNT_STATUS"
FROM dba_sys_privs a, dba_users b
WHERE  privilege IN ('SELECT ANY TABLE', 'INSERT ANY TABLE','UPDATE ANY TABLE','DELETE ANY TABLE','SELECT ANY DICTIONARY', 'CREATE ANY PROCEDURE',
                      'ALTER ANY PROCEDURE','CREATE ANY TRIGGER','ALTER ANY TRIGGER')
 AND   grantee NOT IN ('SYS', 'SYSTEM', 'OUTLN', 'AQ_ADMINISTRATOR_ROLE', 'DBA', 'EXP_FULL_DATABASE', 'IMP_FULL_DATABASE',
                       'OEM_MONITOR', 'CTXSYS', 'DBSNMP', 'IFSSYS','IFSSYS$CM', 'MDSYS', 'ORDPLUGINS', 'ORDSYS', 'TIMESERIES_DBA')
 AND a.grantee=b.username
 ORDER BY 4,1,2
/

PROMPT #######################################################################
PROMPT Check for users with EXPORT FULL DATABASE
PROMPT #######################################################################
SELECT a.grantee "GRANTEE",a.granted_role "GRANTED_ROLE",a.admin_option "ADMIN_OPTION", a.default_role "DEFAULT_ROLE", 
       NVL(b.account_status,'ROLE') "ACCOUNT_STATUS"
FROM dba_role_privs a, dba_users b
WHERE grantee NOT IN (SELECT grantee FROM dba_role_privs
                     WHERE grantee NOT IN (SELECT role FROM dba_roles)
                     AND granted_role='DBA')
AND granted_role IN ('EXP_FULL_DATABASE','DATAPUMP_EXP_FULL_DATABASE', 'DATAPUMP_EXP_FULL_DATABASE','DATAPUMP_IMP_FULL_DATABASE' )
AND grantee <> 'DBA'
AND a.grantee =b.username(+)
ORDER BY 5,1,2
/
PROMPT #######################################################################
PROMPT Database users with deadly roles assigned to them.
PROMPT #######################################################################
SELECT a.grantee "GRANTEE",a.granted_role "GRANTED_ROLE",a.admin_option "ADMIN_OPTION", a.default_role "DEFAULT_ROLE", 
       b.account_status "ACCOUNT_STATUS"
FROM   dba_role_privs a, dba_users b
WHERE  granted_role IN ('DBA', 'SELECTROLE','AQ_ADMINISTRATOR_ROLE',
                       'EXP_FULL_DATABASE', 'IMP_FULL_DATABASE',
                       'OEM_MONITOR')
  AND  grantee NOT IN ('SYS', 'SYSTEM', 'OUTLN', 'AQ_ADMINISTRATOR_ROLE',
                       'DBA', 'EXP_FULL_DATABASE', 'IMP_FULL_DATABASE',
                       'OEM_MONITOR', 'CTXSYS', 'DBSNMP', 'IFSSYS',
                       'IFSSYS$CM', 'MDSYS', 'ORDPLUGINS', 'ORDSYS',
                       'TIMESERIES_DBA')
  AND a.grantee=b.username
ORDER BY 5,1,2
/
PROMPT #######################################################################
PROMPT Security related initialization parameters
PROMPT #######################################################################
col parameter_value format a60
SELECT trim(name)||': '||value "PARAMETER_VALUE", isdefault 
FROM v$parameter 
WHERE name IN 
       ('_trace_files_public','O7_DICTIONARY_ACCESSIBILITY','audit_file_dest','audit_sys_operations','audit_trail','compatible',
        'dblink_encrypt_login','dispatchers', 'global_names','os_authent_prefix','os_roles','remote_listener','remote_login_passwordfile',
        'remote_os_authent','remote_os_roles','sec_case_sensitive_logon','sec_protocol_error_trace_action','sec_protocol_error_further_action',
        'sec_max_failed_login_attempts','sec_return_server_release_banner','sql92_security','transaction_auditing','utl_file_dir')
ORDER BY 1;
PROMPT
PROMPT XDB Port is:
select dbms_xdb.gethttpport() from dual;
PROMPT #######################################################################
PROMPT Security related feature usage
PROMPT #######################################################################
col host for a40
col table_name format a30
col object_name format a30
col privilege format a35
col account_status format a16
col default_tablespace format a15
col external_name format a25
col username format a22
col user_name format a22
col grantor format a22
col owner format a22
col object_type format a15
col object_name format a25
col object_schema format a22
col grantee format a27
col type_name format a25
col type_schema format a17
col policy_text format a50
col directory_path format a100		
col name format a45
col version format a15
SELECT name, version, detected_usages,currently_used 
FROM dba_feature_usage_statistics
WHERE name in ('ASO native encryption and checksumming','Audit Options','Client Identifier','Data Masking Pack','Data Redaction', 'Encrypted Tablespaces','Label Security','Oracle Database Vault','Oracle Java Virtual Machine (system)','Oracle Java Virtual Machine (user)','Oracle Secure Backup','Read Only Tablespace','SecureFile Encryption (system)','SecureFile Encryption (user)','Transparent Data Encryption','Virtual Private Database (VPD)')
ORDER by 1,2;
PROMPT #######################################################################
PROMPT
PROMPT What is being audited in the database?
PROMPT
PROMPT #######################################################################
PROMPT ### Statement Audit
col proxy_name format a30
col audit_option format a40
col success format a15
col failure format a15
SELECT * FROM dba_stmt_audit_opts ORDER BY 1,3;
PROMPT ### Object Audit
select owner, object_type, object_name, sel, upd, ins, del, exe, alt from dba_obj_audit_opts order by 1,2,3;
PROMPT ### Privilege Audit
SELECT * FROM dba_priv_audit_opts;
PROMPT ### Fine Grained Audit Policies
SELECT object_schema, object_name, policy_name, policy_text, policy_column, enabled, sel, ins, upd, del FROM dba_audit_policies ORDER BY 1,2;
PROMPT #### What is in the audit trail 
select audit_type, count(*) "NUM", trunc(min(extended_timestamp)) "MIN_DATE", trunc(max(extended_timestamp)) "MAX_DATE"
from dba_common_audit_trail
group by audit_type;
PROMPT #######################################################################
PROMPT List directories
PROMPT #######################################################################
PROMPT -- Variables gathered using DBMS_SYSTEM
set serveroutput on
declare
v_oh varchar2(500);
v_tns varchar2(500);
v_path varchar2(4000);
begin
dbms_system.get_env('ORACLE_HOME',v_oh);
dbms_system.get_env('TNS_ADMIN',v_tns);
dbms_system.get_env('PATH',v_path);
dbms_output.put_line('ORACLE_HOME: '||v_oh);
dbms_output.put_line('TNS_ADMIN: '||v_tns);
dbms_output.put_line('PATH: '||v_path);
end;
/
PROMPT -- Variables gathered using audit_file_dest
SELECT trim(name)||': '||value "PARAMETER_VALUE", isdefault 
FROM v$parameter 
WHERE name = 'audit_file_dest';
PROMPT -- Variables gathered using a host-level echo of the variables
spool off
host echo ORACLE_HOME=$ORACLE_HOME  >> dbra_main_$ORACLE_SID.out
host echo TNS_ADMIN=$TNS_ADMIN  >> dbra_main_$ORACLE_SID.out
host echo PATH=$PATH  >> dbra_main_$ORACLE_SID.out
col directory_name format a30
col directory_path format a45
spool dbra_main_$ORACLE_SID.out append
SELECT * FROM dba_directories ORDER BY owner, directory_path
/
select * from dba_tab_privs where exists (select 'XX' from dba_directories where directory_name = table_name)
/
PROMPT #######################################################################
PROMPT ROLES ROLES ROLES ROLES ROLES ROLES ROLES
PROMPT #######################################################################
PROMPT
PROMPT Roles in this database
PROMPT
PROMPT #######################################################################
col role format a45
SELECT * FROM dba_roles ORDER BY 1;
PROMPT #######################################################################
PROMPT
PROMPT Count of System level privileges granted to roles
PROMPT
PROMPT #######################################################################
col grantee format a30
 select count(*) "COUNT_SYSPRIVS" , grantee "ROLE_NAME"
  from dba_sys_privs a, DBA_roles b
  where b.role = a.grantee
 group by grantee
 order by 1 desc;
col grantee clear
PROMPT #######################################################################
PROMPT
PROMPT System Privileges granted to roles
PROMPT
PROMPT #######################################################################
col ROLE_NAME format a30
SELECT grantee "ROLE_NAME", privilege, admin_option FROM dba_sys_privs WHERE grantee in
   (SELECT role FROM dba_roles) ORDER BY grantee, privilege
/
PROMPT #######################################################################
PROMPT
PROMPT OBJECT-level Privileges on SYS, SYSTEM, DVSYS, OR LBACSYS objects granted to roles
PROMPT
PROMPT #######################################################################
break on role_name on owner
SELECT grantee "ROLE_NAME", owner, table_name, grantor,
       max(decode(privilege,'SELECT','X')) "SELECT",
       max(decode(privilege,'INSERT','X')) "INSERT",
       max(decode(privilege,'UPDATE','X')) "UPDATE",
       max(decode(privilege,'DELETE','X')) "DELETE",
       max(decode(privilege,'ALTER','X')) "ALTER",
       max(decode(privilege,'REFERENCES','X')) "REFERENCES",
       max(decode(privilege,'INDEX','X')) "INDEX",
       max(decode(privilege,'EXECUTE','X')) "EXECUTE"
FROM dba_tab_privs
WHERE (grantee IN (SELECT role FROM dba_roles) 
    AND grantee NOT IN ('DBA','SELECT_CATALOG_ROLE','EXECUTE_CATALOG_ROLE','DV_SECANALYST','DELETE_CATALOG_ROLE')
    AND owner IN ('SYS','SYSTEM')
    AND table_name IN ('USER$','USER_HISTORY$','SOURCE','LINK$','AUD$','FGA_LOG$','KU$_USER_VIEW'))
OR (grantee IN (SELECT role FROM dba_roles)
    AND grantee NOT IN ('DV_GOLDENGATE_ADMIN','DV_XSTREAM_ADMIN','DV_SECANALYST','DV_MONITOR',
                      'DV_ADMIN','DV_OWNER','DV_ACCTMGR','DV_PUBLIC','DV_PATCH_ADMIN','DV_STREAMS_ADMIN',
                      'DV_GOLDENGATE_REDO_ACCESS','DV_REALM_RESOURCE','DV_REALM_OWNER')
    AND owner ='DVSYS')
OR (grantee IN (SELECT role FROM dba_roles)
    AND grantee not in ('SELECT_CATALOG_ROLE','PUBLIC')
    AND owner='LBACSYS')
GROUP BY grantee, owner, grantor, table_name
ORDER BY grantee,owner,table_name;
clear breaks
PROMPT #######################################################################
PROMPT
PROMPT EXECUTE privileges on sensitive packages granted to roles
PROMPT
PROMPT #######################################################################
break on role_name on owner
SELECT grantee "ROLE_NAME", owner, table_name, grantor,
       max(decode(privilege,'SELECT','X')) "SELECT",
       max(decode(privilege,'INSERT','X')) "INSERT",
       max(decode(privilege,'UPDATE','X')) "UPDATE",
       max(decode(privilege,'DELETE','X')) "DELETE",
       max(decode(privilege,'ALTER','X')) "ALTER",
       max(decode(privilege,'REFERENCES','X')) "REFERENCES",
       max(decode(privilege,'INDEX','X')) "INDEX",
       max(decode(privilege,'EXECUTE','X')) "EXECUTE"
FROM dba_tab_privs
WHERE (grantee IN (SELECT role FROM dba_roles) 
    AND table_name IN ('UTL_SMTP','UTL_FILE','UTL_TCP','UTL_HTTP','DBMS_LOB','DBMS_SYS_SQL','DBMS_JOB','DBMS_BACKUP_RESTORE'))
GROUP BY (grantee, owner, grantor, table_name)
ORDER BY grantee, owner, table_name;
clear breaks
PROMPT #######################################################################
PROMPT
PROMPT Users assigned to roles
PROMPT
PROMPT #######################################################################
col granted_role format a30
col grantee format a30
break on granted_role
SELECT granted_role, grantee, admin_option, default_role FROM dba_role_privs ORDER BY granted_role, grantee
/
clear breaks
PROMPT #######################################################################
PROMPT USERS USERS USERS USERS USERS USERS USERS
PROMPT #######################################################################
PROMPT #######################################################################
PROMPT
PROMPT Top Role Owners
PROMPT
PROMPT #######################################################################
SELECT * FROM (SELECT grantee, count(granted_role) "NUMBER ROLES" 
FROM dba_role_privs 
WHERE grantee IN (SELECT username 
                  FROM dba_users 
                  WHERE username NOT IN ('SYS','SYSTEM')) 
GROUP BY grantee 
ORDER BY 2 desc) 
WHERE rownum<11
/
PROMPT #######################################################################
PROMPT
PROMPT Number of Roles granted to users
PROMPT
PROMPT #######################################################################
SELECT grantee, count(granted_role) "NUMBER ROLES" 
FROM dba_role_privs 
WHERE grantee IN (SELECT username 
                  FROM dba_users 
                  WHERE username NOT IN ('SYS','SYSTEM')) 
GROUP BY grantee 
ORDER BY grantee
/
PROMPT #######################################################################
PROMPT
PROMPT Roles granted to users
PROMPT
PROMPT #######################################################################
break on grantee
SELECT grantee, granted_role, admin_option, default_role 
FROM dba_role_privs
WHERE grantee NOT IN (SELECT role FROM dba_roles) AND grantee NOT IN ('SYS','PUBLIC')
ORDER BY grantee
/
clear breaks
PROMPT #######################################################################
PROMPT
PROMPT Users with SYSTEM as default tablespace
PROMPT
PROMPT #######################################################################
col property_name  format a30
col property_value format a30
col profile format a30
col external_name format a40
SELECT property_name, property_value
FROM database_properties where property_name in ('DEFAULT_PERMANENT_TABLESPACE','DEFAULT_TEMP_TABLESPACE');
prompt########
prompt 
SELECT account_status, username, default_tablespace, profile, external_name 
FROM dba_users 
WHERE default_tablespace='SYSTEM' 
ORDER BY account_status, username
/
PROMPT #######################################################################
PROMPT
PROMPT Users in this database
PROMPT
PROMPT #######################################################################
col password format a15
col profile format a30
SELECT account_status, username, created, lock_date, expiry_date, default_tablespace, profile, password, external_name 
FROM dba_users 
ORDER BY account_status, username
/
PROMPT #######################################################################
PROMPT
PROMPT Potential Root Kits - users not visible in DBA_USERS
PROMPT
PROMPT #######################################################################
col ext_username format a30 heading EXTERNAL_NAME
select u.name, 
       m.status,
       u.ext_username
       from sys.user$ u, 
            sys.user_astatus_map m
       where u.astatus = m.status#
       and u.type# = 1
MINUS
select username, 
       account_status, 
       external_name 
  from dba_users;
PROMPT #######################################################################
PROMPT
PROMPT Users whose passwords never expire
PROMPT
PROMPT #######################################################################
col profile format a25
col LIMIT format a10
col default_limit format a10
SELECT account_status, username, profile, limit, default_limit
FROM (
SELECT a.account_status, a.username, a.profile, b.limit, c.limit "DEFAULT_LIMIT"
FROM dba_users a JOIN dba_profiles b ON a.profile=b.profile LEFT OUTER JOIN dba_profiles c ON b.limit=c.profile
WHERE b.resource_name='PASSWORD_LIFE_TIME'
and (c.resource_name='PASSWORD_LIFE_TIME' OR c.resource_name IS NULL)
AND (b.limit='UNLIMITED' OR c.limit='UNLIMITED'))
ORDER BY account_status, username;
PROMPT #######################################################################
PROMPT
PROMPT Users not subject to failed login limits
PROMPT
PROMPT #######################################################################
SELECT account_status, username, profile, limit, default_limit
FROM (
SELECT a.account_status, a.username, a.profile, b.limit, c.limit "DEFAULT_LIMIT"
FROM dba_users a JOIN dba_profiles b ON a.profile=b.profile LEFT OUTER JOIN dba_profiles c ON b.limit=c.profile
WHERE b.resource_name='FAILED_LOGIN_ATTEMPTS'
and (c.resource_name='FAILED_LOGIN_ATTEMPTS' OR c.resource_name IS NULL)
AND (b.limit='UNLIMITED' OR c.limit='UNLIMITED'))
ORDER BY account_status, username;
PROMPT #######################################################################
PROMPT
PROMPT Roles granted to users
PROMPT
PROMPT #######################################################################
break on grantee
SELECT grantee, granted_role, admin_option, default_role 
FROM dba_role_privs 
WHERE grantee NOT IN ('SYS','SYSTEM')
ORDER BY grantee, granted_role;
clear breaks
PROMPT #######################################################################
PROMPT
PROMPT Count of System level privileges granted to users
PROMPT
PROMPT #######################################################################
col USER format a30
select count(*) "COUNT_SYSPRIVS" , grantee "USER", account_status
  from dba_sys_privs, DBA_users
  where username = grantee
 group by grantee, account_status;
col grantee clear
PROMPT #######################################################################
PROMPT
PROMPT Object level Privileges on SYS, SYSTEM, OR DVSYS objects granted to users
PROMPT
PROMPT #######################################################################
COL select format a3 heading SEL
COL insert format a3 heading INS
COL update format a3 heading UPD
COL delete format a3 heading DEL
COL alter format a3 heading ALT
COL references format a3 heading REF
COL index format a3 heading IND
COL execute format a3 heading EXE
break on grantee
SELECT grantee "USER_NAME", owner, table_name, grantor,
       max(decode(privilege,'SELECT','X')) "SELECT",
       max(decode(privilege,'INSERT','X')) "INSERT",
       max(decode(privilege,'UPDATE','X')) "UPDATE",
       max(decode(privilege,'DELETE','X')) "DELETE",
       max(decode(privilege,'ALTER','X')) "ALTER",
       max(decode(privilege,'REFERENCES','X')) "REFERENCES",
       max(decode(privilege,'INDEX','X')) "INDEX",
       max(decode(privilege,'EXECUTE','X')) "EXECUTE"
FROM dba_tab_privs
WHERE (grantee NOT IN (SELECT role FROM dba_roles) 
    AND grantee NOT IN ('LBACSYS','DVSYS')
    AND owner IN ('SYS','SYSTEM')
    AND table_name IN ('USER$','USER_HISTORY$','SOURCE','LINK$','AUD$','FGA_LOG$','KU$_USER_VIEW'))
OR (grantee NOT IN (SELECT role FROM dba_roles)
    AND grantee NOT IN ('DV_GOLDENGATE_ADMIN','DV_XSTREAM_ADMIN','DV_SECANALYST','DV_MONITOR',
                      'DV_ADMIN','DV_OWNER','DV_ACCTMGR','DV_PUBLIC','DV_PATCH_ADMIN','DV_STREAMS_ADMIN',
                      'DV_GOLDENGATE_REDO_ACCESS','DV_REALM_RESOURCE','DV_REALM_OWNER')
    AND owner ='DVSYS')
OR (grantee NOT IN (SELECT role FROM dba_roles)
    AND grantee not in ('DVSYS','PUBLIC')
    AND owner='LBACSYS')
GROUP BY grantee, owner, grantor, table_name
ORDER BY grantee,owner,table_name;
clear breaks
PROMPT #######################################################################
PROMPT
PROMPT Object level Privileges on SYS *$ tables granted to users
PROMPT
PROMPT #######################################################################
col "Col1" format a25 wrap heading "Grantee"
col "Col2" format a25 wrap heading "Table_name"
SELECT DISTINCT GRANTEE "Col1", 'SYS.'||table_name "Col2"
 FROM DBA_TAB_PRIVS WHERE OWNER LIKE 'SYS' AND TABLE_NAME LIKE '%$';
col "Col1" clear
col "Col2" clear
PROMPT #######################################################################
PROMPT
PROMPT EXECUTE privileges on sensitive packages granted to users
PROMPT
PROMPT #######################################################################
break on role_name on owner
SELECT grantee "USER_NAME", owner, table_name, grantor,
       max(decode(privilege,'SELECT','X')) "SELECT",
       max(decode(privilege,'INSERT','X')) "INSERT",
       max(decode(privilege,'UPDATE','X')) "UPDATE",
       max(decode(privilege,'DELETE','X')) "DELETE",
       max(decode(privilege,'ALTER','X')) "ALTER",
       max(decode(privilege,'REFERENCES','X')) "REFERENCES",
       max(decode(privilege,'INDEX','X')) "INDEX",
       max(decode(privilege,'EXECUTE','X')) "EXECUTE"
FROM dba_tab_privs
WHERE table_name IN ('UTL_SMTP','UTL_FILE','UTL_TCP','UTL_HTTP','DBMS_LOB','DBMS_SYS_SQL','DBMS_JOB','DBMS_BACKUP_RESTORE')
GROUP BY grantee, owner, grantor, table_name
ORDER BY grantee,owner,table_name;
clear breaks
PROMPT #######################################################################
PROMPT Sample Schemas in this database
PROMPT #######################################################################
SELECT username, account_status
FROM dba_users
WHERE username IN ('SCOTT','HR','OE','SH','PM');
PROMPT #######################################################################
PROMPT PUBLIC PUBLIC PUBLIC PUBLIC PUBLIC
PROMPT #######################################################################
PROMPT #######################################################################
PROMPT
PROMPT Roles Granted To Public
PROMPT
PROMPT #######################################################################
SELECT * FROM dba_role_privs WHERE grantee = 'PUBLIC' ORDER BY 1
/
PROMPT #######################################################################
PROMPT
PROMPT System Privileges Granted To Public
PROMPT
PROMPT #######################################################################
SELECT * FROM dba_sys_privs WHERE grantee = 'PUBLIC' ORDER BY privilege
/
PROMPT #######################################################################
PROMPT
PROMPT Object Privileges Granted To Public
PROMPT
PROMPT #######################################################################
col grantee format a30
col grantor format a30
break on owner on table_name
SELECT owner, table_name, grantor, grantee,
       max(decode(privilege,'SELECT','X')) "SELECT",
       max(decode(privilege,'INSERT','X')) "INSERT",
       max(decode(privilege,'UPDATE','X')) "UPDATE",
       max(decode(privilege,'DELETE','X')) "DELETE",
       max(decode(privilege,'ALTER','X')) "ALTER",
       max(decode(privilege,'REFERENCES','X')) "REFERENCES",
       max(decode(privilege,'INDEX','X')) "INDEX",
       max(decode(privilege,'EXECUTE','X')) "EXECUTE"
FROM dba_tab_privs
WHERE grantee ='PUBLIC'
and (owner <> 'SYS' AND table_name not LIKE 'java/%')
and (owner <> 'SYS' AND table_name not LIKE 'javax/%')
and (owner <> 'SYS' AND table_name not LIKE '/%')
group by owner, grantor, grantee, table_name
ORDER BY grantee,owner,table_name
/
clear breaks
PROMPT #######################################################################
PROMPT
PROMPT Column Privileges Granted To Public
PROMPT
PROMPT #######################################################################
SELECT substr(grantee,1,length(grantee)) ||':'|| 
substr(owner,1,length(owner)) ||':'|| 
substr(column_name,1,length(column_name)) ||':'|| 
substr(table_name,1,length(table_name)) ||':'|| substr(privilege,1,length(privilege))||':'
"grantee:owner:col:tab:priv"
FROM sys.dba_col_privs
WHERE grantee = 'PUBLIC'
ORDER BY table_name,column_name, privilege,grantee
/
PROMPT #######################################################################
PROMPT PASSWORDS PASSWORDS PASSWORDS PASSWORDS PASSWORDS
PROMPT #######################################################################
PROMPT #######################################################################
PROMPT
PROMPT Password file users
PROMPT
PROMPT #######################################################################
SELECT * FROM sys.v_$pwfile_users ORDER BY 1
/
PROMPT #######################################################################
PROMPT
PROMPT Count of Password Profile Users
PROMPT
PROMPT #######################################################################
SELECT DISTINCT profile, count(*) "NUMBER_USERS_ASSIGNED"
FROM dba_users
GROUP BY profile
ORDER BY 1;
PROMPT #######################################################################
PROMPT
PROMPT List of Password Profiles
PROMPT
PROMPT #######################################################################
col profile format a20
col limit   format a20
break on profile skip 1
SELECT profile, resource_name, limit
FROM   dba_profiles
WHERE  resource_name LIKE '%PASSWORD%'
   OR  resource_name LIKE '%LOGIN%'
ORDER BY 1,2
/
clear breaks
PROMPT #######################################################################
PROMPT
PROMPT List of Password Verify Functions
PROMPT
PROMPT #######################################################################
col text format a70
break on name skip 2
SELECT name, text FROM dba_source WHERE owner='SYS' AND name IN
(SELECT limit FROM dba_profiles WHERE resource_name='PASSWORD_VERIFY_FUNCTION' AND limit <> 'DEFAULT') 
order by name,line;
clear breaks
PROMPT #######################################################################
PROMPT
PROMPT List Resource Profiles
PROMPT
PROMPT #######################################################################
col profile:name:limit format a60
SELECT substr(profile,1,length(profile))||':'|| 
substr(resource_name,1,length(resource_name))||':'||
substr(limit,1,length(limit))||':'
"profile:name:limit"
FROM dba_profiles
WHERE  resource_name not LIKE '%PASSWORD%'
   AND  resource_name not LIKE '%LOGIN%'
ORDER BY profile
/ 
PROMPT #######################################################################
PROMPT
PROMPT Check for passwords in database links
PROMPT
PROMPT #######################################################################
col host for a55
col name for a20
col userid for a15
col password for a20
SELECT name, userid, password, host FROM sys.link$
/
PROMPT #######################################################################
PROMPT
PROMPT Check for 11g databases without 10g verifiers CVE-2012-3137,  
PROMPT   (not valid for 10g and earlier)  MOS note 1492721.1.  Also check SQLNET.ORA for
PROMPT   SQLNET.ALLOWED_LOGON_VERSION=12 if DB version is 11.2.0.3.
PROMPT   Users without password verifiers that are not GLOBAL or EXTERNAL have 
PROMPT     probably been impersonated at some point using an "identified by values" clause
PROMPT
PROMPT #######################################################################
select banner from v$version;
SELECT USERNAME,PASSWORD_VERSIONS, ACCOUNT_STATUS, PASSWORD FROM DBA_USERS order by 3,1;
PROMPT Are passwords case sensitive?
select value from v$parameter where name='sec_case_sensitive_login';
PROMPT #######################################################################
PROMPT
PROMPT Check for default passwords using rainbow table
PROMPT   See output of dfltpass script for more complete results
PROMPT
PROMPT #######################################################################
--Looking for well known verifiers (simplified rainbow table)
SELECT a.name "USERNAME", a.password "PASSWORD_HASH", b.account_status "ACCOUNT_STATUS"
FROM sys.user$ A, dba_users b 
WHERE a.user#=b.user_id 
AND a.password in (
'D0F2982F121C7840', '72CDEF4A3483F60D', '147215F51929A6E8', 'CAC22318F162D597', 'B8B15AC9A946886A', 'F9ED601D936158BD', '1848F0A31D1C5C62', '7910AE63C9F7EEEE', '33C2E27CF5E401A4', 
'8FCB78BBA8A59515', '049B2397FB1A419E', 'B064872E7F344CAE', 'BE89B24F9F8231A9', 'BD821F59270E5F34', '38BC87EB334A1AC4', 'B8527562E504BC3F', 'FE0E8CE7C92504E9', 'EED09A552944B6AD', 
'CB562C240E871070', 'FE84888987A6BF5A', 'E153FFF4DAE6C9F7', '0F886772980B8C79', 'D5DB40BB03EA1270', 'D2E3EF40EE87221E', '78194639B5C3DF9F', '78194639B5C3DF9F', 'A5E09E84EC486FC9', 
'D728438E8A5925E0', '2FFDCBB4FD11D9DC', '7E2C3C2D4BF4071B', '2B0C31040A1CFB48', '5140E342712061DD', '8765D2543274B42E', '4CF13BDAC1D7511C', 'BBBFE175688DED7E', 'B6FD427D08619EEE', 
'1EF8D8BD87CF16BE', '03B20D2C323D0BFE', 'F712D80109E3C9D8', 'CF95D2C6C85FF513', 'F13FF949563EAB3C', '7B83A0860CF3CB71', 'CB4F2CEC5A352488', 'E1BAE6D95AA95F1E', '80C099F0EADF877E', 
'0A8303530E86FCDD', 'AAA18B5D51B0D5AC', 'EAA333E83BF2810D', '9671866348E03616', 'E84CC95CBBAC1B67', 'BF24BCE2409BE1F7', '6026F9A8A54B9468', '7E9901882E5F3565', '2564B34BE50C2524', 
'3DD36935EAEDE2E3', '9435F2E60569158E', 'C9B597D7361EE067', '56DB3E89EAE5788E', 'EB50644BE27DF70B', '2F11631B6B4E0B6F', '652C49CDF955F83A', 'EC481FD7DCE6366A', 'E9473A88A4DD31F2', 
'34200F94830271A3', '397129246919E8DA', 'C6AF8FCA0B51B32F', '7299A5E2A5A05820', '67B891F114BE3AEB', '3A34F0B26B951F3F', 'E39CEFE64B73B308', 'CEAE780F25D556F8', 'C35109FE764ED61E', 
'E7FDFE26A524FE39', '63BF5FFE5E3EA16D', 'A98B26E2F65CA4D3', 'AA71234EF06CE6B3', '7653EBAF048F0A10', 'AA2602921607EE84', '3AA26FC267C5F577', 'BEA52A368C31B86F', '7AAFE7D01511D73F', 
'73F284637A54777D', '402B659C15EAF6CB', 'E3D0DCF4B4DBE626', '04071E7EDEB2F5CC', '0273F484CD3F44B7', 'F165BDE5462AD557', 'DB78866145D4E1C3', 'EDECA9762A8C79CD', '144441CEBAFC91CF', 
'D8CC61E8F42537DA', '684E28B3C899D42C', '71C2B12C28B79294', 'C4D7FE062EFB85AB', '09B4BB013FBD0D65', '5746C5E077719DB4', '0E0F7C1B1FE3FA32', '3C6B8C73DDC6B04F', 'CB6B5E9D9672FE89', 
'71E687F036AD56E5', '24ABAB8B06281B4C', 'CB7B2E6FFDD7976F', 'A219FE4CA25023AA', '82959A9BD2D51297', '21FBCADAEAFCC489', 'AD7862E01FA80912', '41C2D31F3C85A79D', 'C03082CD3B13EC42',
'00A12CC6EBF8EDB8', '9B667E9C5A0D21A6', '5ECB30FD1A71CC54', 'D8FF6ECEF4C50809', 'E066D214D5421CCC', 'F74F7EF36A124931', '4F9FFB093F909574', '4646116A123897CF', '0E7260738FDFD678', 
'EE02531A80D998CA', 'ABFEC5AC2274E54D', '611E7A73EC4B425A', '18A0C8BD6B13BEE2', '46DC27700F2ADE28', 'CE4A36B8E06CA59C', '5C1AED4D1AADAA4C', 'BFBA5A553FD9E28A', 'E53F7C782FAA6898', 
'6869F3CFD027983A', 'E3B6E6006B3A99E0', '5A40D4065B3673D2', 'A410B2C5A0958CDF', 'CE8234D92FCFB563', '8AA1C62E08C76445', 'C5D5C455A1DE5F4D', '6A066C462B62DD46', '0A30645183812087', 
'69CB07E2162C6C93', '4C59B97125B6641A', '313F9DFD92922CD2', 'B40C23C6E2B4EA3D', '4553A3B443FB3207', '05A92C0958AFBCBC', '51063C47AC2628D4', '7CA0A42DA768F96D', '137CEDC20DE69F71',
'637417B1DC47C2E5', '66F4EF5650C20355', 'BAEF9D34973EE4EC', '6A10DD2DB23880CB', '21A837D0AED8F8E5', 'BD63D79ADF5262E7', 'CF39DE29C08F71B9', '6CBBF17292A1B9AA', '8E2713F53A3D69D5', 
'CEE2C4B59E7567A3', '0C0832F8B6897321', '707156934A6318D4', '73E3EC9C0D1FAECF', '9A2A7E2EBE6E4F71', '2ED539F71B4AA697', '2FB4D2C9BAE2CCCA', '907D70C0891A85B1', 'CD6E99DACE4EA3A6', 
'DC7948E807DFE242', 'E269165256F22F01', 'B2F0E221F45A228F', 'A07F1956E3E468E1', '82542940B0CF9C16', '5F1869AD455BBA73', '450793ACFCC7B58E', 'E654261035504804', 'BA787E988F8BC424', 
'9D561E4D6585824B', 'F5AB0AA3197AEE42', '2485287AC1DB6756', '3DE1EBA32154C56B', '855296220C095810', '6399F3B38EDF3288', '4C6D73C3E8B0F0DA', '49A3A09B8FC291D0', '5787B0D15766ADFD', 
'4CEA0BF02214DA55', '169018EB8E2C4A77', '0BD475D5BF449C63', '9D41D2B3DD095227', '840267B7BD30C82E', '0AD9ABABC74B3057', 'F483A48F6A8C51EC', '76B8D54A74465BB4', '7766E887AF4DCC46', 
'739F5BC33AC03043', 'A695699F0F71C300', 'CA39F929AF0A2DEC', '37EF7B2DD17279B5', 'E93196E9196653F1', '30802533ADACFE14', '5D0E790B9E882230', '6CC978F56D21258D', '1DF0D45B58E72097', 
'D33CEB8277F25346', '1740079EFF46AB81', '8C69D50E9D92B9D0', 'DAF602231281B5AC', 'B39565F4E3CF744B', 'E079BF5E433F0B89', 'C7D0B9CDE0B42C73', '8FB1DC9A6F8CE827', 'E4AAF998653C9A72', 
'AB27B53EDC5FEF41', 'E0BF7F3DDE682D3B', 'ACEAB015589CF4BC', 'EB265A08759A15B4', '066A2E3072C1F2F3', '7404A12072F4E5E8', '373F527DC0CFAE98', 'D90F98746B68E6CA', '9AC2B58153C23F3D',
'1CE0B71B4A34904B', 'FBB3209FD6280E69', '37A99698752A1CF1', 'D89D6F9EB78FC841', '489B61E488094A8D', '063BA85BF749DF8E', '29ED3FDC733DC86D', 'B9E99443032F059D', '5C5F6FC2EBB94124', 
'6D79A2259D5B4B5A', '4087EE6EB7F9CD7C', 'CF9CB787BD98DA7F', 'AD0D93891AEB26D2', '0A6B2DF907484CEE', 'AC9700FD3F1410EB', '11E0654A7068559C', 'F0EB74546E22E94D', 'F7101600ACABCD74', 
'4EA68D0DDE8AAC6B', '9C4F452058285A74', 'DF02A496267DEE66', '46DFFB4D08C33739', '564F871D61369A39', 'E5288E225588D11F', '2E175141BEE66FF6', 'B41BCD9D3737F5C4', '72979A94BAD2AF80', 
'E5436F7169B29E4D', 'FC1B0DD35E790847', '9D1F407F3A05BDD9', 'EA514DD74D7DE14C', '5A88CE52084E9700', 'D0EFCD03C95DF106', 'AE128772645F6709', 'A0E2085176E05C85', 'BBFF58334CDEF86D', 
'CF5A081E7585936B', 'B45D4DF02D4E0C85', '89A8C104725367B2', '6A29482069E23675', '3BAA3289DB35813C', 'C9D53D00FE77D813', 'E462DB4671A51CD4', '6465913FF5FF1831', '1E2F06BE2A1D41A6', 
'C5F0512A64EB0E7F', '9B95D28A979CC5C4', '05BFA7FF86D6EB32', '4782D68D42792139', 'FD621020564A4978', '71452E4797DF917B', '8A43574EFB1C71C7', '73A3AC32826558AE', 'A8116DB6E84FA95D', 
'C09011CB0205B347', '2C3A5DEF1EE57E92', 'C252E8FA117AF049', 'A7A32CD03D3CE8D5', '89804494ADFC71BC', 'C6E799A949471F57', '59BBED977430C1A8', 'D1A2DFC623FDA40A', '9C30855E7E0CB02D',
'9DCE98CCF541AAE6', '7BB2F629772BF2E5', 'A01A5F0698FC9E31', '31C1DDF4D5D63FE6', 'B7C1BB95646C16FE', '991C817E5FD0F35A', '6E204632EC7CA65D', 'BB0E28666845FCDC', 'C2B4C76AB8257DF5', 
'F9FDEB0DE52F5D6B', '1AF71599EDACFB00', 'AF52CFD036E8F425', '3B3F6DB781927D0F', '3FB8EF9DB538647C', 'C1510E7AC8F0D90D', '54A85D2A0AB8D865', '9E3C81574654100A', '2AB9032E4483FAFC', 
'D664AAB21CE86FD2', '1BF23812A0AEEDA0', '5A4EEC421DE68DDD', '38E38619A12E0257', 'C37E732953A8ABDB', '2E3EA470A4CA2D94', '28D778112C63CB15', 'F3701A008AA578CF', '17DC8E02BC75C141', 
'133F8D161296CB8F', '63BB534256053305', 'C6EED68A8F75F5D3', '6102BAE530DD4B95', '7C0BE475D580FBA2', '9B616F5489F90AD7', '88A2B2C183431F00', '7EFA02EC7EA6B86F', '05327CD9F6114E21', 
'106AE118841A5D8C', 'C04057049DF974C2', 'F5E498AC7009A217', '4A3BA55E08595C81', 'CA5D67CD878AFC49', '0D9EC1D1F2A37657', '3CBED37697EB01D1', '5C3546B4F9165300', '970B962D942D0C75',
'B650B1BB35E86863', '0DABFF67E0D33623', '8CE2703752DB36D8', '3E7B4116043BEAFF', '0478B8F047DECC65', '35EC0362643ADD3F', 'AC98877DE1297365', 'A68F56FBBCDC04AB', '021B05DBB892D11F', 
'71B5C2271B7CFF18', '99355BF0E53FF635', 'C4522E109BCF69D0', '72E382A52E89575A', 'C7A235E6D2AF6018', 'A7F7978B21A6F65E', 'D40D0FEF9C8DC624', '355CBEC355C10FEF', '6B870AF28F711204', 
'7E15FBACA7CDEBEC', '2AB40F104D8517A0', '123CF56E05D4EF3C', 'A0A3A6A577A931A3', 'D1FB757B6E3D8E2F', '969F9C3839672C6D', 'D373ABE86992BE68', '7AF870D89CABF1C7', 'CFD1302A7F832068', 
'333B8121593F96FB', '42068201613CA6E2', '882B80B587FCDBC8', 'BDE248D4CCCD015D', 'F2C3DC8003BC90F8', '98741BDA2AC7FFB2', '6F6675F272217CF7', '2C5ECE3BEC35CE69', '70C3248DFFB90152', 
'FF4B266F9E61F911', '28EE1E024FC55E66', '4FE07360D435E2F0', '80294AE45A46E77B', 'D6DF5BBC8B64933E', '76224BCC80895D3D', 'C7AEAA2D59EB1EAE', 'AE62CB8167819595', '10A40A72991DCA15', 
'8B09C6075BDF2DC4', '4603BCD2744BDE4F', '991CDDAD5C5C32CA', '3990FB418162F2A0', 'CF9CFACF5AE24964', '870C36D8E6CD7CF5', '7C632AFB71F8D305', '20E788F9D4F1D92C', '91A00922D8C0F146', 
'2CA6D0FC25128CF3', 'E6A6FA4BB042E3C2', '9A5F2D9F5D1A9EF4', 'FF09F3EB14AE5C26', '0EF5997DC2638A61', '24ACF617DD7D8F2F', '0447F2F756B4F460', '933B9A9475E882A6', '2D4B13A8416073A1', 
'88D8F06915B1FE30', 'BD99EC2DD84E3B5C', '57F2A93832685ADB', '915C93F34954F5F8', '0D9D14FE6653CF69', '635074B4416CD3AC', '0FAA06DA0F42F21F', 'FFDF6A0C8C96E676', 'C1959B03F36C9BB2', 
'4B16ACDA351B557D', 'DA4435BBF8CAE54C', 'E7B5D92911C831E1', '5CA8F5380C959CA9', 'E74B15A3F7A19CA8', 'BEAA1036A464F9F0', 'B1344DC1B5F3D903', '58872B4319A76363', 'F894844C34402B67', 
'7AA1A84E31ED7771', 'C789210ACC24DA16', '009BBE8142502E10', '183AC2094A6BD59F', '9793B3777CD3BD1A', '54B253CBBAAA8C48', '84B8CBCA4D477FA3', '061354246A45BBAB', 'FDFE8B904875643D',
'4A0A55000357BB3E', '87470D6CE203FB4D', '6658C384B8D63B0A', 'AEBEDBB4EFB5225B', '4CB05AA42D8E3A47', '783E58C29D2FC7E1', 'E7683741B91AF226', '1FA22316B703EBDD', '12CFB5AE1D087BA3',
'380E3D3AD5CE32D4', '2563EFAAE44E785A', 'E7686462E8CD2F5E', '691C5E7E424B821A', 'D4C5016086B2DC6A', '43BE121A2A135FF3', '8A8F025737A9097A', '4DE42795E66117AE', '66BC3FF56063CE97', 
'57D7CFA12BB5BABF', 'A9A57E819B32A03D', '2905ECA56A830226', '64074AF827F4B74A', '41B328CA13F70713', '0B4409DDD5688913', '6CFF570939041278', '3522F32DD32A9706', 'BE29E31B2B0EDA33', 
'5AC333703DE0DBD4', '5638228DAF52805F', 'BA3E855E93B5B9B0', 'DC86E8DEAA619C1A', '447B729161192C24', '639C32A115D2CA57', '1B9F1F9A5CB9EB31', 'D4DF7931AB130E37', '2D594E86F93B17A1', 
'4861C2264FB17936', '970BAA5B81930A40', '135176FFB5BA07C9', 'E4519FCD3A565446', '66A490AEAA61FF72', '10B0C2DA37E11872', 'D5DD57A09A63AA38', '69C27FA786BA774C', '86FDB286770CD4B9', 
'B171042374D7E6A2', 'D7C18B3B3F2A4D4B', '4438308EE0CAFB7F', 'FAAD7ADAF48B5F45', '685657E9DC29E185', '49B70B505DF0247F', 'B49C4279EBD8D1A8', '604101D3AACE7E88', '02AB2DB93C952A8F', 
'203CD8CF183E716C', '8BF0DA8E551DE1B9', 'F339612C73D27861', '905475E949CF2703', '7C0900F751723768', '9699CFD34358A7A7', '26ED9DD4450DD33C', '7A0F2B316C212D67', 'C0A0F776EBBBB7FB', 
'DE5B73C964C7B67D', '5DCD6E2E26D33A6E', 'ED4CDE954630FA82', 'B516D9A33679F56B', 'F9DA8977092B7B81', '97FD0AE6DFF0F5FE', '29268859446F5A8C', '90C4F894E2972F08', '76F373437F33F347', 
'4C3F880EFA364016', 'F4F306B7AEB5B6FC', '82E7FF841BFEAB6C', '74085BE8A9CF16B4', '96AE343CA71895DA', '8A0760E2710AB0B4', 'BBE7786A584F9103', '1718E5DBB8F89784', '94152F9F5B35B103', 
'2907B1BFA9DA5091', '6E97FCEA92BAA4CB', 'F73E1A76B1E57F3D', '3E9C94488C1A3908', 'D148049C2780B869', '0487AFEE55ECEE66', '1AB4E5FD2217F7AA', '81F2423D6811246D', 'C42D1FA3231AB025', 
'D38D161C22345902', '72A90A786AAE2914', 'DEF637F1D23C0C59', '29ECA1F239B0F7DF', '9A7DCB0C1D84C488', '404B03707BF5CEA3', '571A7090023BCD04', '811C49394C921D66', '3D703795F61E3A9A',
'C69573E9DEC14D50', 'D4C4DCDD41B05A5D', 'F8841A7B16302DE6', 'A97282CE3D94E29E', 'FD0C7DB4C69FA642', 'DD58348364219102', 'C909E4F104002876', '91792EFFCB2464F9', 'D326D25AE0A0355C', 
'29802572EB547DBF', '888203D36F64C5F6', 'AA3CB2A4D9188DDB', 'B97545C4DD2ABE54', '69ED49EE1851900D', '545E13456B7DDEA0', '8B104568E259B370', 'D7837F182995E381', '7C9BA362F8314299', 
'D27FA6297C0313F4', '50D22B9D18547CF7', 'D4D76D217B02BD7A', '750F2B109F49CC13', '6DE993A60BC8DBBF', 'F239A50072154BAC', 'ADBC95D8DCC69E66', '88D8364765FCE6AF', 'F05E53C662835FA2', 
'2A8ED59E27D86D41', 'BD8EA41168F6C664', 'F55561567EF71890', '92776EA17B8B5555', '3D1FB783F96D1F5E', 'FABA49C38150455E', '0D5C9EFC2DFE52BA', 'A43EE9629FA90CAE')
ORDER BY 3,1;
--11g only
PROMPT #######################################################################
PROMPT
PROMPT Check for default passwords using dba_users_with_defpwd
PROMPT
PROMPT #######################################################################
col password format a20
SELECT a.username, b.account_status, b.lock_date, b.created, c.password
FROM DBA_USERS_WITH_DEFPWD A, DBA_USERS B, SYS.USER$ c
WHERE a.username=b.username
and b.username=c.name
ORDER BY 2,1;
PROMPT #######################################################################
PROMPT Check for passwords that are the same as the user name
PROMPT #######################################################################
create or replace function password_hash (username in varchar2, password in varchar2) return varchar2 is
raw_key_v raw(128):= hextoraw('0123456789ABCDEF');
ascii_string_v varchar2(124):='';
uni_string_v raw(128) := '';
hex_string_v varchar2(2048) := '';
raw_string_v raw(2048) :='';
length_v number :=0;
current_char_v char(1);
padd_lenth_v number := 0;
password_hash_raw_v raw(2048) :='';
password_hash_hex_v varchar2(16) := ''; 

begin
length_v:=length(username||password);

for i in 1..length_v loop
current_char_v:=substr(upper(username||password),i,1);
ascii_string_v:=ascii_string_v||chr(0)||current_char_v;
end loop;

length_v:= mod((length_v*2),8);

if (length_v = 0) then
padd_lenth_v:= 0;
else
padd_lenth_v:=8 - length_v;
end if;

for i in 1..padd_lenth_v loop
ascii_string_v:=ascii_string_v||chr(0);
end loop;

uni_string_v:=utl_raw.cast_to_raw(ascii_string_v);
dbms_obfuscation_toolkit.desencrypt(input => uni_string_v, key => raw_key_v, encrypted_data => raw_string_v);
hex_string_v:=rawtohex(raw_string_v);

length_v:=length(hex_string_v);

raw_key_v:=hextoraw(substr(hex_string_v,(length_v-16+1),16));
dbms_obfuscation_toolkit.desencrypt(input => uni_string_v, key => raw_key_v, encrypted_data => password_hash_raw_v);

hex_string_v:=rawtohex(password_hash_raw_v);
length_v:=length(hex_string_v);
password_hash_hex_v:=substr(hex_string_v,(length_v-16+1),16);

return(password_hash_hex_v);
end;
/
select 'User '||a.name||' with account status '||b.account_status||' has a password the same as their username.' "WEAK_PASSWORDS" 
from user$ a, dba_users b
where a.password=password_hash(a.name,a.name)
and a.user#=b.user_id
order by b.account_status, a.name;
drop function password_hash;
PROMPT #######################################################################
PROMPT OBJECTS OBJECTS OBJECTS
PROMPT #######################################################################
PROMPT
PROMPT -----Which constraints have been disabled
PROMPT
PROMPT #######################################################################
SELECT owner, table_name, constraint_type, constraint_name,  last_change, status 
FROM dba_constraints 
WHERE status <> 'ENABLED'
AND owner not in ('SYS','SYSTEM')
ORDER BY owner, table_name;
PROMPT #######################################################################
PROMPT
PROMPT -----Which tables have names columns names like password
PROMPT
PROMPT #######################################################################
col data_type format a15
col column_name format a40
SELECT owner, table_name, column_name, data_type 
FROM dba_tab_columns
WHERE column_name LIKE '%PASSWORD%' OR column_name LIKE '%PWD%'OR column_name LIKE '%PASSWD%'
ORDER by 1,2,3
/
PROMPT
PROMPT ---Roles with access to these possible password tables
PROMPT
break on grantee
SELECT table_name, owner, grantee "ROLE_NAME",  grantor,
       max(decode(privilege,'SELECT','X')) "SELECT",
       max(decode(privilege,'INSERT','X')) "INSERT",
       max(decode(privilege,'UPDATE','X')) "UPDATE",
       max(decode(privilege,'DELETE','X')) "DELETE",
       max(decode(privilege,'ALTER','X')) "ALTER",
       max(decode(privilege,'REFERENCES','X')) "REFERENCES",
       max(decode(privilege,'INDEX','X')) "INDEX",
       max(decode(privilege,'EXECUTE','X')) "EXECUTE"
FROM dba_tab_privs
WHERE (grantee IN (SELECT role FROM dba_roles) 
    AND table_name IN (SELECT distinct table_name 
                       FROM dba_tab_columns
                       WHERE column_name LIKE '%PASSWORD%' OR column_name LIKE '%PWD%'OR column_name LIKE '%PASSWD%'))
GROUP BY grantee, owner, grantor, table_name
ORDER BY owner, table_name, grantee;
clear breaks
PROMPT
PROMPT ---Users with access to these possible password tables
PROMPT
break on grantee
SELECT table_name, owner, grantee "USER_NAME", grantor,
       max(decode(privilege,'SELECT','X')) "SELECT",
       max(decode(privilege,'INSERT','X')) "INSERT",
       max(decode(privilege,'UPDATE','X')) "UPDATE",
       max(decode(privilege,'DELETE','X')) "DELETE",
       max(decode(privilege,'ALTER','X')) "ALTER",
       max(decode(privilege,'REFERENCES','X')) "REFERENCES",
       max(decode(privilege,'INDEX','X')) "INDEX",
       max(decode(privilege,'EXECUTE','X')) "EXECUTE"
FROM dba_tab_privs
WHERE (grantee NOT IN (SELECT role FROM dba_roles) 
    AND table_name IN (SELECT distinct table_name 
                       FROM dba_tab_columns
                       WHERE column_name LIKE '%PASSWORD%' OR column_name LIKE '%PWD%'OR column_name LIKE '%PASSWD%'))
GROUP BY grantee, owner, grantor, table_name
ORDER BY owner,table_name,grantee;
clear breaks
PROMPT #######################################################################
PROMPT
PROMPT -----Which tables have names columns names like SSN
PROMPT
PROMPT #######################################################################
SELECT owner, table_name, column_name, data_type
FROM dba_tab_columns
WHERE column_name LIKE '%TAXPAYER%' OR column_name LIKE '%SSN%'OR column_name LIKE '%SOCIAL%'
ORDER by 1,2,3
/
PROMPT
PROMPT ---Roles with access to these possible SSN tables
PROMPT
break on grantee
SELECT grantee "USER_NAME", owner, table_name, grantor,
       max(decode(privilege,'SELECT','X')) "SELECT",
       max(decode(privilege,'INSERT','X')) "INSERT",
       max(decode(privilege,'UPDATE','X')) "UPDATE",
       max(decode(privilege,'DELETE','X')) "DELETE",
       max(decode(privilege,'ALTER','X')) "ALTER",
       max(decode(privilege,'REFERENCES','X')) "REFERENCES",
       max(decode(privilege,'INDEX','X')) "INDEX",
       max(decode(privilege,'EXECUTE','X')) "EXECUTE"
FROM dba_tab_privs
WHERE (grantee IN (SELECT role FROM dba_roles) 
    AND table_name IN (SELECT distinct table_name 
                       FROM dba_tab_columns
                       WHERE column_name LIKE '%TAXPAYER%' OR column_name LIKE '%SSN%'OR column_name LIKE '%SOCIAL%'))
GROUP BY grantee, owner, grantor, table_name
ORDER BY grantee,owner,table_name;
clear breaks
PROMPT
PROMPT ---Users with access to these possible SSN tables
PROMPT
break on grantee
SELECT table_name, owner, grantee "USER_NAME",  grantor,
       max(decode(privilege,'SELECT','X')) "SELECT",
       max(decode(privilege,'INSERT','X')) "INSERT",
       max(decode(privilege,'UPDATE','X')) "UPDATE",
       max(decode(privilege,'DELETE','X')) "DELETE",
       max(decode(privilege,'ALTER','X')) "ALTER",
       max(decode(privilege,'REFERENCES','X')) "REFERENCES",
       max(decode(privilege,'INDEX','X')) "INDEX",
       max(decode(privilege,'EXECUTE','X')) "EXECUTE"
FROM dba_tab_privs
WHERE (grantee NOT IN (SELECT role FROM dba_roles) 
    AND table_name IN (SELECT distinct table_name 
                       FROM dba_tab_columns
                       WHERE column_name LIKE '%TAXPAYER%' OR column_name LIKE '%SSN%'OR column_name LIKE '%SOCIAL%'))
GROUP BY grantee, owner, grantor, table_name
ORDER BY owner,table_name, grantee;
clear breaks
PROMPT #######################################################################
PROMPT
PROMPT -----Which tables have names columns names like credit card numbers
PROMPT
PROMPT #######################################################################
SELECT owner, table_name, column_name, data_type
FROM dba_tab_columns
WHERE column_name LIKE '%PAN%' OR column_name LIKE '%CREDIT%'OR column_name LIKE '%CARD%'
      OR column_name LIKE '%VISA%' OR column_name LIKE '%CC%'
ORDER by 1,2,3
/
PROMPT
PROMPT ---Roles with access to these possible Credit Card tables
PROMPT
break on grantee
SELECT table_name, owner, grantee "ROLE_NAME", grantor,
       max(decode(privilege,'SELECT','X')) "SELECT",
       max(decode(privilege,'INSERT','X')) "INSERT",
       max(decode(privilege,'UPDATE','X')) "UPDATE",
       max(decode(privilege,'DELETE','X')) "DELETE",
       max(decode(privilege,'ALTER','X')) "ALTER",
       max(decode(privilege,'REFERENCES','X')) "REFERENCES",
       max(decode(privilege,'INDEX','X')) "INDEX",
       max(decode(privilege,'EXECUTE','X')) "EXECUTE"
FROM dba_tab_privs
WHERE (grantee IN (SELECT role FROM dba_roles) 
    AND table_name IN (SELECT distinct table_name 
                       FROM dba_tab_columns
                       WHERE column_name LIKE '%PAN%' OR column_name LIKE '%CREDIT%'OR column_name LIKE '%CARD%'
                             OR column_name LIKE '%VISA%' OR column_name LIKE '%CC%'))
GROUP BY grantee, owner, grantor, table_name
ORDER BY owner,table_name,grantee;
clear breaks
PROMPT
PROMPT ---Users with access to these possible Credit Card tables
PROMPT
break on grantee
SELECT table_name, owner, grantee "USER_NAME", grantor,
       max(decode(privilege,'SELECT','X')) "SELECT",
       max(decode(privilege,'INSERT','X')) "INSERT",
       max(decode(privilege,'UPDATE','X')) "UPDATE",
       max(decode(privilege,'DELETE','X')) "DELETE",
       max(decode(privilege,'ALTER','X')) "ALTER",
       max(decode(privilege,'REFERENCES','X')) "REFERENCES",
       max(decode(privilege,'INDEX','X')) "INDEX",
       max(decode(privilege,'EXECUTE','X')) "EXECUTE"
FROM dba_tab_privs
WHERE (grantee NOT IN (SELECT role FROM dba_roles) 
    AND table_name IN (SELECT distinct table_name 
                       FROM dba_tab_columns
                       WHERE column_name LIKE '%PAN%' OR column_name LIKE '%CREDIT%'OR column_name LIKE '%CARD%'
                             OR column_name LIKE '%VISA%' OR column_name LIKE '%CC%'))
GROUP BY grantee, owner, grantor, table_name
ORDER BY owner,table_name,grantee;
clear breaks
PROMPT #######################################################################
PROMPT LOGIN TRIGGERS LOGIN TRIGGERS LOGIN TRIGGERS
PROMPT #######################################################################
PROMPT
PROMPT Which logon triggers exist?
PROMPT
PROMPT #######################################################################
set long 2000
SELECT trigger_name, status, trigger_body
FROM dba_triggers
WHERE TRIGGERING_EVENT LIKE 'LOGON%'
/
PROMPT #######################################################################
PROMPT VPD VPD VPD VPD VPD VPD VPD VPD VPD
PROMPT #######################################################################
PROMPT
PROMPT Which VPD policies exist?
PROMPT
PROMPT #######################################################################
col policy_owner format a25
col policy_name format a25
col source format a75
break on policy_owner on policy_name skip 1
SELECT policy_owner, policy_name, source
FROM (
SELECT a.owner "POLICY_OWNER", a.name "POLICY_NAME", a.text "SOURCE"
FROM dba_source a, dba_policies b
WHERE a.owner=b.pf_owner
and a.name=b.function
and a.owner <> 'XDB')
/
clear breaks
PROMPT #######################################################################
PROMPT REDACTION REDACTION REDACTION REDACTION
PROMPT #######################################################################
PROMPT
PROMPT Which Data Redaction policies exist?
PROMPT
PROMPT #######################################################################
col object_owner format a25
col object_name format a25
col column_name format a30
col policy_name format a45
break on object_owner skip 1
SELECT object_owner, object_name, policy_name FROM redaction_policies ORDER BY 1,2;
SELECT object_owner, object_name, column_name, function_type FROM redaction_columns ORDER BY 1,2; 
clear breaks
PROMPT #######################################################################
PROMPT ENCRYPTION ENCRYPTION ENCRYPTION ENCRYPTION
PROMPT #######################################################################
PROMPT
PROMPT Encryption Wallet
PROMPT
PROMPT #######################################################################
col WRL_PARAMETER format a45
SELECT * FROM sys.v$encryption_wallet
/
PROMPT #######################################################################
PROMPT
PROMPT Encrypted Columns
PROMPT
PROMPT #######################################################################
col OWNER format a20
col TABLE_NAME format a25
col COLUMN_NAME format a25
SELECT * FROM DBA_ENCRYPTED_COLUMNS;
/
PROMPT #######################################################################
PROMPT
PROMPT Encrypted Tablespaces
PROMPT
PROMPT #######################################################################
col NAME format a25
SELECT a.name, a.encrypt_in_backup "BACKUP", b.encryptedts "ENCRYPTED", b.ENCRYPTIONALG "ALGORITHM" 
FROM v$tablespace a, v$encrypted_tablespaces b
WHERE a.ts#=b.ts#;
PROMPT #######################################################################
PROMPT
PROMPT Tables in Encrypted Tablespaces
PROMPT
PROMPT #######################################################################
col NAME format a25
SELECT a.owner "OWNER", a.table_name "TABLE_NAME", c.name "TABLESPACE", a.num_rows "ROWCOUNT", b.encryptionalg "ALGORITHM"
FROM dba_tables a, v$encrypted_tablespaces b, v$tablespace c
WHERE a.tablespace_name=c.name
AND c.TS#=b.TS#
ORDER BY 1,2;
PROMPT #######################################################################
PROMPT CONFIGURATION CONFIGURATION CONFIGURATION CONFIGURATION
PROMPT #######################################################################
PROMPT #######################################################################
PROMPT
PROMPT Listing of parameters
PROMPT
PROMPT #######################################################################
col name format a37
col value format a60
SELECT name, value, isdefault
FROM v$parameter
ORDER BY isDefault, name
/ 
PROMPT #######################################################################
PROMPT
PROMPT Listing of Java Permissions
PROMPT
PROMPT #######################################################################
col action format a35
col grantee format a30
SELECT grantee, kind, type_name, type_schema, name, action FROM dba_java_policy
WHERE grantee not LIKE 'JAVA%' AND grantee <> 'SYS'
ORDER BY grantee
/
PROMPT #######################################################################
PROMPT #######################################################################
PROMPT NETWORKING NETWORKING NETWORKING
PROMPT #######################################################################
PROMPT #######################################################################
PROMPT
PROMPT -----Check for external procedures
PROMPT
PROMPT #######################################################################
col agent format a20
col leaf_filename format a30
col library_name format a30
col file_spec format a40
SELECT * FROM dba_libraries WHERE file_spec IS NOT null;
PROMPT
PROMPT -----Check status of network permissions (11g)
PROMPT
PROMPT #######################################################################
col host format a25
col ACL format a50
col principal format a40
col privilege format a25
SELECT host, lower_port, upper_port, ACL FROM dba_network_acls;
SELECT acl, principal, privilege, is_grant, invert, trunc(start_date) "START_DATE", trunc(end_date) "END_DATE" from dba_network_acl_privileges;
PROMPT
PROMPT #######rompt################################################################
PROMPT -----GET XML ACL from XDB
Prompt ====================
col xml_acl format a80
SELECT to_char(XMLTYPE.getclobval (SYS_NC_ROWINFO$))||CHR(13)||' END OF FILE'||CHR(13) XML_ACL FROM xdb.xdb$ACL;
col xml_acl clear
PROMPT #######################################################################
PROMPT #######################################################################
PROMPT PATCHING PATCHING PATCHING
PROMPT #######################################################################
PROMPT #######################################################################
PROMPT
PROMPT -----Check for PSU/CPU
PROMPT
PROMPT #######################################################################
col comments format a60
col DATE_APPLIED format DD-MMM-YYYY
SELECT trunc(action_time) DATE_APPLIED, comments FROM dba_registry_history;
PROMPT #######################################################################
Prompt Patchsets from sysman.mgmt$applied_patchsets
PROMPT #######################################################################
col version format a11
col name format a50
col host format a30
col home_name format a20
select version,
       name,
       host,
       home_name
  from sysman.mgmt$applied_patchsets;
col version clear
col name clear
col host clear
col home_name clear
PROMPT #######################################################################
Prompt Patches from sysman.mgmt.applied_patches
PROMPT #######################################################################
col patch format a11
col bugs format a11
col host format a20
select Patch, 
       Bugs,
       host,
       installation_time
from sysman.mgmt$applied_patches;
col patch clear
col bugs clear
col host clear
Prompt
PROMPT #######################################################################
Prompt Patches from registry$history
PROMPT #######################################################################
SET linesize 200 pagesize 200
col action_time format a28
col version format a10
col comments format a35
col action format a25
col namespace format a12
col bundle_series format a14
col action format a8
SELECT * FROM registry$history;
clear col
PROMPT #######################################################################
PROMPT
PROMPT Tests for specific vulnerabilities
PROMPT
PROMPT #######################################################################
Prompt test for CVE-2012-3132: Get SYSDBA rights
Prompt ========================================================
Prompt
Prompt USERS, which could maybe use this EXPLOIT
Prompt CREATE TABLE, CREATE PROC, EXECUTE CTX_DDL, DBMS_STAT
Prompt ========================================================
col owner format a30
col table_name format a30
col privilege format a30
col grantee format a30
SELECT * from (select NULL OWNER, 'SYSTEM PRIV' TABLE_NAME, privilege, grantee from dba_sys_privs 
 where privilege in ('CREATE TABLE','CREATE PROCEDURE', 'CREATE ANY TABLE','CREATE ANY PROCEDURE') 
UNION 
select owner, 
       table_name, 
       privilege, 
       grantee
  from dba_tab_privs
where  privilege = 'EXECUTE' and table_name in ('DBMS_STATS', 'CTX_DDL')
)
order by grantee, privilege;
col owner clear
col table_name clear
col privilege clear
col grantee clear                  
Prompt
Prompt END: CVE-2012-3132: Get SYSDBA rights
PROMPT #######################################################################
set verif on
Prompt ## Test for OJVM vulnerability - CVE-2014-6546-7,CVE-2014-6545, CVE-2014-6453, CVE-2014-6450, CVE-2014-6537 ##
Prompt Remediated with Oct 2014 CPU
--- OJVM test developed by richard.c.evans
Prompt Checks for Patch 19721304 - if Oct 2014 or higher CPU is not present this is important
Prompt The mitigation patch steps will prevent creation of any new stored Java in the database.
Prompt This includes attempts to create Java objects from SQL, import, loadjava, etc..
Prompt Check if the patch is registered in the inventory
host echo $ORACLE_HOME/OPatch/opatch lsinventory | grep 19721304  >> dbra_main_$ORACLE_SID.out
Prompt The patch creates a role to allow creation/modification of Java Objects
select count(*) from dba_roles where role = 'ORACLE_JAVA_DEV';
Prompt  Check the status of Java Development in the DB.  We want this to say NO.
Prompt  If it is not, the customer should disable it by executing "exec dbms_java_dev.disable;"
column java_dev_allowed format a18
select * from sys.java_dev_status;
Prompt END: CVE-2014-6546-7,CVE-2014-6545, CVE-2014-6453, CVE-2014-6450, CVE-2014-6537: OJVM Vulnerability
set lines 150
PROMPT
PROMPT #######################################################################
Prompt ## Test for DUAL Public Privileges vulnerability - CVE-2015-0393 ##
Prompt Remediated with Jan 2015 CPU
PROMPT
Prompt Check to see if any privileges other than select are granted to public on DUAL
Prompt 
SELECT 'revoke ' || privilege || ' ON sys.dual FROM public;' "SQL"
FROM sys.dba_tab_privs
WHERE owner = 'SYS' AND table_name = 'DUAL' AND grantee = 'PUBLIC' AND privilege != 'SELECT';
Prompt
Prompt Check to see if any function-based indexes have already been created on DUAL
Prompt
SELECT owner "OWNER", index_name "NAME", index_type "TYPE", FUNCIDX_STATUS "STATUS" from DBA_INDEXES 
WHERE table_owner = 'SYS' AND table_name = 'DUAL' AND upper(index_type) like 'FUNCTION%';
Prompt
Prompt END: CVE-2015-0393: Dual Public Privileges
spool off
host sleep 5
host echo '#######################################################################' >> dbra_main_$ORACLE_SID.out
host echo '----------------------OS level checks----------------------------------' >> dbra_main_$ORACLE_SID.out
host echo '#######################################################################' >> dbra_main_$ORACLE_SID.out
host echo '###-----Check for ShellShock BASH bug' >> dbra_main_$ORACLE_SID.out
host echo 'Testing for simple shellshock vulnerability' >> dbra_main_$ORACLE_SID.out
host env x='() { :;}; echo shellshock vulnerable' bash -c 'echo first ShellShock Test done' >> dbra_main_$ORACLE_SID.out
host echo 'Another shellshock test' >> dbra_main_$ORACLE_SID.out
host env ls="() { echo 'shellshock auto-import vulnerable'; }" bash -c "ls /nosuchdir" >> dbra_main_$ORACLE_SID.out
host echo 'End of Shellshock testing' >> dbra_main_$ORACLE_SID.out
host echo '#######################################################################' >> dbra_main_$ORACLE_SID.out
host echo '###--Check patches applied to the database' >> dbra_main_$ORACLE_SID.out
host echo '#######################################################################' >> dbra_main_$ORACLE_SID.out
host $ORACLE_HOME/OPatch/opatch lsinventory  >> dbra_main_$ORACLE_SID.out
host echo '#######################################################################' >> dbra_main_$ORACLE_SID.out
host echo '###--Check file permissions' >> dbra_main_$ORACLE_SID.out
host echo '#######################################################################' >> dbra_main_$ORACLE_SID.out
host ls -l $ORACLE_HOME/bin/oracle >> dbra_main_$ORACLE_SID.out
host ls -l $ORACLE_HOME/bin/sqlplus >> dbra_main_$ORACLE_SID.out
host ls -l $ORACLE_HOME/bin/tkprof >> dbra_main_$ORACLE_SID.out
host echo '#######################################################################' >> dbra_main_$ORACLE_SID.out
host echo '###--Who runs Oracle Processes?' >> dbra_main_$ORACLE_SID.out
host echo '#######################################################################' >> dbra_main_$ORACLE_SID.out
host ps -ef |grep pmon | grep -v grep >> dbra_main_$ORACLE_SID.out
host ps -ef |grep tnslsnr | grep -v grep >> dbra_main_$ORACLE_SID.out
host ps -ef |grep agent | grep -v grep >> dbra_main_$ORACLE_SID.out
host echo '#######################################################################' >> dbra_main_$ORACLE_SID.out
host echo '###--Check for OS Users that can startup, shutdown AND admin Oracle Databases' >> dbra_main_$ORACLE_SID.out
host echo '#######################################################################' >> dbra_main_$ORACLE_SID.out
host echo '###/etc/passwd' >> dbra_main_$ORACLE_SID.out
host cat /etc/passwd >> dbra_main_$ORACLE_SID.out
host echo '###/etc/group' >> dbra_main_$ORACLE_SID.out
host cat /etc/group >> dbra_main_$ORACLE_SID.out
host echo '#######################################################################' >> dbra_main_$ORACLE_SID.out
host echo '###--Check listener security level' >> dbra_main_$ORACLE_SID.out
host echo '#######################################################################' >> dbra_main_$ORACLE_SID.out
host ls -l $ORACLE_HOME/bin/lsnrctl  >> dbra_main_$ORACLE_SID.out
host echo '###default Listener Status' >> dbra_main_$ORACLE_SID.out
host $ORACLE_HOME/bin/lsnrctl status  >> dbra_main_$ORACLE_SID.out
host echo '###SQLNET.ORA FROM ORACLE_HOME' >> dbra_main_$ORACLE_SID.out
host cat $ORACLE_HOME/network/admin/sqlnet.ora  >> dbra_main_$ORACLE_SID.out
host echo '###SQLNET.ORA FROM TNS_ADMIN' >> dbra_main_$ORACLE_SID.out
host cat $TNS_ADMIN/sqlnet.ora  >> dbra_main_$ORACLE_SID.out
host echo '###LISTENER.ORA FROM ORACLE_HOME' >> dbra_main_$ORACLE_SID.out
host cat $ORACLE_HOME/network/admin/listener.ora  >> dbra_main_$ORACLE_SID.out
host echo '###LISTENER.ORA FROM TNS_ADMIN' >> dbra_main_$ORACLE_SID.out
host cat $TNS_ADMIN/listener.ora  >> dbra_main_$ORACLE_SID.out
host echo '#######################################################################' >> dbra_main_$ORACLE_SID.out
host echo '###Check DB Password File Permissions' >> dbra_main_$ORACLE_SID.out
host echo '#######################################################################' >> dbra_main_$ORACLE_SID.out
host ls -l $ORACLE_HOME/dbs  >> dbra_main_$ORACLE_SID.out
host echo '#######################################################################' >> dbra_main_$ORACLE_SID.out
host echo '###Check network listeners' >> dbra_main_$ORACLE_SID.out
host echo '#######################################################################' >> dbra_main_$ORACLE_SID.out
host netstat -lptuxn |grep -i LISTEN | grep -v grep >> dbra_main_$ORACLE_SID.out
host ps -ef |grep -i ftp |grep -v grep >> dbra_main_$ORACLE_SID.out
host echo '#######################################################################' >> dbra_main_$ORACLE_SID.out
host echo '###Check VNC Servers' >> dbra_main_$ORACLE_SID.out
host echo '#######################################################################' >> dbra_main_$ORACLE_SID.out
host ps -ef |grep -i vnc | grep -v grep >> dbra_main_$ORACLE_SID.out
host echo '#######################################################################' >> dbra_main_$ORACLE_SID.out
host echo '###End of OS level checks' >> dbra_main_$ORACLE_SID.out
host echo '#######################################################################' >> dbra_main_$ORACLE_SID.out
host echo '#######################################################################' >> dbra_main_$ORACLE_SID.out
host echo 'END END END END END END END END END END END END' >> dbra_main_$ORACLE_SID.out
host echo '#######################################################################' >> dbra_main_$ORACLE_SID.out
PROMPT  *********************END OF RISK ASSESSMENT SCRIPT************************
PROMPT  **************************************************************************
exit
