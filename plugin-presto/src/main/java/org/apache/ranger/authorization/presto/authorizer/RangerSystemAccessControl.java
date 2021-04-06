/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.ranger.authorization.presto.authorizer;

import io.prestosql.spi.connector.CatalogSchemaName;
import io.prestosql.spi.connector.CatalogSchemaRoutineName;
import io.prestosql.spi.connector.CatalogSchemaTableName;
import io.prestosql.spi.connector.SchemaTableName;
import io.prestosql.spi.security.*;
import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.policyengine.RangerPolicyEngine;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.Principal;
import java.util.*;

import static io.prestosql.spi.security.AccessDeniedException.denyShowColumns;
import static io.prestosql.spi.security.AccessDeniedException.denyShowTables;
import static java.util.Locale.ENGLISH;

public class RangerSystemAccessControl
  implements SystemAccessControl {

  public static String RANGER_CONFIG_KEYTAB = "ranger.keytab";
  public static String RANGER_CONFIG_PRINCIPAL = "ranger.principal";
  final public static String RANGER_CONFIG_USE_UGI = "ranger.use_ugi";
  public static String RANGER_PRESTO_SERVICETYPE = "presto";
  public static String RANGER_PRESTO_APPID = "presto";

  private static Logger LOG = LoggerFactory.getLogger(RangerSystemAccessControl.class);

  private RangerBasePlugin rangerPlugin;

  public RangerSystemAccessControl(Map<String, String> config) {
    super();

    if (config.get(RANGER_CONFIG_KEYTAB) != null && config.get(RANGER_CONFIG_PRINCIPAL) != null) {
      String keytab = config.get(RANGER_CONFIG_KEYTAB);
      String principal = config.get(RANGER_CONFIG_PRINCIPAL);

      LOG.info("Performing kerberos login with principal " + principal + " and keytab " + keytab);

      try {
        UserGroupInformation.setConfiguration(new Configuration());
        UserGroupInformation.loginUserFromKeytab(principal, keytab);
      } catch (IOException ioe) {
        LOG.error("Kerberos login failed", ioe);
        throw new RuntimeException(ioe);
      }
    }
    rangerPlugin = new RangerBasePlugin(RANGER_PRESTO_SERVICETYPE, RANGER_PRESTO_APPID);
    rangerPlugin.init();
    rangerPlugin.setResultProcessor(new RangerDefaultAuditHandler());
  }

  private boolean checkPermission(RangerPrestoResource resource, Identity identity, PrestoAccessType accessType) {
    boolean ret = false;

    UserGroupInformation ugi = UserGroupInformation.createRemoteUser(identity.getUser());

    String[] groups = ugi != null ? ugi.getGroupNames() : null;

    Set<String> userGroups = null;
    if (groups != null && groups.length > 0) {
      userGroups = new HashSet<>(Arrays.asList(groups));
    }

    RangerPrestoAccessRequest request = new RangerPrestoAccessRequest(
      resource,
      identity.getUser(),
      userGroups,
      accessType
    );

    RangerAccessResult result = rangerPlugin.isAccessAllowed(request);
    if (result != null)  {
      LOG.info("\n result: " + result.toString() + "\n request: " + request.toString() + "\n");
    } else {
      LOG.info("result is NULL!" + "request:\n" + request.toString());
    }

    if (result != null && result.getIsAllowed()) {
      ret = true;
    }

    return ret;
  }

    @Override
    public void checkCanImpersonateUser(SystemSecurityContext context, String userName)
    {
      if(LOG.isDebugEnabled()) {
        LOG.debug("==> RangerSystemAccessControl.checkCanImpersonateUser(context.User:" + context.getIdentity().getUser() + " userName:"+ userName + ")");
      }
      if (!context.getIdentity().getUser().contains(userName)) {
        LOG.info("==> RangerSystemAccessControl.checkCanImpersonateUser(context.User:" + context.getIdentity().getUser() + " not contains userName:"+ userName + ")");
        AccessDeniedException.denyImpersonateUser(context.getIdentity().getUser(), userName);
      }
    }

  @Override
  public void checkCanSetUser(Optional<Principal> principal, String userName) {
    if(LOG.isDebugEnabled()) {
      LOG.debug("==> RangerSystemAccessControl.checkCanSetUser(" + userName + ")");
    }

    /*
    if (!principal.isPresent()) {
      //AccessDeniedException.denySetUser(principal, userName);
    }*/

    //AccessDeniedException.denySetUser(principal, userName);
  }

  @Override
  public void  checkCanExecuteQuery(SystemSecurityContext context){
    if(LOG.isDebugEnabled()) {
      LOG.debug("==> RangerSystemAccessControl.checkCanExecuteQuery default accessed.");
    }
  }

  @Override
  public void checkCanViewQueryOwnedBy(SystemSecurityContext context, String queryOwner)
  {
    if(LOG.isDebugEnabled()) {
      LOG.debug("==> RangerSystemAccessControl.checkCanViewQueryOwnedBy ( "+ queryOwner+" )");
    }
  }

  @Override
  public void checkCanKillQueryOwnedBy(SystemSecurityContext context, String queryOwner)
  {
    if(LOG.isDebugEnabled()) {
      LOG.debug("==> RangerSystemAccessControl.checkCanKillQueryOwnedBy ( "+ queryOwner+" )");
    }
  }

  @Override
  public void checkCanSetSystemSessionProperty(SystemSecurityContext context, String propertyName) {
    if (!checkPermission(new RangerPrestoResource(), context.getIdentity(), PrestoAccessType.ADMIN)) {
      LOG.info("==> RangerSystemAccessControl.checkCanSetSystemSessionProperty denied");
      AccessDeniedException.denySetSystemSessionProperty(propertyName);
    }
  }

  @Override
  public void checkCanAccessCatalog(SystemSecurityContext context, String catalogName) {
    if (!checkPermission(createResource(catalogName), context.getIdentity(), PrestoAccessType.USE)) {
      LOG.info("==> RangerSystemAccessControl.checkCanAccessCatalog(" + catalogName + ") denied");
      AccessDeniedException.denyCatalogAccess(catalogName);
    }
  }

  @Override
  public Set<String> filterCatalogs(SystemSecurityContext context, Set<String> catalogs) {
    return catalogs;
  }

  @Override
  public void checkCanCreateSchema(SystemSecurityContext context, CatalogSchemaName schema) {
    if (!checkPermission(createResource(schema.getCatalogName(), schema.getSchemaName()), context.getIdentity(), PrestoAccessType.CREATE)) {
      LOG.info("==> RangerSystemAccessControl.checkCanCreateSchema(" + schema.getSchemaName() + ") denied");
      AccessDeniedException.denyCreateSchema(schema.getSchemaName());
    }
  }

  @Override
  public void checkCanDropSchema(SystemSecurityContext context, CatalogSchemaName schema) {
    if (!checkPermission(createResource(schema.getCatalogName(), schema.getSchemaName()), context.getIdentity(), PrestoAccessType.DROP)) {
      LOG.info("==> RangerSystemAccessControl.checkCanDropSchema(" + schema.getSchemaName() + ") denied");
      AccessDeniedException.denyDropSchema(schema.getSchemaName());
    }
  }

    @Override
    public void checkCanSetSchemaAuthorization(SystemSecurityContext context, CatalogSchemaName schema, PrestoPrincipal principal)
    {
        if (!checkPermission(new RangerPrestoResource(), context.getIdentity(), PrestoAccessType.ADMIN)) {
            LOG.info("==> RangerSystemAccessControl.checkCanSetSchemaAuthorization denied");
            AccessDeniedException.denySetSchemaAuthorization(schema.getSchemaName(), principal);
        }
    }

  @Override
  public void checkCanRenameSchema(SystemSecurityContext context, CatalogSchemaName schema, String newSchemaName) {
    RangerPrestoResource res = createResource(schema.getCatalogName(), schema.getSchemaName());
    if (!checkPermission(res, context.getIdentity(), PrestoAccessType.ALTER)) {
      LOG.info("==> RangerSystemAccessControl.checkCanRenameSchema(" + schema.getSchemaName() + ") denied");
      AccessDeniedException.denyRenameSchema(schema.getSchemaName(), newSchemaName);
    }
  }

  @Override
  public void checkCanShowSchemas(SystemSecurityContext context, String catalogName) {
    if (!checkPermission(createResource(catalogName), context.getIdentity(), PrestoAccessType.SELECT)) {
      LOG.info("==> RangerSystemAccessControl.checkCanShowSchemas(" + catalogName + ") denied");
      AccessDeniedException.denyShowSchemas(catalogName);
    }
  }

  @Override
  public Set<String> filterSchemas(SystemSecurityContext context, String catalogName, Set<String> schemaNames) {
    LOG.debug("==> RangerSystemAccessControl.filterSchemas(" + catalogName + ")");
    return schemaNames;
  }

  @Override
  public void checkCanCreateTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    if (!checkPermission(createResource(table), context.getIdentity(), PrestoAccessType.CREATE)) {
      LOG.info("==> RangerSystemAccessControl.checkCanCreateTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyCreateTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanDropTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    if (!checkPermission(createResource(table), context.getIdentity(), PrestoAccessType.DROP)) {
      LOG.info("==> RangerSystemAccessControl.checkCanDropTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyDropTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public  void checkCanShowCreateTable(SystemSecurityContext context, CatalogSchemaTableName table)
  {
      if (!checkPermission(createResource(table.getCatalogName(),table.getSchemaTableName().getSchemaName(), table.getSchemaTableName().getTableName()), context.getIdentity(), PrestoAccessType.SELECT)) {
          LOG.info("==> RangerSystemAccessControl.checkCanShowCreateTable(" + table.getSchemaTableName().getTableName() + ") denied");
          AccessDeniedException.denyShowCreateTable(table.getSchemaTableName().getTableName());
      }
  }

  @Override
  public void checkCanRenameTable(SystemSecurityContext context, CatalogSchemaTableName table, CatalogSchemaTableName newTable) {
    RangerPrestoResource res = createResource(table);
    if (!checkPermission(res, context.getIdentity(), PrestoAccessType.ALTER)) {
      LOG.info("==> RangerSystemAccessControl.checkCanRenameTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyRenameTable(table.getSchemaTableName().getTableName(), newTable.getSchemaTableName().getTableName());
    }
  }

//  @Override
//  public void checkCanShowTablesMetadata(SystemSecurityContext context, CatalogSchemaName schema) {
//    if (!checkPermission(createResource(schema.getCatalogName(), schema.getSchemaName()), context.getIdentity(), PrestoAccessType.SELECT)) {
//      LOG.info("==> RangerSystemAccessControl.checkCanShowTablesMetadata(" + schema.getSchemaName() + ") denied");
//      AccessDeniedException.denyShowTablesMetadata(schema.getSchemaName());
//    }
//  }

  @Override
  public void checkCanShowTables(SystemSecurityContext context, CatalogSchemaName schema)
  {
    if (!checkPermission(createResource(schema.getCatalogName(), schema.getSchemaName()), context.getIdentity(), PrestoAccessType.SELECT)) {
      LOG.info("==> RangerSystemAccessControl.checkCanShowTables(" + schema.getSchemaName() + ") denied");
      denyShowTables(schema.getSchemaName());
    }
  }

    @Override
    public void checkCanShowColumns(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!checkPermission(createResource(table.getCatalogName(), table.getSchemaTableName().getSchemaName(),table.getSchemaTableName().getTableName()), context.getIdentity(), PrestoAccessType.SELECT)) {
            LOG.info("==> RangerSystemAccessControl.checkCanShowColumns(" +  table.getSchemaTableName().getTableName() + ") denied");
            denyShowColumns(table.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanSetTableComment(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!checkPermission(new RangerPrestoResource(), context.getIdentity(), PrestoAccessType.ALTER)) {
            LOG.info("==> RangerSystemAccessControl.checkCanSetTableComment denied");
            AccessDeniedException.denyCommentTable(table.getSchemaTableName().getTableName());
        }
    }

  @Override
  public Set<SchemaTableName> filterTables(SystemSecurityContext context, String catalogName, Set<SchemaTableName> tableNames) {
    LOG.debug("==> RangerSystemAccessControl.filterTables(" + catalogName + ")");
    return tableNames;
  }

  @Override
  public void checkCanAddColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
    RangerPrestoResource res = createResource(table);
    if (!checkPermission(res, context.getIdentity(), PrestoAccessType.ALTER)) {
      AccessDeniedException.denyAddColumn(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanDropColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
    RangerPrestoResource res = createResource(table);
    if (!checkPermission(res, context.getIdentity(), PrestoAccessType.ALTER)) {
      LOG.info("==> RangerSystemAccessControl.checkCanDropColumn(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyDropColumn(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanRenameColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
    RangerPrestoResource res = createResource(table);
    if (!checkPermission(res, context.getIdentity(), PrestoAccessType.ALTER)) {
      LOG.info("==> RangerSystemAccessControl.checkCanRenameColumn(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyRenameColumn(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns) {
    for (RangerPrestoResource res : createResource(table, columns)) {
      if (!checkPermission(res, context.getIdentity(), PrestoAccessType.SELECT)) {
        LOG.info("==> RangerSystemAccessControl.checkCanSelectFromColumns(" + table.getSchemaTableName().getTableName() + ") denied");
        AccessDeniedException.denySelectColumns(table.getSchemaTableName().getTableName(), columns);
      }
    }
  }

  @Override
  public void checkCanInsertIntoTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    RangerPrestoResource res = createResource(table);
    if (!checkPermission(res, context.getIdentity(), PrestoAccessType.INSERT)) {
      LOG.info("==> RangerSystemAccessControl.checkCanInsertIntoTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyInsertTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanDeleteFromTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    if (!checkPermission(createResource(table), context.getIdentity(), PrestoAccessType.DELETE)) {
      LOG.info("==> RangerSystemAccessControl.checkCanDeleteFromTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyDeleteTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanCreateView(SystemSecurityContext context, CatalogSchemaTableName view) {
    if (!checkPermission(createResource(view), context.getIdentity(), PrestoAccessType.CREATE)) {
      LOG.info("==> RangerSystemAccessControl.checkCanCreateView(" + view.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyCreateView(view.getSchemaTableName().getTableName());
    }
  }

    @Override
    public void checkCanRenameView(SystemSecurityContext context, CatalogSchemaTableName view, CatalogSchemaTableName newView)
    {
        if (!checkPermission(createResource(view), context.getIdentity(), PrestoAccessType.ALTER)) {
            LOG.info("==> RangerSystemAccessControl.checkCanRenameView(" + view.getSchemaTableName().getTableName() + ") denied");
            AccessDeniedException.denyCreateView(view.getSchemaTableName().getTableName());
        }
    }

  @Override
  public void checkCanDropView(SystemSecurityContext context, CatalogSchemaTableName view) {
    if (!checkPermission(createResource(view), context.getIdentity(), PrestoAccessType.DROP)) {
      LOG.info("==> RangerSystemAccessControl.checkCanDropView(" + view.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyCreateView(view.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanCreateViewWithSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns) {
    for (RangerPrestoResource res : createResource(table, columns)) {
      if (!checkPermission(res, context.getIdentity(), PrestoAccessType.CREATE)) {
        LOG.info("==> RangerSystemAccessControl.checkCanCreateViewWithSelectFromColumns(" + table.getSchemaTableName().getTableName() + ") denied");
        AccessDeniedException.denyCreateViewWithSelect(table.getSchemaTableName().getTableName(), context.getIdentity());
      }
    }
  }

  @Override
  public void checkCanSetCatalogSessionProperty(SystemSecurityContext context, String catalogName, String propertyName) {
    if (!checkPermission(createResource(catalogName), context.getIdentity(), PrestoAccessType.ADMIN)) {
      LOG.info("==> RangerSystemAccessControl.checkCanSetCatalogSessionProperty(" + catalogName + ") denied");
      AccessDeniedException.denySetCatalogSessionProperty(catalogName, propertyName);
    }
  }

    @Override
    public void checkCanGrantExecuteFunctionPrivilege(SystemSecurityContext context, String functionName, PrestoPrincipal grantee, boolean grantOption)
    {
        if (!checkPermission(createFunctionResource(functionName), context.getIdentity(), PrestoAccessType.ADMIN)) {
            LOG.info("==> RangerSystemAccessControl.checkCanGrantExecuteFunctionPrivilege(" + functionName + ") denied");
            AccessDeniedException.denyGrantExecuteFunctionPrivilege(functionName, context.getIdentity(), grantee.getName());
        }
    }

  @Override
  public void checkCanGrantTablePrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaTableName table, PrestoPrincipal grantee, boolean withGrantOption) {
    if (!checkPermission(createResource(table), context.getIdentity(), PrestoAccessType.ADMIN)) {
      LOG.info("==> RangerSystemAccessControl.checkCanGrantTablePrivilege(" + table + ") denied");
      AccessDeniedException.denyGrantTablePrivilege(privilege.toString(), table.toString());
    }
  }

  @Override
  public void checkCanRevokeTablePrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaTableName table, PrestoPrincipal revokee, boolean grantOptionFor) {
    if (!checkPermission(createResource(table), context.getIdentity(), PrestoAccessType.ADMIN)) {
      LOG.info("==> RangerSystemAccessControl.checkCanRevokeTablePrivilege(" + table + ") denied");
      AccessDeniedException.denyRevokeTablePrivilege(privilege.toString(), table.toString());
    }
  }

    @Override
    public void checkCanExecuteProcedure(SystemSecurityContext systemSecurityContext, CatalogSchemaRoutineName procedure)
    {
        if (!checkPermission(createProcedureResource(procedure), systemSecurityContext.getIdentity(), PrestoAccessType.SELECT)) {
            LOG.info("==> RangerSystemAccessControl.checkCanExecuteProcedure(" + procedure.toString() + ") denied");
            AccessDeniedException.denyExecuteProcedure(procedure.toString());
        }
    }

    @Override
    public void checkCanExecuteFunction(SystemSecurityContext systemSecurityContext, String functionName)
    {
        if (!checkPermission(createFunctionResource(functionName), systemSecurityContext.getIdentity(), PrestoAccessType.SELECT)) {
            LOG.info("==> RangerSystemAccessControl.checkCanExecuteFunction(" + functionName + ") denied");
            AccessDeniedException.denyExecuteFunction(functionName);
        }
    }

  @Override
  public void checkCanShowRoles(SystemSecurityContext context, String catalogName) {
    if (!checkPermission(createResource(catalogName), context.getIdentity(), PrestoAccessType.ADMIN)) {
      LOG.info("==> RangerSystemAccessControl.checkCanShowRoles(" + catalogName + ") denied");
      AccessDeniedException.denyShowRoles(catalogName);
    }
  }


  private static RangerPrestoResource createResource(CatalogSchemaName catalogSchemaName) {
    return createResource(catalogSchemaName.getCatalogName(), catalogSchemaName.getSchemaName());
  }

  private static RangerPrestoResource createResource(CatalogSchemaTableName catalogSchemaTableName) {
    return createResource(catalogSchemaTableName.getCatalogName(),
      catalogSchemaTableName.getSchemaTableName().getSchemaName(),
      catalogSchemaTableName.getSchemaTableName().getTableName());
  }

  private static RangerPrestoResource createFunctionResource(String function) {
    RangerPrestoResource res = new RangerPrestoResource();
    res.setValue(RangerPrestoResource.KEY_FUNCTION, function);
    return res;
  }
  private static RangerPrestoResource createProcedureResource(CatalogSchemaRoutineName procedure) {
    RangerPrestoResource res = new RangerPrestoResource();
    res.setValue(RangerPrestoResource.KEY_CATALOG, procedure.getCatalogName());
    res.setValue(RangerPrestoResource.KEY_SCHEMA, procedure.getSchemaRoutineName().getSchemaName());
    res.setValue(RangerPrestoResource.KEY_PROCEDURE, procedure.getSchemaRoutineName().getRoutineName());

    return res;
  }

  private static RangerPrestoResource createResource(String catalogName) {
    return new RangerPrestoResource(catalogName, Optional.empty(), Optional.empty());
  }

  private static RangerPrestoResource createResource(String catalogName, String schemaName) {
    return new RangerPrestoResource(catalogName, Optional.of(schemaName), Optional.empty());
  }

  private static RangerPrestoResource createResource(String catalogName, String schemaName, final String tableName) {
    return new RangerPrestoResource(catalogName, Optional.of(schemaName), Optional.of(tableName));
  }

  private static RangerPrestoResource createResource(String catalogName, String schemaName, final String tableName, final Optional<String> column) {
    return new RangerPrestoResource(catalogName, Optional.of(schemaName), Optional.of(tableName), column);
  }

  private static List<RangerPrestoResource> createResource(CatalogSchemaTableName table, Set<String> columns) {
    List<RangerPrestoResource> colRequests = new ArrayList<>();

    if (columns.size() > 0) {
      for (String column : columns) {
        RangerPrestoResource rangerPrestoResource = createResource(table.getCatalogName(),
          table.getSchemaTableName().getSchemaName(),
          table.getSchemaTableName().getTableName(), Optional.of(column));
        colRequests.add(rangerPrestoResource);
      }
    } else {
      colRequests.add(createResource(table.getCatalogName(),
        table.getSchemaTableName().getSchemaName(),
        table.getSchemaTableName().getTableName(), Optional.empty()));
    }
    return colRequests;
  }
}

class RangerPrestoResource
  extends RangerAccessResourceImpl {


  public static final String KEY_CATALOG = "catalog";
  public static final String KEY_SCHEMA = "schema";
  public static final String KEY_TABLE = "table";
  public static final String KEY_COLUMN = "column";
  public static final String KEY_FUNCTION = "function";
  public static final String KEY_PROCEDURE = "procedure";
  //public static final String KEY_SYSTEM_PROPERTY = "systemproperty";
  //public static final String KEY_SESSION_PROPERTY = "sessionproperty";

  public RangerPrestoResource() {}

  public RangerPrestoResource(String catalogName, Optional<String> schema, Optional<String> table) {
    setValue(KEY_CATALOG, catalogName);
    if (schema.isPresent()) {
      setValue(KEY_SCHEMA, schema.get());
    }
    if (table.isPresent()) {
      setValue(KEY_TABLE, table.get());
    }
  }

  public RangerPrestoResource(String catalogName, Optional<String> schema, Optional<String> table, Optional<String> column) {
    setValue(KEY_CATALOG, catalogName);
    if (schema.isPresent()) {
      setValue(KEY_SCHEMA, schema.get());
    }
    if (table.isPresent()) {
      setValue(KEY_TABLE, table.get());
    }
    if (column.isPresent()) {
      setValue(KEY_COLUMN, column.get());
    }
  }

  public String getCatalogName() {
    return (String) getValue(KEY_CATALOG);
  }

  public String getTable() {
    return (String) getValue(KEY_TABLE);
  }

  public String getCatalog() {
    return (String) getValue(KEY_CATALOG);
  }

  public String getSchema() { return (String) getValue(KEY_SCHEMA); }

  public Optional<SchemaTableName> getSchemaTable() {
    final String schema = getSchema();
    if (StringUtils.isNotEmpty(schema)) {
      return Optional.of(new SchemaTableName(schema, Optional.ofNullable(getTable()).orElse("*")));
    }
    return Optional.empty();
  }
}

class RangerPrestoAccessRequest
  extends RangerAccessRequestImpl {
  public RangerPrestoAccessRequest(RangerPrestoResource resource,
                                   String user,
                                   Set<String> userGroups,
                                   PrestoAccessType prestoAccessType)

  {
    super(resource,
      prestoAccessType == PrestoAccessType.USE ? RangerPolicyEngine.ANY_ACCESS :
        //prestoAccessType == PrestoAccessType.ADMIN ? RangerPolicyEngine.ADMIN_ACCESS :
          prestoAccessType.name().toLowerCase(ENGLISH), user,
      userGroups);
    setAccessTime(new Date());
  }
}

enum PrestoAccessType {
  CREATE, DROP, SELECT, INSERT, DELETE, USE, ALTER, ALL, ADMIN;
}