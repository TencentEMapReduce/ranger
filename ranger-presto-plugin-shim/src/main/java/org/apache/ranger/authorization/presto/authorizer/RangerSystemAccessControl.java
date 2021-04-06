/*
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
package org.apache.ranger.authorization.presto.authorizer;

import io.prestosql.spi.connector.*;
import io.prestosql.spi.security.*;
import io.prestosql.spi.type.Type;
import org.apache.ranger.plugin.classloader.RangerPluginClassLoader;

import javax.inject.Inject;
import java.security.Principal;
import java.util.*;

import static java.lang.String.format;

public class RangerSystemAccessControl
  implements SystemAccessControl {
  private static final String RANGER_PLUGIN_TYPE = "presto";
  private static final String RANGER_PRESTO_AUTHORIZER_IMPL_CLASSNAME = "org.apache.ranger.authorization.presto.authorizer.RangerSystemAccessControl";

  final private RangerPluginClassLoader rangerPluginClassLoader;
  final private SystemAccessControl systemAccessControlImpl;

  @Inject
  public RangerSystemAccessControl(RangerConfig config) {
    try {
      rangerPluginClassLoader = RangerPluginClassLoader.getInstance(RANGER_PLUGIN_TYPE, this.getClass());

      @SuppressWarnings("unchecked")
      Class<SystemAccessControl> cls = (Class<SystemAccessControl>) Class.forName(RANGER_PRESTO_AUTHORIZER_IMPL_CLASSNAME, true, rangerPluginClassLoader);

      activatePluginClassLoader();

      Map<String, String> configMap = new HashMap<>();
      if (config.getKeytab() != null && config.getPrincipal() != null) {
        configMap.put("ranger.keytab", config.getKeytab());
        configMap.put("ranger.principal", config.getPrincipal());
      }
      systemAccessControlImpl = cls.getDeclaredConstructor(Map.class).newInstance(configMap);
    } catch (Exception e) {
      throw new RuntimeException(e);
    } finally {
      deactivatePluginClassLoader();
    }
  }

  @Override
  public void checkCanImpersonateUser(SystemSecurityContext context, String userName)
  {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanImpersonateUser(context,userName);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyImpersonateUser(context.getIdentity().getUser(), userName);
    }
  }

  @Override
  public void checkCanSetUser(Optional<Principal> principal, String userName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSetUser(principal, userName);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denySetUser(principal, userName);
    }
  }

  @Override
  public void checkCanExecuteQuery(SystemSecurityContext context)
  {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanExecuteQuery(context);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyExecuteQuery(e.getMessage() + context.toString());
    }
  }

  @Override
  public void checkCanViewQueryOwnedBy(SystemSecurityContext context, String queryOwner)
  {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanViewQueryOwnedBy(context, queryOwner);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyViewQuery(context.toString());
    }
  }

  @Override
  public Set<String> filterViewQueryOwnedBy(SystemSecurityContext context, Set<String> queryOwners)
  {
    return queryOwners;
  }

  @Override
  public void checkCanKillQueryOwnedBy(SystemSecurityContext context, String queryOwner)
  {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanKillQueryOwnedBy(context, queryOwner);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyKillQuery(context.toString());
    }
  }

  @Override
  public void checkCanSetSystemSessionProperty(SystemSecurityContext context, String propertyName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSetSystemSessionProperty(context, propertyName);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denySetSystemSessionProperty(propertyName);
    }
  }

  @Override
  public void checkCanAccessCatalog(SystemSecurityContext context, String catalogName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanAccessCatalog(context, catalogName);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyCatalogAccess(catalogName);
    }
  }

  @Override
  public Set<String> filterCatalogs(SystemSecurityContext context, Set<String> catalogs) {
    return catalogs;
  }

  @Override
  public void checkCanCreateSchema(SystemSecurityContext context, CatalogSchemaName schema) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanCreateSchema(context, schema);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyCreateSchema(schema.getSchemaName());
    }
  }

  @Override
  public void checkCanDropSchema(SystemSecurityContext context, CatalogSchemaName schema) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanDropSchema(context, schema);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyDropSchema(schema.getSchemaName());
    }
  }

  @Override
  public void checkCanRenameSchema(SystemSecurityContext context, CatalogSchemaName schema, String newSchemaName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanRenameSchema(context, schema, newSchemaName);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyRenameSchema(schema.getSchemaName(), newSchemaName);
    }
  }

  @Override
  public void checkCanSetSchemaAuthorization(SystemSecurityContext context, CatalogSchemaName schema, PrestoPrincipal principal)
  {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSetSchemaAuthorization(context, schema, principal);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denySetSchemaAuthorization(schema.getSchemaName(), principal);
    }
  }

  @Override
  public void checkCanShowSchemas(SystemSecurityContext context, String catalogName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanShowSchemas(context, catalogName);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyShowSchemas();
    }
  }

  @Override
  public Set<String> filterSchemas(SystemSecurityContext context, String catalogName, Set<String> schemaNames) {
    //TODO
    return schemaNames;
  }

  @Override
  public void checkCanCreateTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanCreateTable(context, table);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyCreateTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public  void checkCanShowCreateTable(SystemSecurityContext context, CatalogSchemaTableName table)
  {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanShowCreateTable(context, table);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyShowCreateTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanDropTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanDropTable(context, table);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyDropTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanRenameTable(SystemSecurityContext context, CatalogSchemaTableName table, CatalogSchemaTableName newTable) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanRenameTable(context, table, newTable);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyRenameTable(table.getSchemaTableName().getTableName(), newTable.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanSetTableComment(SystemSecurityContext context, CatalogSchemaTableName table)
  {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSetTableComment(context, table);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyCommentTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanShowTables(SystemSecurityContext context, CatalogSchemaName schema) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanShowTables(context, schema);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyShowTables(schema.getSchemaName());
    }
  }

  @Override
  public void checkCanShowColumns(SystemSecurityContext context, CatalogSchemaTableName table)
  {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanShowColumns(context, table);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyShowSchemas(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public List<ColumnMetadata> filterColumns(SystemSecurityContext context, CatalogSchemaTableName table, List<ColumnMetadata> columns)
  {
    //TODO,
    return columns;
  }


  @Override
  public Set<SchemaTableName> filterTables(SystemSecurityContext context, String catalogName, Set<SchemaTableName> tableNames) {
    return tableNames;
  }

  @Override
  public void checkCanAddColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanAddColumn(context, table);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyAddColumn(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanDropColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanDropColumn(context, table);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyDropColumn(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanRenameColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanRenameColumn(context, table);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyRenameColumn(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSelectFromColumns(context, table, columns);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denySelectColumns(table.getSchemaTableName().getTableName(), columns);
    }
  }

  @Override
  public void checkCanInsertIntoTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanInsertIntoTable(context, table);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyInsertTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanDeleteFromTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanDeleteFromTable(context, table);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyDeleteTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanCreateView(SystemSecurityContext context, CatalogSchemaTableName view) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanCreateView(context, view);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyCreateView(view.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanRenameView(SystemSecurityContext context, CatalogSchemaTableName view, CatalogSchemaTableName newView)
  {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanRenameView(context, view, newView);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyRenameView(view.getSchemaTableName().getTableName(), newView.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanDropView(SystemSecurityContext context, CatalogSchemaTableName view) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanDropView(context, view);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyDropView(view.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanCreateViewWithSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanCreateViewWithSelectFromColumns(context, table, columns);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyCreateViewWithSelect(table.getSchemaTableName().getTableName(), context.getIdentity());
    }
  }

  @Override
  public void checkCanSetCatalogSessionProperty(SystemSecurityContext context, String catalogName, String propertyName) {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanSetCatalogSessionProperty(context, catalogName, propertyName);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denySetCatalogSessionProperty(catalogName, propertyName);
    }
  }

  @Override
  public void checkCanGrantExecuteFunctionPrivilege(SystemSecurityContext context, String functionName, PrestoPrincipal grantee, boolean grantOption)
  {
    String granteeAsString = format("%s '%s'", grantee.getType().name().toLowerCase(Locale.ENGLISH), grantee.getName());
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanGrantExecuteFunctionPrivilege(context, functionName, grantee, grantOption);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyGrantExecuteFunctionPrivilege(functionName, context.getIdentity(), granteeAsString);
    }
  }

  @Override
  public void checkCanGrantTablePrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaTableName table, PrestoPrincipal grantee, boolean grantOption)
  {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanGrantTablePrivilege(context, privilege, table, grantee, grantOption);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyGrantTablePrivilege(privilege.name(), table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanRevokeTablePrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaTableName table, PrestoPrincipal revokee, boolean grantOption)
  {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanRevokeTablePrivilege(context, privilege, table, revokee, grantOption);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyRevokeTablePrivilege(privilege.name(), table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanShowRoles(SystemSecurityContext context, String catalogName)
  {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanShowRoles(context, catalogName);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyShowRoles(catalogName);
    }
  }

  @Override
  public void checkCanExecuteProcedure(SystemSecurityContext systemSecurityContext, CatalogSchemaRoutineName procedure)
  {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanExecuteProcedure(systemSecurityContext, procedure);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyExecuteProcedure(procedure.toString());
    }
  }

  @Override
  public void checkCanExecuteFunction(SystemSecurityContext systemSecurityContext, String functionName)
  {
    try {
      activatePluginClassLoader();
      systemAccessControlImpl.checkCanExecuteFunction(systemSecurityContext, functionName);
    } catch (AccessDeniedException e) {
      deactivatePluginClassLoader();
      throw e;
    } catch (Exception e) {
      deactivatePluginClassLoader();
      AccessDeniedException.denyExecuteFunction(functionName);
    }
  }

  @Override
  public Optional<ViewExpression> getRowFilter(SystemSecurityContext context, CatalogSchemaTableName tableName)
  {
    //TODO
    return Optional.empty();
  }

  @Override
  public  Optional<ViewExpression> getColumnMask(SystemSecurityContext context, CatalogSchemaTableName tableName, String columnName, Type type)
  {
    //TODO
    return Optional.empty();
  }

  private void activatePluginClassLoader() {
    if (rangerPluginClassLoader != null) {
      rangerPluginClassLoader.activate();
    }
  }

  private void deactivatePluginClassLoader() {
    if (rangerPluginClassLoader != null) {
      rangerPluginClassLoader.deactivate();
    }
  }
}
