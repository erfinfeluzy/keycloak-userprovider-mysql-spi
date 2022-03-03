package com.erfinfeluzy.customkeycloakspi;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.commons.codec.digest.DigestUtils;

public class CustomUserStorageProvider implements UserStorageProvider, 
  UserLookupProvider, 
  CredentialInputValidator,
  UserQueryProvider {
    
    private static final Logger log = LoggerFactory.getLogger(CustomUserStorageProvider.class);
    private KeycloakSession ksession;
    private ComponentModel model;

    //MYSQL
    // private static final String Q_GET_USER_BY_USERNAME  = "select username, firstName,lastName, email, birthDate from users where username = ?";
    // private static final String Q_GET_USER_BY_EMAIL     = "select username, firstName,lastName, email, birthDate from users where email = ?";
    // private static final String Q_GET_PASS              = "select password from users where username = ?";
    // private static final String Q_GET_USERS             = "select username, firstName,lastName, email, birthDate from users order by username limit ? offset ?";
    // private static final String Q_SEARCH_BY_USERNAME    = "select username, firstName,lastName, email, birthDate from users where username like ? order by username limit ? offset ?";

    //ORACLE
    private static final String Q_GET_USER_BY_USERNAME  = "select USERNAME, FULLNAME, FULLNAME, EMAIL, CREATIONDATE from RH_POC_USER where USERNAME = ? ";
    private static final String Q_GET_USER_BY_EMAIL     = "select USERNAME, FULLNAME, FULLNAME, EMAIL, CREATIONDATE from RH_POC_USER where EMAIL = ? ";
    private static final String Q_GET_PASS              = "select PASSWORD from USERDEVELOPER where USERNAME = ? ";
    // private static final String Q_GET_USERS             = "select USERNAME, FULLNAME, FULLNAME, EMAIL, CREATIONDATE from USERDEVELOPER order by USERNAME limit ? offset ?";
    private static final String Q_GET_USERS             = "select USERNAME, FULLNAME, FULLNAME, EMAIL, CREATIONDATE from RH_POC_USER order by USERNAME offset ? rows fetch first ? rows only ";
    // private static final String Q_SEARCH_BY_USERNAME    = "select USERNAME, FULLNAME, FULLNAME, EMAIL, CREATIONDATE from USERDEVELOPER where USERNAME like ? order by USERNAME limit ? offset ?";
    private static final String Q_SEARCH_BY_USERNAME    = "select USERNAME, FULLNAME, FULLNAME, EMAIL, CREATIONDATE from RH_POC_USER where USERNAME like ? order by USERNAME offset ? rows fetch first ? rows only ";


    public CustomUserStorageProvider(KeycloakSession ksession, ComponentModel model) {
        this.ksession = ksession;
        this.model = model;
    }

    @Override
    public void close() {
        log.info("[I30] close()");
    }

    @Override
    public UserModel getUserById(String id, RealmModel realm) {
        log.info("[I35] getUserById({})",id);
        StorageId sid = new StorageId(id);
        return getUserByUsername(sid.getExternalId(),realm);
    }

    @Override
    public UserModel getUserByUsername(String username, RealmModel realm) {
        log.info("[I41] getUserByUsername({})",username);
        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement(Q_GET_USER_BY_USERNAME);
            st.setString(1, username);
            st.execute();
            ResultSet rs = st.getResultSet();
            if ( rs.next()) {
                return mapUser(realm,rs);
            }
            else {
                return null;
            }
        }
        catch(SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
        }
    }

    @Override
    public UserModel getUserByEmail(String email, RealmModel realm) {
        log.info("[I48] getUserByEmail({})",email);
        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement(Q_GET_USER_BY_EMAIL);
            st.setString(1, email);
            st.execute();
            ResultSet rs = st.getResultSet();
            if ( rs.next()) {
                return mapUser(realm,rs);
            }
            else {
                return null;
            }
        }
        catch(SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
        }
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        log.info("[I57] supportsCredentialType({})",credentialType);
        return PasswordCredentialModel.TYPE.endsWith(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        log.info("[I57] isConfiguredFor(realm={},user={},credentialType={})",realm.getName(), user.getUsername(), credentialType);
        // In our case, password is the only type of credential, so we allways return 'true' if
        // this is the credentialType
        return supportsCredentialType(credentialType);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
        log.info("[I57] isValid(realm={},user={},credentialInput.type={})",realm.getName(), user.getUsername(), credentialInput.getType());
        if( !this.supportsCredentialType(credentialInput.getType())) {
            return false;
        }
        StorageId sid = new StorageId(user.getId());
        String username = sid.getExternalId();
        
        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement(Q_GET_PASS);
            st.setString(1, username);
            st.execute();
            ResultSet rs = st.getResultSet();
            if ( rs.next()) {
                String pwd = rs.getString(1);
                String credentialInputHash = DigestUtils.sha256Hex(credentialInput.getChallengeResponse());
                return pwd.equals(credentialInputHash);
                // return pwd.equals(credentialInput.getChallengeResponse());
            }
            else {
                return false;
            }
        }
        catch(SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
        }
    }

    // UserQueryProvider implementation
    
    @Override
    public int getUsersCount(RealmModel realm) {
        log.info("[I93] getUsersCount: realm={}", realm.getName() );
        try ( Connection c = DbUtil.getConnection(this.model)) {
            Statement st = c.createStatement();
            st.execute("select count(*) from users");
            ResultSet rs = st.getResultSet();
            rs.next();
            return rs.getInt(1);
        }
        catch(SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
        }
    }

    @Override
    public List<UserModel> getUsers(RealmModel realm) {
        return getUsers(realm,0, 5000); // Keep a reasonable maxResults 
    }

    @Override
    public List<UserModel> getUsers(RealmModel realm, int firstResult, int maxResults) {
        log.info("[I113] getUsers: realm={}", realm.getName());
        
        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement(Q_GET_USERS);
            st.setInt(1, maxResults);
            st.setInt(2, firstResult);
            st.execute();
            ResultSet rs = st.getResultSet();
            List<UserModel> users = new ArrayList<>();
            while(rs.next()) {
                users.add(mapUser(realm,rs));
            }
            return users;
        }
        catch(SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
        }
    }

    @Override
    public List<UserModel> searchForUser(String search, RealmModel realm) {
        return searchForUser(search,realm,0,5000);
    }

    @Override
    public List<UserModel> searchForUser(String search, RealmModel realm, int firstResult, int maxResults) {
        log.info("[I139] searchForUser: realm={}", realm.getName());
        
        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement(Q_SEARCH_BY_USERNAME);
            st.setString(1, search);
            st.setInt(2, maxResults);
            st.setInt(3, firstResult);
            st.execute();
            ResultSet rs = st.getResultSet();
            List<UserModel> users = new ArrayList<>();
            while(rs.next()) {
                users.add(mapUser(realm,rs));
            }
            return users;
        }
        catch(SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
        }
    }

    @Override
    public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm) {
        return searchForUser(params,realm,0,1000);
    }

    @Override
    public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm, int firstResult, int maxResults) {
        return getUsers(realm, firstResult, maxResults);
    }

    @Override
    public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group, int firstResult, int maxResults) {
        return Collections.emptyList();
    }

    @Override
    public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group) {
        return Collections.emptyList();
    }

    @Override
    public List<UserModel> searchForUserByUserAttribute(String attrName, String attrValue, RealmModel realm) {
        return Collections.emptyList();
    }

    
    //------------------- Implementation 
    private UserModel mapUser(RealmModel realm, ResultSet rs) throws SQLException {
        
        // DateFormat fmt = new SimpleDateFormat("yyyy-MM-dd");
        // CustomUser user = new CustomUser.Builder(ksession, realm, model, rs.getString("username"))
        //   .email(rs.getString("email"))
        //   .firstName(rs.getString("firstName"))
        //   .lastName(rs.getString("lastName"))
        //   .birthDate(rs.getDate("birthDate"))
        //   .build();

        String fullName = rs.getString("FULLNAME");
        String firstName = "";
        String lastName = "";
        int idx = fullName.lastIndexOf(' ');
        if (idx == -1){
            firstName = fullName;
        }else{
            firstName = fullName.substring(0, idx);
            lastName = fullName.substring(idx + 1);
        }

        CustomUser user = new CustomUser.Builder(ksession, realm, model, rs.getString("USERNAME"))
          .email(rs.getString("EMAIL"))
          .firstName(firstName)
          .lastName(lastName)
          .birthDate(rs.getDate("CREATIONDATE"))
          .build();
        
        return user;
    }
}