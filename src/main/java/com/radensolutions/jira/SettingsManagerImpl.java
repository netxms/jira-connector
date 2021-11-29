package com.radensolutions.jira;

import com.atlassian.sal.api.pluginsettings.PluginSettings;
import com.atlassian.sal.api.pluginsettings.PluginSettingsFactory;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class SettingsManagerImpl implements SettingsManager {
    private static final String NAMESPACE = "netxms-";
    public static final String KEY_PASSWORD = NAMESPACE + "password";
    public static final String KEY_LOGIN = NAMESPACE + "login";
    public static final String KEY_SERVERS = NAMESPACE + "servers";
    public static final String KEY_ENABLED = NAMESPACE + "enabled";
    public static final String KEY_PROJECT = NAMESPACE + "project";
    public static final String KEY_JIRA_ACCOUNT = NAMESPACE + "jira-account";

    private final PluginSettingsFactory pluginSettingsFactory;

    public SettingsManagerImpl(PluginSettingsFactory pluginSettingsFactory) {
        this.pluginSettingsFactory = pluginSettingsFactory;
    }

    @Override
    public List<String> getServers() {
        PluginSettings globalSettings = pluginSettingsFactory.createGlobalSettings();
        Object o = globalSettings.get(KEY_SERVERS);
        return o == null ? new ArrayList<String>(0) : (List<String>) o;
    }

    @Override
    public void setServers(List<String> servers) {
        PluginSettings globalSettings = pluginSettingsFactory.createGlobalSettings();
        globalSettings.put(KEY_SERVERS, servers);
    }

    @Override
    public String getLogin() {
        PluginSettings globalSettings = pluginSettingsFactory.createGlobalSettings();
        return (String) globalSettings.get(KEY_LOGIN);
    }

    @Override
    public void setLogin(String login) {
        PluginSettings globalSettings = pluginSettingsFactory.createGlobalSettings();
        globalSettings.put(KEY_LOGIN, login);
    }

    @Override
    public String getPassword() {
        PluginSettings globalSettings = pluginSettingsFactory.createGlobalSettings();
        String login = (String) globalSettings.get(KEY_LOGIN);
        String password = (String) globalSettings.get(KEY_PASSWORD);
        return decryptPassword(login, password);
    }

    @Override
    public void setPassword(String password) {
        PluginSettings globalSettings = pluginSettingsFactory.createGlobalSettings();
        globalSettings.put(KEY_PASSWORD, password);
    }

    @Override
    public boolean isEnabled() {
        PluginSettings globalSettings = pluginSettingsFactory.createGlobalSettings();
        String enabled = (String) globalSettings.get(KEY_ENABLED);
        return enabled != null && enabled.equals("YES");
    }

    @Override
    public void setEnabled(boolean enabled) {
        PluginSettings globalSettings = pluginSettingsFactory.createGlobalSettings();
        globalSettings.put(KEY_ENABLED, enabled ? "YES" : "NO");
    }

    @Override
    public String getProjectKey() {
        PluginSettings globalSettings = pluginSettingsFactory.createGlobalSettings();
        return (String) globalSettings.get(KEY_PROJECT);
    }

    @Override
    public void setProjectKey(String projectKey) {
        PluginSettings globalSettings = pluginSettingsFactory.createGlobalSettings();
        globalSettings.put(KEY_PROJECT, projectKey);
    }

    @Override
    public String getJiraAccount() {
        PluginSettings globalSettings = pluginSettingsFactory.createGlobalSettings();
        return (String) globalSettings.get(KEY_JIRA_ACCOUNT);
    }

    @Override
    public void setJiraAccount(String jiraAccount) {
        PluginSettings globalSettings = pluginSettingsFactory.createGlobalSettings();
        globalSettings.put(KEY_JIRA_ACCOUNT, jiraAccount);
    }

    @Override
    public String decryptPassword(String login, String obfuscatedPassword) {
        if (obfuscatedPassword.length() == 44 || obfuscatedPassword.length() == 88) {
            // might be ICE-obfuscated
            try {
                byte[] rawObfuscatedPassword = Base64.getDecoder().decode(obfuscatedPassword);

                MessageDigest md5 = MessageDigest.getInstance("MD5");
                md5.update(login.getBytes());
                byte[] key = md5.digest();

                IceKey ice = new IceKey(1);
                ice.set(key);

                byte[] decrypted = new byte[rawObfuscatedPassword.length];
                byte[] buffer = new byte[8];
                byte[] outBuffer = new byte[8];
                for (int i = 0; i < rawObfuscatedPassword.length / 8; i++) {
                    System.arraycopy(rawObfuscatedPassword, i * 8, buffer, 0, 8);
                    ice.decrypt(buffer, outBuffer);
                    System.arraycopy(outBuffer, 0, decrypted, i * 8, 8);
                }
                StringBuilder sb = new StringBuilder();
                for (byte b : decrypted) {
                    if (b == 0) {
                        break;
                    }
                    sb.append((char) b);
                }
                return sb.toString();
            } catch (Exception e) {
                // ignore all errors, use password as is
            }
        }
        return obfuscatedPassword;
    }
}
