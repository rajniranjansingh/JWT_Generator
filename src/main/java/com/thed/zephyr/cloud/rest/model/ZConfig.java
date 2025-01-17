package com.thed.zephyr.cloud.rest.model;

import com.atlassian.connect.play.java.AcHost;
import com.atlassian.fugue.Option;
import com.google.common.collect.ImmutableList;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;

import java.util.List;
import java.util.Map;

public class ZConfig extends PropertiesConfiguration 
{
    public Option<String> ACCOUNT_ID;
    public String JIRA_HOST_KEY;
    public String JIRA_BASE_URL;
    public String JIRA_SHARED_SECRET;

    public String ZEPHYR_BASE_URL;
    public String APP_KEY;
    public String SECRET_KEY;
    public String ACCESS_KEY;
    public AcHost host;

    final List<String> reqdConfigKeys = ImmutableList.<String>builder()
            .add("accountId")
            .add("jiraHostKey")
            .add("jiraBaseURL")
            .add("sharedSecret")
            .add("zephyrBaseURL")
            .add("accessKey")
            .add("secretKey")
            .add("appKey").build();

    private ZConfig()
    {
    	
    }

    public  ZConfig(String accessKey, String secretKey, String accountId, String zephyrBaseUrl)
    {
        JIRA_HOST_KEY = accessKey;
        JIRA_SHARED_SECRET = secretKey;

        ZEPHYR_BASE_URL = zephyrBaseUrl;
        ACCESS_KEY = accessKey;
        ACCOUNT_ID = Option.option(accountId);

        host = new AcHost();
        host.setKey(JIRA_HOST_KEY);
        host.setBaseUrl(JIRA_BASE_URL);
        host.setSharedSecret(JIRA_SHARED_SECRET);
    }

    public ZConfig(String fileName) throws ConfigurationException 
    {
        super(fileName);
        configure();
    }

    public ZConfig(Map<String, String> props) throws ConfigurationException 
    {
        super();
        for(Map.Entry<String, String> prop : props.entrySet()) 
        {
            this.addProperty(prop.getKey(), prop.getValue());
        }
        configure();
    }

    private void configure() throws ConfigurationException
    {
        checkMandatoryPropertiesSet();
        setLocalPropertyValues();
    }

    private void checkMandatoryPropertiesSet() throws ConfigurationException 
    {
        for (String key : reqdConfigKeys)
        {
            if (!this.containsKey(key)) 
            {
                getLogger().fatal(key + "is required in ZFJ Cloud configration");
                throw new ConfigurationException(key + "is required in ZFJ Cloud configration");
            }
        }
    }

    public static class ZConfigBuilder
    {
        private ZConfig zconfig;

        public ZConfigBuilder() 
        {
            zconfig = new ZConfig();
        }

        public ZConfigBuilder withJiraHostKey(String hostKey) 
        {
            zconfig.addProperty("jiraHostKey", hostKey);
            return this;
        }

        public ZConfigBuilder withJIRABaseUrl(String baseUrl) 
        {
            zconfig.addProperty("jiraBaseURL", baseUrl);
            return this;
        }

        public ZConfigBuilder withJIRASharedSecret(String sharedSecret) 
        {
            zconfig.addProperty("sharedSecret", sharedSecret);
            return this;
        }

        public ZConfigBuilder withZephyrBaseUrl(String zephyrBaseUrl) 
        {
            zconfig.addProperty("zephyrBaseURL", zephyrBaseUrl);
            return this;
        }

        public ZConfigBuilder withZephyrAppKey(String appKey)
        {
            zconfig.addProperty("appKey", appKey);
            return this;
        }

        public ZConfigBuilder withZephyrAccessKey(String accessKey) 
        {
            zconfig.addProperty("accessKey", accessKey);
            return this;
        }

        public ZConfigBuilder withZephyrSecretKey(String secretKey) 
        {
            zconfig.addProperty("secretKey", secretKey);
            return this;
        }


        public ZConfigBuilder withJiraAccountId(String accountId) 
        {
            zconfig.addProperty("accountId", accountId);
            return this;
        }

        public ZConfig build() throws ConfigurationException
        {
            zconfig.configure();
            return zconfig;
        }
    }

    private void setLocalPropertyValues() 
    {
        JIRA_HOST_KEY = this.getString("accessKey");
        JIRA_SHARED_SECRET = this.getString("secretKey");

        ZEPHYR_BASE_URL = this.getString("zephyrBaseURL");
        ACCESS_KEY = this.getString("accessKey");

        ACCOUNT_ID =  Option.some(this.getString("accountId"));

        host = new AcHost();
        host.setKey(JIRA_HOST_KEY);
        host.setBaseUrl(JIRA_BASE_URL);
        host.setSharedSecret(JIRA_SHARED_SECRET);
    }
}
