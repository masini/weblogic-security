package net.lucamasini.security;

import weblogic.management.security.ProviderMBean;
import weblogic.security.spi.AuthenticationProviderV2;
import weblogic.security.spi.IdentityAsserterV2;
import weblogic.security.spi.PrincipalValidator;
import weblogic.security.spi.SecurityServices;

import javax.security.auth.login.AppConfigurationEntry;
import java.util.HashMap;
import java.util.logging.Logger;

public class PacktAuthProviderImpl implements AuthenticationProviderV2

{
    private AppConfigurationEntry.LoginModuleControlFlag controlFlag;
    private String description;
    private String url;
    private static final Logger LOGGER = Logger.getLogger(PacktAuthProviderImpl.class.getSimpleName());

    static {
        System.err.println("********************STARTED");
    }

    @Override
    public void initialize(ProviderMBean mbean, SecurityServices services) {
        LOGGER.info("PacktAuthProviderImpl.initialize");
        PacktSiteUsersAuthenticationMBean myMBean = (PacktSiteUsersAuthenticationMBean) mbean;
        String flag = myMBean.getControlFlag();
        if (flag.equalsIgnoreCase("REQUIRED")) {
            controlFlag = AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;
        } else if (flag.equalsIgnoreCase("OPTIONAL")) {
            controlFlag = AppConfigurationEntry.LoginModuleControlFlag.OPTIONAL;
        } else if (flag.equalsIgnoreCase("REQUISITE")) {
            controlFlag = AppConfigurationEntry.LoginModuleControlFlag.REQUISITE;
        } else if (flag.equalsIgnoreCase("SUFFICIENT")) {
            controlFlag = AppConfigurationEntry.LoginModuleControlFlag.SUFFICIENT;
        } else {
            throw new IllegalArgumentException("invalid flag value" + flag);
        }
        description = myMBean.getDescription() + "\n" + myMBean.getVersion();
        url = myMBean.getURL();
    }

    @Override
    public String getDescription() {
        return description;
    }

    @Override
    public void shutdown() {
        LOGGER.info("PacktAuthProviderImpl.shutdown");
    }

    @Override
    public AppConfigurationEntry getLoginModuleConfiguration() {
        return new AppConfigurationEntry(
                "net.lucamasini.security.PacktLoginModuleImpl",
                controlFlag,
                new HashMap<String, Object>() {{
                    put("url", url);
                }}
        );
    }

    @Override
    public AppConfigurationEntry getAssertionModuleConfiguration() {
        return getLoginModuleConfiguration();
    }

    @Override
    public PrincipalValidator getPrincipalValidator() {
        return new weblogic.security.provider.PrincipalValidatorImpl();
    }

    @Override
    public IdentityAsserterV2 getIdentityAsserter() {
        return null;  // non serve !!!!
    }
}
