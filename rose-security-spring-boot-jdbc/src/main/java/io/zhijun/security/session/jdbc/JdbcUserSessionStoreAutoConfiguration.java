package io.zhijun.security.session.jdbc;

import io.zhijun.security.core.UserSessionStore;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;

@AutoConfiguration
@AutoConfigureAfter(
        name = {
            "org.springframework.boot.jdbc.autoconfigure.JdbcTemplateAutoConfiguration",
            "org.springframework.boot.jdbc.autoconfigure.DataSourceTransactionManagerAutoConfiguration"
        })
@ConditionalOnClass(JdbcTemplate.class)
@ConditionalOnProperty(prefix = "auth.security", name = "enabled", havingValue = "true", matchIfMissing = true)
@ConditionalOnBean({JdbcTemplate.class, PlatformTransactionManager.class})
public class JdbcUserSessionStoreAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(UserSessionStore.class)
    JdbcUserSessionStore authSecurityJdbcUserSessionStore(
            JdbcTemplate jdbcTemplate, PlatformTransactionManager transactionManager) {
        return new JdbcUserSessionStore(jdbcTemplate, transactionManager);
    }
}
