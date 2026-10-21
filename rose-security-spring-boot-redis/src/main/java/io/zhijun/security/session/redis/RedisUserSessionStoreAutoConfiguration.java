package io.zhijun.security.session.redis;

import io.zhijun.security.core.UserSessionStore;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.StringRedisTemplate;

@AutoConfiguration
@AutoConfigureAfter(name = {
    "io.zhijun.security.session.jdbc.JdbcUserSessionStoreAutoConfiguration",
    "org.springframework.boot.data.redis.autoconfigure.RedisAutoConfiguration"
})
@ConditionalOnClass(StringRedisTemplate.class)
@ConditionalOnProperty(prefix = "auth.security", name = "enabled", havingValue = "true", matchIfMissing = true)
@ConditionalOnBean(StringRedisTemplate.class)
public class RedisUserSessionStoreAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(UserSessionStore.class)
    RedisUserSessionStore authSecurityRedisUserSessionStore(StringRedisTemplate redis) {
        return new RedisUserSessionStore(redis);
    }
}
