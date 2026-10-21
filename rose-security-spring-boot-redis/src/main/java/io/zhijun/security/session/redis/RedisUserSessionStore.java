package io.zhijun.security.session.redis;

import io.zhijun.security.core.UserSessionConcurrencyPolicy;
import io.zhijun.security.core.UserSessionStore;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

/** Redis-backed token sessions. Rotation and revocation use Redis Lua scripts for atomic updates. */
public class RedisUserSessionStore implements UserSessionStore {

    private static final String PREFIX = "rose-security:{session-store}:";
    private static final String CREATE_SCRIPT = """
            if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
            if ARGV[13] ~= '' and redis.call('EXISTS', KEYS[3]) == 1 then return 0 end
            local maximum = tonumber(ARGV[14] or '0')
            if maximum and maximum > 0 then
              local now = tonumber(ARGV[16])
              local ids = redis.call('ZRANGE', KEYS[2], 0, -1)
              local active = {}
              for _, sid in ipairs(ids) do
                local sessionKey = ARGV[17] .. 'session:' .. sid
                if redis.call('EXISTS', sessionKey) == 0 then
                  redis.call('ZREM', KEYS[2], sid)
                else
                  local v = redis.call('HMGET', sessionKey, 'username', 'revokedAt', 'expiresAt',
                    'absoluteExpiresAt', 'createdAt', 'currentRefreshTokenHash')
                  local expiresAt = tonumber(v[3] or '0')
                  local absoluteExpiresAt = tonumber(v[4] or '0')
                  if v[1] ~= ARGV[2] or (v[2] and v[2] ~= '') or expiresAt <= now or absoluteExpiresAt <= now then
                    redis.call('ZREM', KEYS[2], sid)
                  else
                    table.insert(active, {
                      sid = sid, key = sessionKey, createdAt = tonumber(v[5] or '0'),
                      refreshHash = v[6] or '', absoluteExpiresAt = v[4]
                    })
                  end
                end
              end
              table.sort(active, function(left, right)
                if left.createdAt == right.createdAt then return left.sid < right.sid end
                return left.createdAt < right.createdAt
              end)
              if #active >= maximum and ARGV[15] == 'DENY_NEW' then return -1 end
              while #active >= maximum do
                local oldest = table.remove(active, 1)
                redis.call('HSET', oldest.key, 'revokedAt', ARGV[16], 'currentRefreshTokenHash', '')
                if oldest.refreshHash ~= '' then
                  local oldRefreshKey = ARGV[17] .. 'refresh:' .. oldest.refreshHash
                  redis.call('SET', oldRefreshKey, 'C|' .. oldest.sid .. '|' .. oldest.key)
                  redis.call('PEXPIREAT', oldRefreshKey, oldest.absoluteExpiresAt)
                end
                redis.call('ZREM', KEYS[2], oldest.sid)
              end
            end
            redis.call('HSET', KEYS[1],
              'sessionId', ARGV[1], 'username', ARGV[2], 'securityVersion', ARGV[3],
              'authenticatedAt', ARGV[4], 'authenticationMethods', ARGV[5], 'createdAt', ARGV[6],
              'lastUsedAt', ARGV[7], 'expiresAt', ARGV[8], 'absoluteExpiresAt', ARGV[9],
              'revokedAt', ARGV[10], 'clientIp', ARGV[11], 'device', ARGV[12],
              'currentRefreshTokenHash', ARGV[13], 'userSessionsKey', KEYS[2])
            redis.call('ZADD', KEYS[2], ARGV[9], ARGV[1])
            local latest = redis.call('ZREVRANGE', KEYS[2], 0, 0, 'WITHSCORES')
            if latest[2] then redis.call('PEXPIREAT', KEYS[2], latest[2]) end
            redis.call('PEXPIREAT', KEYS[1], ARGV[9])
            if ARGV[13] ~= '' then
              redis.call('SET', KEYS[3], 'A|' .. ARGV[1] .. '|' .. KEYS[1])
              redis.call('PEXPIREAT', KEYS[3], ARGV[9])
            end
            return 1
            """;
    private static final String ROTATE_SCRIPT = """
            local token = redis.call('GET', KEYS[1])
            if not token then return 'INVALID' end
            local state, sid, sessionKey = string.match(token, '^([^|]+)|([^|]+)|(.+)$')
            if not state or not sid or not sessionKey then return 'INVALID' end
            if state == 'C' then
              if redis.call('EXISTS', sessionKey) == 0 then return 'INVALID' end
              local revokedAt = redis.call('HGET', sessionKey, 'revokedAt') or ''
              if revokedAt == '' then
                local currentHash = redis.call('HGET', sessionKey, 'currentRefreshTokenHash') or ''
                redis.call('HSET', sessionKey, 'revokedAt', ARGV[2], 'currentRefreshTokenHash', '')
                if currentHash ~= '' then
                  local currentKey = ARGV[3] .. currentHash
                  redis.call('SET', currentKey, 'C|' .. sid .. '|' .. sessionKey)
                  redis.call('PEXPIREAT', currentKey, redis.call('HGET', sessionKey, 'absoluteExpiresAt'))
                end
                local userSessionsKey = redis.call('HGET', sessionKey, 'userSessionsKey')
                if userSessionsKey then redis.call('ZREM', userSessionsKey, sid) end
              end
              return 'REPLAYED'
            end
            if state ~= 'A' then return 'INVALID' end
            local v = redis.call('HMGET', sessionKey, 'sessionId', 'username', 'securityVersion',
              'authenticatedAt', 'authenticationMethods', 'createdAt', 'lastUsedAt', 'expiresAt',
              'absoluteExpiresAt', 'revokedAt', 'clientIp', 'device')
            if not v[1] then return 'INVALID' end
            local now = tonumber(ARGV[2])
            local expiresAt = tonumber(v[8])
            local absoluteExpiresAt = tonumber(v[9])
            if (v[10] and v[10] ~= '') or expiresAt <= now or absoluteExpiresAt <= now then return 'INVALID' end
            local replacementExpiresAt = math.min(now + tonumber(ARGV[1]), absoluteExpiresAt)
            redis.call('HSET', sessionKey, 'lastUsedAt', ARGV[2], 'expiresAt', tostring(replacementExpiresAt),
              'currentRefreshTokenHash', ARGV[4])
            redis.call('SET', KEYS[1], 'C|' .. sid .. '|' .. sessionKey)
            redis.call('PEXPIREAT', KEYS[1], absoluteExpiresAt)
            redis.call('SET', KEYS[2], 'A|' .. sid .. '|' .. sessionKey)
            redis.call('PEXPIREAT', KEYS[2], absoluteExpiresAt)
            v[7] = ARGV[2]
            v[8] = tostring(replacementExpiresAt)
            local out = {'ROTATED'}
            for i = 1, 12 do out[#out + 1] = v[i] or '' end
            return table.concat(out, '|')
            """;
    private static final String REVOKE_SCRIPT = """
            if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
            if redis.call('HGET', KEYS[1], 'username') ~= ARGV[1] then return 0 end
            local revokedAt = redis.call('HGET', KEYS[1], 'revokedAt') or ''
            if revokedAt ~= '' then return 0 end
            local sid = redis.call('HGET', KEYS[1], 'sessionId')
            local currentHash = redis.call('HGET', KEYS[1], 'currentRefreshTokenHash') or ''
            local absoluteExpiresAt = redis.call('HGET', KEYS[1], 'absoluteExpiresAt')
            redis.call('HSET', KEYS[1], 'revokedAt', ARGV[2], 'currentRefreshTokenHash', '')
            if currentHash ~= '' then
              local currentKey = ARGV[3] .. currentHash
              redis.call('SET', currentKey, 'C|' .. sid .. '|' .. KEYS[1])
              redis.call('PEXPIREAT', currentKey, absoluteExpiresAt)
            end
            redis.call('ZREM', KEYS[2], sid)
            return 1
            """;
    private static final String REVOKE_ALL_SCRIPT = """
            local sessionIds = redis.call('ZRANGE', KEYS[1], 0, -1)
            local revoked = 0
            for _, sid in ipairs(sessionIds) do
              local sessionKey = ARGV[1] .. 'session:' .. sid
              if redis.call('EXISTS', sessionKey) == 1
                  and redis.call('HGET', sessionKey, 'username') == ARGV[2] then
                local revokedAt = redis.call('HGET', sessionKey, 'revokedAt') or ''
                if revokedAt == '' then
                  local currentHash = redis.call('HGET', sessionKey, 'currentRefreshTokenHash') or ''
                  local absoluteExpiresAt = redis.call('HGET', sessionKey, 'absoluteExpiresAt')
                  redis.call('HSET', sessionKey, 'revokedAt', ARGV[3], 'currentRefreshTokenHash', '')
                  if currentHash ~= '' then
                    local currentKey = ARGV[1] .. 'refresh:' .. currentHash
                    redis.call('SET', currentKey, 'C|' .. sid .. '|' .. sessionKey)
                    redis.call('PEXPIREAT', currentKey, absoluteExpiresAt)
                  end
                  revoked = revoked + 1
                end
              end
              redis.call('ZREM', KEYS[1], sid)
            end
            return revoked
            """;
    private static final DefaultRedisScript<Long> CREATE = new DefaultRedisScript<>(CREATE_SCRIPT, Long.class);
    private static final DefaultRedisScript<String> ROTATE = new DefaultRedisScript<>(ROTATE_SCRIPT, String.class);
    private static final DefaultRedisScript<Long> REVOKE = new DefaultRedisScript<>(REVOKE_SCRIPT, Long.class);
    private static final DefaultRedisScript<Long> REVOKE_ALL = new DefaultRedisScript<>(REVOKE_ALL_SCRIPT, Long.class);

    private final StringRedisTemplate redis;

    public RedisUserSessionStore(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public void create(UserSession session) {
        create(session, null);
    }

    @Override
    public void create(UserSession session, String refreshTokenHash) {
        Long result = create(session, refreshTokenHash, 0, UserSessionConcurrencyPolicy.LimitBehavior.DENY_NEW);
        if (result == null || result != 1L) {
            throw new IllegalStateException("Could not create user session");
        }
    }

    @Override
    public SessionCreationResult create(
            UserSession session, String refreshTokenHash, UserSessionConcurrencyPolicy.Policy concurrencyPolicy) {
        if (concurrencyPolicy.maximumActiveSessions() == 0) {
            create(session, refreshTokenHash);
            return SessionCreationResult.CREATED;
        }
        Long result = create(
                session,
                refreshTokenHash,
                concurrencyPolicy.maximumActiveSessions(),
                concurrencyPolicy.limitBehavior());
        if (result == null || result == 0L) {
            throw new IllegalStateException("Could not create user session");
        }
        return result == -1L ? SessionCreationResult.LIMIT_REACHED : SessionCreationResult.CREATED;
    }

    private Long create(
            UserSession session,
            String refreshTokenHash,
            int maximumActiveSessions,
            UserSessionConcurrencyPolicy.LimitBehavior limitBehavior) {
        String sessionKey = sessionKey(session.sessionId());
        String tokenHash = refreshTokenHash == null ? "" : refreshTokenHash;
        List<String> keys = List.of(sessionKey, userSessionsKey(session.username()), refreshKey(tokenHash));
        Long created = redis.execute(
                CREATE,
                keys,
                session.sessionId(),
                encode(session.username()),
                Long.toString(session.securityVersion()),
                millis(session.authenticatedAt()),
                encodeMethods(session.authenticationMethods()),
                millis(session.createdAt()),
                millis(session.lastUsedAt()),
                millis(session.expiresAt()),
                millis(session.absoluteExpiresAt()),
                millis(session.revokedAt()),
                encode(session.clientIp()),
                encode(session.device()),
                tokenHash,
                Integer.toString(maximumActiveSessions),
                limitBehavior.name(),
                millis(session.createdAt()),
                PREFIX);
        return created;
    }

    @Override
    public RotationResult rotate(String presentedHash, String replacementHash, Duration refreshTtl, Instant now) {
        String result = redis.execute(
                ROTATE,
                List.of(refreshKey(presentedHash), refreshKey(replacementHash)),
                Long.toString(refreshTtl.toMillis()),
                millis(now),
                refreshKeyPrefix(),
                replacementHash);
        if (result == null || result.equals("INVALID")) {
            return new RotationResult(RotationStatus.INVALID, null);
        }
        if (result.equals("REPLAYED")) {
            return new RotationResult(RotationStatus.REPLAYED, null);
        }
        String[] values = result.split("\\|", -1);
        if (values.length != 13 || !values[0].equals("ROTATED")) {
            throw new IllegalStateException("Redis returned an invalid session rotation result");
        }
        UserSession session = new UserSession(
                values[1],
                decode(values[2]),
                Long.parseLong(values[3]),
                instant(values[4]),
                decodeMethods(values[5]),
                instant(values[6]),
                instant(values[7]),
                instant(values[8]),
                instant(values[9]),
                optionalInstant(values[10]),
                decode(values[11]),
                decode(values[12]));
        return new RotationResult(RotationStatus.ROTATED, session);
    }

    @Override
    public boolean revoke(String sessionId, String username, Instant revokedAt) {
        Long revoked = redis.execute(
                REVOKE,
                List.of(sessionKey(sessionId), userSessionsKey(username)),
                encode(username),
                millis(revokedAt),
                refreshKeyPrefix());
        return revoked != null && revoked == 1L;
    }

    @Override
    public int revokeAll(String username, Instant revokedAt) {
        Long revoked = redis.execute(
                REVOKE_ALL, List.of(userSessionsKey(username)), PREFIX, encode(username), millis(revokedAt));
        return revoked == null ? 0 : Math.toIntExact(revoked);
    }

    @Override
    public List<UserSession> findActiveSessions(String username, Instant now) {
        String userKey = userSessionsKey(username);
        redis.opsForZSet().removeRangeByScore(userKey, Double.NEGATIVE_INFINITY, now.toEpochMilli());
        Set<String> sessionIds = redis.opsForZSet().range(userKey, 0, -1);
        if (sessionIds == null || sessionIds.isEmpty()) {
            return List.of();
        }
        List<UserSession> active = new ArrayList<>();
        for (String sessionId : sessionIds) {
            var values = redis.opsForHash().entries(sessionKey(sessionId));
            if (values.isEmpty()) {
                redis.opsForZSet().remove(userKey, sessionId);
                continue;
            }
            UserSession session = fromHash(values);
            if (session.username().equals(username)
                    && session.revokedAt() == null
                    && session.expiresAt().isAfter(now)
                    && session.absoluteExpiresAt().isAfter(now)) {
                active.add(session);
            }
        }
        return List.copyOf(active);
    }

    private UserSession fromHash(java.util.Map<Object, Object> values) {
        return new UserSession(
                value(values, "sessionId"),
                decode(value(values, "username")),
                Long.parseLong(value(values, "securityVersion")),
                instant(value(values, "authenticatedAt")),
                decodeMethods(value(values, "authenticationMethods")),
                instant(value(values, "createdAt")),
                instant(value(values, "lastUsedAt")),
                instant(value(values, "expiresAt")),
                instant(value(values, "absoluteExpiresAt")),
                optionalInstant(value(values, "revokedAt")),
                decode(value(values, "clientIp")),
                decode(value(values, "device")));
    }

    private String sessionKey(String sessionId) {
        return PREFIX + "session:" + sessionId;
    }

    private String userSessionsKey(String username) {
        return PREFIX + "user-sessions:" + sha256(username);
    }

    private String refreshKey(String tokenHash) {
        return refreshKeyPrefix() + tokenHash;
    }

    private String refreshKeyPrefix() {
        return PREFIX + "refresh:";
    }

    private static String encodeMethods(List<String> methods) {
        return methods.stream().map(RedisUserSessionStore::encode).collect(java.util.stream.Collectors.joining(","));
    }

    private static List<String> decodeMethods(String value) {
        if (value == null || value.isEmpty()) {
            return List.of();
        }
        return java.util.Arrays.stream(value.split(",", -1))
                .map(RedisUserSessionStore::decode)
                .toList();
    }

    private static String encode(String value) {
        return value == null
                ? ""
                : Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String decode(String value) {
        return value == null || value.isEmpty()
                ? null
                : new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
    }

    private static String millis(Instant instant) {
        return instant == null ? "" : Long.toString(instant.toEpochMilli());
    }

    private static Instant instant(String millis) {
        return Instant.ofEpochMilli(Long.parseLong(millis));
    }

    private static Instant optionalInstant(String millis) {
        return millis == null || millis.isEmpty() ? null : instant(millis);
    }

    private static String value(java.util.Map<Object, Object> values, String field) {
        Object value = values.get(field);
        return value == null ? "" : value.toString();
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }
}
