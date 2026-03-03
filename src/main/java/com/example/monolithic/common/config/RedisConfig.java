package com.example.monolithic.common.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

/*
Redis: 메모리 위에 돌아가는 초고속 데이터 저장소
용도: 로그인 세션 정보, 실시간 순위, 최근 본 상품 등 캐시 용도
*/
@Configuration  // 설정을 담당하는 클래스로서 내부 정의된 객체를 관리
public class RedisConfig {

    @Value("${spring.data.redis.host}")
    private String host;

    @Value("${spring.data.redis.port}")
    private int port;

    @Bean
    @Qualifier("tokenRedis")
    public RedisConnectionFactory redisConnectionFactory() {
        RedisStandaloneConfiguration configuration = new RedisStandaloneConfiguration();
        configuration.setHostName(host);
        configuration.setPort(port);

        return new LettuceConnectionFactory(configuration);
    }

    @Bean   // 스프링 컨테이너가 관리하는 객체(Bean)로 등록
    @Qualifier("tokenRedis")
    public RedisTemplate<String, Object> redisTemplate(@Qualifier("tokenRedis") RedisConnectionFactory rcf) {
        // RedisTemplate: Redis에 데이터를 읽고 쓰는 핵심 도구
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(rcf); // 연결 공장(Factory)를 설정해야 작동

        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new StringRedisSerializer());

        return template;
    }
}
