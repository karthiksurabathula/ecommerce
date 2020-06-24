package com.open.loginservice.config;

import java.util.concurrent.Executor;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

@Configuration
@EnableAsync
public class AsyncConfiguration {

	@Value("${async.coreThreadSize:30}")
	private int async_coreThreadSize;
	@Value("${async.maxPoolSize:30}")
	private int async_maxPoolSize;
	@Value("${async.queueSize:100}")
	private int async_queueSize;

	@Bean(name = "asyncExecutor")
	public Executor asyncExecutor() {
		ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
		executor.setCorePoolSize(async_coreThreadSize);
		executor.setMaxPoolSize(async_maxPoolSize);
		executor.setQueueCapacity(async_queueSize);
		executor.setThreadNamePrefix("AsyncThread-");
		executor.initialize();
		return executor;
	}
}
