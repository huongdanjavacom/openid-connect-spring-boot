package com.huongdanjava.openid.connect;

import java.util.HashMap;
import java.util.Map;

import javax.persistence.EntityManagerFactory;
import javax.sql.DataSource;

import org.eclipse.persistence.config.PersistenceUnitProperties;
import org.eclipse.persistence.jpa.PersistenceProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.JpaVendorAdapter;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.EclipseLinkJpaVendorAdapter;
import org.springframework.transaction.TransactionManager;

@SpringBootApplication(scanBasePackages = { "org.mitre", "com.huongdanjava" })
public class OpenIdConnectApplication {

    public static void main(String[] args) {
        SpringApplication.run(OpenIdConnectApplication.class, args);
    }

    @Bean("entityManagerFactory")
    public LocalContainerEntityManagerFactoryBean localContainerEntityManagerFactory(JpaVendorAdapter jpaVendorAdapter,
            DataSource dataSource) {
        var factory = new LocalContainerEntityManagerFactoryBean();
        factory.setPackagesToScan("org.mitre");
        factory.setPersistenceProviderClass(PersistenceProvider.class);
        factory.setDataSource(dataSource);
        factory.setJpaVendorAdapter(jpaVendorAdapter);
        factory.setJpaPropertyMap(initJpaProperties());
        factory.setPersistenceUnitName("defaultPersistenceUnit");

        return factory;
    }

    @Bean
    public JpaVendorAdapter jpaVendorAdapter() {
        var adapter = new EclipseLinkJpaVendorAdapter();
        adapter.setDatabasePlatform("org.eclipse.persistence.platform.database.PostgreSQLPlatform");
        adapter.setShowSql(true);

        return adapter;
    }

    private static Map<String, ?> initJpaProperties() {
        final Map<String, Object> map = new HashMap<>();
        map.put(PersistenceUnitProperties.WEAVING, "false");
        map.put(PersistenceUnitProperties.LOGGING_LEVEL, "INFO");
        map.put("eclipselink.logging.level.sql", "INFO");
        map.put(PersistenceUnitProperties.CACHE_SHARED_DEFAULT, "false");

        return map;
    }

    @Bean("defaultTransactionManager")
    public TransactionManager transactionManager(EntityManagerFactory entityManagerFactory) {
        return new JpaTransactionManager(entityManagerFactory);
    }

}