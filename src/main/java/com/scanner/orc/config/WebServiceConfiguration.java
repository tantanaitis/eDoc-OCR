package com.scanner.orc.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.ws.config.annotation.EnableWs;
import org.springframework.ws.config.annotation.WsConfigurerAdapter;
import org.springframework.ws.server.EndpointInterceptor;
import org.springframework.ws.soap.security.wss4j2.Wss4jSecurityInterceptor;
import org.springframework.ws.soap.security.wss4j2.callback.KeyStoreCallbackHandler;
import org.springframework.ws.soap.security.wss4j2.support.CryptoFactoryBean;
import org.springframework.ws.transport.http.MessageDispatcherServlet;

import java.io.IOException;
import java.util.List;

/**
 * Created by titas on 15/10/2017.
 */
@EnableWs
@Configuration
public class WebServiceConfiguration extends WsConfigurerAdapter {

    @Value("${keystore.password}")
    private String keystorePassword;
    @Value("${keystore.name}")
    private String keystoreName;
    @Value("${keystore.alias}")
    private String keystoreAlias;


    @Bean
    public KeyStoreCallbackHandler securityCallbackHandler(){
        KeyStoreCallbackHandler callbackHandler = new KeyStoreCallbackHandler();
        callbackHandler.setPrivateKeyPassword(keystorePassword);
        return callbackHandler;
    }

    @Bean
    public Wss4jSecurityInterceptor securityInterceptor() throws Exception {
        Wss4jSecurityInterceptor securityInterceptor = new Wss4jSecurityInterceptor();


        securityInterceptor.setValidationActions("Timestamp Signature Encrypt");
        securityInterceptor.setValidationSignatureCrypto(getCryptoFactoryBean().getObject());
        securityInterceptor.setValidationDecryptionCrypto(getCryptoFactoryBean().getObject());
        securityInterceptor.setValidationCallbackHandler(securityCallbackHandler());


        securityInterceptor.setSecurementEncryptionUser(keystoreAlias);
        /*securityInterceptor.setSecurementEncryptionParts("{Content}{http://memorynotfound.com/beer}getBeerResponse");*/
        securityInterceptor.setSecurementEncryptionCrypto(getCryptoFactoryBean().getObject());


        securityInterceptor.setSecurementActions("Timestamp Signature Encrypt");
        securityInterceptor.setSecurementUsername(keystoreAlias);
        securityInterceptor.setSecurementPassword(keystorePassword);
        securityInterceptor.setSecurementSignatureCrypto(getCryptoFactoryBean().getObject());

        return securityInterceptor;
    }

    @Bean
    public CryptoFactoryBean getCryptoFactoryBean() throws IOException {
        CryptoFactoryBean cryptoFactoryBean = new CryptoFactoryBean();
        cryptoFactoryBean.setKeyStorePassword(keystorePassword);
        cryptoFactoryBean.setKeyStoreLocation(new ClassPathResource(keystoreName));
        return cryptoFactoryBean;
    }

    @Override
    public void addInterceptors(List<EndpointInterceptor> interceptors) {
        try {
            interceptors.add(securityInterceptor());
        } catch (Exception e) {
            throw new RuntimeException(e + "\n could not initialize security interceptor");
        }
    }

    @Bean
    public ServletRegistrationBean messageDispatcherServlet(ApplicationContext appContext){
        MessageDispatcherServlet servlet = new MessageDispatcherServlet();
        servlet.setApplicationContext(appContext);
        servlet.setTransformWsdlLocations(true);
        return new ServletRegistrationBean(servlet, "/*");
    }
}
