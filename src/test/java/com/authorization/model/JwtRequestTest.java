package com.authorization.model;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;
import org.springframework.boot.test.context.SpringBootTest;

import com.authorization.model.JwtRequest;

@SpringBootTest
class JwtRequestTest {

	private JwtRequest jwtReqAllArg = new JwtRequest("admin", "password");

	@Test
	void testUserNameGetter() {
		assertThat(jwtReqAllArg.getUserName()).isEqualTo("admin");
	}
	
	@Test
    void testPensionerBean() {
        final BeanTester beanTester = new BeanTester();
        beanTester.getFactoryCollection();
        beanTester.testBean(JwtRequest.class);
    }


}
