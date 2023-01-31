package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

/*-
 * #%L
 * spring-boot-starter-dingtalk
 * %%
 * Copyright (C) 2022 徐晓伟工作室
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.DingtalkService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryDingtalkService;
import org.springframework.security.oauth2.server.authorization.properties.DingtalkProperties;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

/**
 * 钉钉 dingtalk OAuth 2.0 配置器的实用方法。
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see OAuth2ConfigurerUtils
 */
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public class OAuth2DingtalkConfigurerUtils {

	public static OAuth2AuthorizationService getAuthorizationService(HttpSecurity httpSecurity) {
		return OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity);
	}

	public static OAuth2TokenGenerator<? extends OAuth2Token> getTokenGenerator(HttpSecurity httpSecurity) {
		return OAuth2ConfigurerUtils.getTokenGenerator(httpSecurity);
	}

	public static DingtalkService getDingtalkService(HttpSecurity httpSecurity) {
		DingtalkService dingtalkService = httpSecurity.getSharedObject(DingtalkService.class);
		if (dingtalkService == null) {
			dingtalkService = OAuth2ConfigurerUtils.getOptionalBean(httpSecurity, DingtalkService.class);
			if (dingtalkService == null) {
				DingtalkProperties dingtalkProperties = OAuth2ConfigurerUtils.getOptionalBean(httpSecurity,
						DingtalkProperties.class);
				dingtalkService = new InMemoryDingtalkService(dingtalkProperties);
			}
		}
		return dingtalkService;
	}

}
