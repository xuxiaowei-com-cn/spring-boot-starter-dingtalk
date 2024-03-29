package org.springframework.security.authentication;

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

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.access.intercept.RunAsUserToken;
import org.springframework.security.authentication.jaas.JaasAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * 钉钉 dingtalk 登录认证令牌
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see RunAsUserToken
 * @see AnonymousAuthenticationToken
 * @see RememberMeAuthenticationToken
 * @see TestingAuthenticationToken
 * @see UsernamePasswordAuthenticationToken
 * @see JaasAuthenticationToken
 * @see OAuth2AccessTokenAuthenticationToken
 * @see OAuth2AuthorizationCodeAuthenticationToken
 * @see OAuth2AuthorizationCodeRequestAuthenticationToken
 * @see OAuth2AuthorizationGrantAuthenticationToken
 * @see OAuth2ClientAuthenticationToken
 * @see OAuth2ClientCredentialsAuthenticationToken
 * @see OAuth2RefreshTokenAuthenticationToken
 * @see OAuth2TokenIntrospectionAuthenticationToken
 * @see OAuth2TokenRevocationAuthenticationToken
 * @see OidcClientRegistrationAuthenticationToken
 * @see OidcUserInfoAuthenticationToken
 * @see BearerTokenAuthenticationToken
 * @see AbstractOAuth2TokenAuthenticationToken
 * @see BearerTokenAuthentication
 * @see JwtAuthenticationToken
 * @see PreAuthenticatedAuthenticationToken
 */
public class DingtalkAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	/**
	 * 授权类型：钉钉 dingtalk
	 */
	@Getter
	private final AuthorizationGrantType authorizationGrantType;

	@Setter
	private Object credentials;

	/**
	 * 经过身份验证的客户端主体
	 */
	@Getter
	private final Authentication clientPrincipal;

	/**
	 * 经过身份验证的 钉钉 dingtalk 主体
	 */
	private final Authentication principal;

	/**
	 * 用户信息
	 */
	@Getter
	private final UserDetails userDetails;

	/**
	 * 附加参数
	 */
	@Getter
	private final Map<String, Object> additionalParameters;

	@Getter
	private final Collection<GrantedAuthority> authorities;

	@Getter
	private final Object details;

	/**
	 * AppID
	 */
	@Getter
	private final String appid;

	/**
	
	 */
	@Getter
	private final String code;

	/**
	
	 */
	@Getter
	private final String openId;

	/**
	
	 */
	@Getter
	@Setter
	private String unionId;

	public DingtalkAuthenticationToken(Collection<? extends GrantedAuthority> authorities,
			Authentication clientPrincipal, Authentication principal, UserDetails userDetails,
			Map<String, Object> additionalParameters, Object details, String appid, String code, String openId) {
		super(authorities);
		Assert.notNull(authorities, "authorities 不能为空");
		Assert.notNull(clientPrincipal, "clientPrincipal 不能为空");
		Assert.notNull(principal, "principal 不能为空");
		Assert.notNull(userDetails, "userDetails 不能为空");
		Assert.notNull(appid, "appid 不能为空");
		Assert.notNull(openId, "openId 不能为空");
		this.authorizationGrantType = OAuth2DingtalkAuthenticationToken.DINGTALK;
		this.clientPrincipal = clientPrincipal;
		this.principal = principal;
		this.userDetails = userDetails;
		this.additionalParameters = Collections.unmodifiableMap(
				additionalParameters != null ? new HashMap<>(additionalParameters) : Collections.emptyMap());
		this.authorities = Collections.unmodifiableCollection(authorities);
		this.details = details;
		this.appid = appid;
		this.code = code;
		this.openId = openId;
	}

	@Override
	public Object getCredentials() {
		return this.credentials;
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

}
