package org.springframework.security.oauth2.server.authorization.client;

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

import com.aliyun.dingtalkcontact_1_0.models.GetUserHeaders;
import com.aliyun.dingtalkcontact_1_0.models.GetUserResponse;
import com.aliyun.dingtalkcontact_1_0.models.GetUserResponseBody;
import com.aliyun.dingtalkoauth2_1_0.models.GetUserTokenRequest;
import com.aliyun.dingtalkoauth2_1_0.models.GetUserTokenResponse;
import com.aliyun.dingtalkoauth2_1_0.models.GetUserTokenResponseBody;
import com.aliyun.teaopenapi.models.Config;
import com.aliyun.teautil.models.RuntimeOptions;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.BeanUtils;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.DingtalkAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2TokenEndpointConfigurer;
import org.springframework.security.oauth2.server.authorization.exception.AppidDingtalkException;
import org.springframework.security.oauth2.server.authorization.exception.RedirectDingtalkException;
import org.springframework.security.oauth2.server.authorization.exception.RedirectUriDingtalkException;
import org.springframework.security.oauth2.server.authorization.properties.DingtalkProperties;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2DingtalkEndpointUtils;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * 钉钉 dingtalk 账户服务接口 基于内存的实现
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class InMemoryDingtalkService implements DingtalkService {

	private final DingtalkProperties dingtalkProperties;

	public InMemoryDingtalkService(DingtalkProperties dingtalkProperties) {
		this.dingtalkProperties = dingtalkProperties;
	}

	/**
	 * 根据 appid 获取重定向的地址
	 * @param appid 开放平台 ID
	 * @return 返回重定向的地址
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public String getRedirectUriByAppid(String appid) throws OAuth2AuthenticationException {
		DingtalkProperties.Dingtalk dingtalk = getDingtalkByAppid(appid);
		String redirectUriPrefix = dingtalk.getRedirectUriPrefix();

		if (StringUtils.hasText(redirectUriPrefix)) {
			return UriUtils.encode(redirectUriPrefix + "/" + appid, StandardCharsets.UTF_8);
		}
		else {
			OAuth2Error error = new OAuth2Error(OAuth2DingtalkEndpointUtils.ERROR_CODE, "重定向地址前缀不能为空", null);
			throw new RedirectUriDingtalkException(error);
		}
	}

	/**
	 * 生成状态码
	 * @param request 请求
	 * @param response 响应
	 * @param appid 开放平台 ID
	 * @return 返回生成的授权码
	 */
	@Override
	public String stateGenerate(HttpServletRequest request, HttpServletResponse response, String appid) {
		return UUID.randomUUID().toString();
	}

	/**
	 * 储存绑定参数
	 * @param request 请求
	 * @param response 响应
	 * @param appid 开放平台 ID
	 * @param state 状态码
	 * @param binding 绑定参数
	 */
	@Override
	public void storeBinding(HttpServletRequest request, HttpServletResponse response, String appid, String state,
			String binding) {

	}

	/**
	 * 储存操作用户
	 * @param request 请求
	 * @param response 响应
	 * @param appid 开放平台 ID
	 * @param state 状态码
	 * @param binding 绑定参数
	 */
	@Override
	public void storeUsers(HttpServletRequest request, HttpServletResponse response, String appid, String state,
			String binding) {

	}

	/**
	 * 状态码验证（返回 {@link Boolean#FALSE} 时，将终止后面需要执行的代码）
	 * @param request 请求
	 * @param response 响应
	 * @param appid 开放平台 ID
	 * @param code 授权码
	 * @param state 状态码
	 * @return 返回 状态码验证结果
	 */
	@Override
	public boolean stateValid(HttpServletRequest request, HttpServletResponse response, String appid, String code,
			String state) {
		return true;
	}

	/**
	 * 获取 绑定参数
	 * @param request 请求
	 * @param response 响应
	 * @param appid 开放平台 ID
	 * @param code 授权码
	 * @param state 状态码
	 * @return 返回 绑定参数
	 */
	@Override
	public String getBinding(HttpServletRequest request, HttpServletResponse response, String appid, String code,
			String state) {
		return null;
	}

	/**
	 * 根据 appid 获取 钉钉 dingtalk 属性配置
	 * @param appid 公众号ID
	 * @return 返回 钉钉 dingtalk 属性配置
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public DingtalkProperties.Dingtalk getDingtalkByAppid(String appid) throws OAuth2AuthenticationException {
		List<DingtalkProperties.Dingtalk> list = dingtalkProperties.getList();
		if (list == null) {
			OAuth2Error error = new OAuth2Error(OAuth2DingtalkEndpointUtils.ERROR_CODE, "appid 未配置", null);
			throw new AppidDingtalkException(error);
		}

		for (DingtalkProperties.Dingtalk dingtalk : list) {
			if (appid.equals(dingtalk.getAppid())) {
				return dingtalk;
			}
		}
		OAuth2Error error = new OAuth2Error(OAuth2DingtalkEndpointUtils.ERROR_CODE, "未匹配到 appid", null);
		throw new AppidDingtalkException(error);
	}

	/**
	 * 获取 OAuth 2.1 授权 Token（如果不想执行此方法后面的内容，可返回 null）
	 * @param request 请求
	 * @param response 响应
	 * @param clientId 客户ID
	 * @param clientSecret 客户凭证
	 * @param tokenUrlPrefix 获取 Token URL 前缀
	 * @param tokenUrl Token URL
	 * @param uriVariables 参数
	 * @return 返回 OAuth 2.1 授权 Token
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@SuppressWarnings("AlibabaLowerCamelCaseVariableNaming")
	@Override
	public OAuth2AccessTokenResponse getOAuth2AccessTokenResponse(HttpServletRequest request,
			HttpServletResponse response, String clientId, String clientSecret, String tokenUrlPrefix, String tokenUrl,
			Map<String, String> uriVariables) throws OAuth2AuthenticationException {

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setContentType(MediaType.MULTIPART_FORM_DATA);

		MultiValueMap<String, String> multiValueMap = new LinkedMultiValueMap<>(8);
		multiValueMap.put(OAuth2ParameterNames.CLIENT_ID, Collections.singletonList(clientId));
		multiValueMap.put(OAuth2ParameterNames.CLIENT_SECRET, Collections.singletonList(clientSecret));

		HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(multiValueMap, httpHeaders);
		RestTemplate restTemplate = new RestTemplate();
		List<HttpMessageConverter<?>> messageConverters = restTemplate.getMessageConverters();
		messageConverters.add(5, new OAuth2AccessTokenResponseHttpMessageConverter());

		return restTemplate.postForObject(tokenUrlPrefix + tokenUrl, httpEntity, OAuth2AccessTokenResponse.class,
				uriVariables);
	}

	/**
	 * 根据 AppID、code、accessTokenUrl 获取Token
	 * @param appid AppID
	 * @param code 授权码
	 * @param state 状态码
	 * @param binding 是否绑定，需要使用者自己去拓展
	 * @param remoteAddress 用户IP
	 * @param sessionId SessionID
	 * @return 返回 钉钉 dingtalk 授权结果
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public DingtalkTokenResponse getAccessTokenResponse(String appid, String code, String state, String binding,
			String remoteAddress, String sessionId) throws OAuth2AuthenticationException {

		DingtalkProperties.Dingtalk dingtalk = getDingtalkByAppid(appid);
		String secret = dingtalk.getSecret();

		Config config = new Config();
		config.protocol = "https";
		config.regionId = "central";
		com.aliyun.dingtalkoauth2_1_0.Client authClient;
		try {
			authClient = new com.aliyun.dingtalkoauth2_1_0.Client(config);
		}
		catch (Exception e) {
			OAuth2Error error = new OAuth2Error(OAuth2DingtalkEndpointUtils.ERROR_CODE, "创建 钉钉 dingtalk 授权配置异常",
					OAuth2DingtalkEndpointUtils.AUTH_CODE2SESSION_URI);
			throw new OAuth2AuthenticationException(error, e);
		}

		// @formatter:off
		GetUserTokenRequest getUserTokenRequest = new GetUserTokenRequest()
				// 应用基础信息-应用信息的AppKey,请务必替换为开发的应用AppKey
				.setClientId(appid)
				// 应用基础信息-应用信息的AppSecret，,请务必替换为开发的应用AppSecret
				.setClientSecret(secret)
				.setCode(code)
				.setGrantType("authorization_code");
		// @formatter:on

		GetUserTokenResponse getUserTokenResponse;
		try {
			getUserTokenResponse = authClient.getUserToken(getUserTokenRequest);
		}
		catch (Exception e) {
			OAuth2Error error = new OAuth2Error(OAuth2DingtalkEndpointUtils.ERROR_CODE,
					"使用 钉钉 dingtalk 授权code：" + code + " 获取Token异常", OAuth2DingtalkEndpointUtils.AUTH_CODE2SESSION_URI);
			throw new OAuth2AuthenticationException(error, e);
		}

		// 获取用户个人token
		GetUserTokenResponseBody getUserTokenResponseBody = getUserTokenResponse.getBody();
		String accessToken = getUserTokenResponseBody.getAccessToken();

		com.aliyun.dingtalkcontact_1_0.Client contactClient;
		try {
			contactClient = new com.aliyun.dingtalkcontact_1_0.Client(config);
		}
		catch (Exception e) {
			OAuth2Error error = new OAuth2Error(OAuth2DingtalkEndpointUtils.ERROR_CODE, "创建 钉钉 dingtalk 联系客户配置异常",
					OAuth2DingtalkEndpointUtils.AUTH_CODE2SESSION_URI);
			throw new OAuth2AuthenticationException(error, e);
		}

		GetUserHeaders getUserHeaders = new GetUserHeaders();
		getUserHeaders.xAcsDingtalkAccessToken = accessToken;
		// 获取用户个人信息，如需获取当前授权人的信息，unionId参数必须传me
		GetUserResponse getUserResponse;
		try {
			getUserResponse = contactClient.getUserWithOptions("me", getUserHeaders, new RuntimeOptions());
		}
		catch (Exception e) {
			OAuth2Error error = new OAuth2Error(OAuth2DingtalkEndpointUtils.ERROR_CODE, "使用 钉钉 dingtalk 获取用户个人信息异常",
					OAuth2DingtalkEndpointUtils.AUTH_CODE2SESSION_URI);
			throw new OAuth2AuthenticationException(error, e);
		}
		GetUserResponseBody getUserResponseBody = getUserResponse.getBody();

		DingtalkTokenResponse accessTokenResponse = new DingtalkTokenResponse();
		BeanUtils.copyProperties(getUserTokenResponseBody, accessTokenResponse);
		BeanUtils.copyProperties(getUserResponseBody, accessTokenResponse);

		return accessTokenResponse;
	}

	/**
	 * 构建 钉钉 dingtalk 认证信息
	 * @param clientPrincipal 经过身份验证的客户端主体
	 * @param additionalParameters 附加参数
	 * @param details 登录信息
	 * @param appid AppID
	 * @param code 授权码
	 * @param openId 用户唯一标识
	 * @param credentials 证书
	 * @param unionId 多账户用户唯一标识
	 * @param accessToken 授权凭证
	 * @param refreshToken 刷新凭证
	 * @param expiresIn 过期时间
	 * @return 返回 认证信息
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public AbstractAuthenticationToken authenticationToken(Authentication clientPrincipal,
			Map<String, Object> additionalParameters, Object details, String appid, String code, String openId,
			Object credentials, String unionId, String accessToken, String refreshToken, Long expiresIn)
			throws OAuth2AuthenticationException {
		List<GrantedAuthority> authorities = new ArrayList<>();
		SimpleGrantedAuthority authority = new SimpleGrantedAuthority(dingtalkProperties.getDefaultRole());
		authorities.add(authority);
		User user = new User(openId, accessToken, authorities);

		UsernamePasswordAuthenticationToken principal = UsernamePasswordAuthenticationToken.authenticated(user, null,
				user.getAuthorities());

		DingtalkAuthenticationToken authenticationToken = new DingtalkAuthenticationToken(authorities, clientPrincipal,
				principal, user, additionalParameters, details, appid, code, openId);

		authenticationToken.setCredentials(credentials);
		authenticationToken.setUnionId(unionId);

		return authenticationToken;
	}

	/**
	 * 授权成功重定向方法
	 * @param request 请求
	 * @param response 响应
	 * @param uriVariables 参数
	 * @param oauth2AccessTokenResponse OAuth2.1 授权 Token
	 * @param dingtalk 钉钉 dingtalk 配置
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public void sendRedirect(HttpServletRequest request, HttpServletResponse response, Map<String, String> uriVariables,
			OAuth2AccessTokenResponse oauth2AccessTokenResponse, DingtalkProperties.Dingtalk dingtalk)
			throws OAuth2AuthenticationException {

		OAuth2AccessToken accessToken = oauth2AccessTokenResponse.getAccessToken();

		try {
			response.sendRedirect(
					dingtalk.getSuccessUrl() + "?" + dingtalk.getParameterName() + "=" + accessToken.getTokenValue());
		}
		catch (IOException e) {
			OAuth2Error error = new OAuth2Error(OAuth2DingtalkEndpointUtils.ERROR_CODE, "钉钉 dingtalk 重定向异常", null);
			throw new RedirectDingtalkException(error, e);
		}

	}

}
