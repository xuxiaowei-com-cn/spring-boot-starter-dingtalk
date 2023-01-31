package org.springframework.security.oauth2.server.authorization.http;

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

import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.endpoint.OAuth2DingtalkParameterNames;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.DingtalkService;
import org.springframework.security.oauth2.server.authorization.properties.DingtalkProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 钉钉 dingtalk 跳转到 钉钉 dingtalk 授权页面
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@Slf4j
@Data
@EqualsAndHashCode(callSuper = true)
@Component
public class DingtalkAuthorizeHttpFilter extends HttpFilter {

	public static final String PREFIX_URL = "/dingtalk/authorize";

	/**
	 * @see <a href=
	 * "https://open.dingtalk.com/document/orgapp-server/tutorial-obtaining-user-personal-information">实现登录第三方网站</a>
	 */
	public static final String AUTHORIZE_URL = "https://login.dingtalk.com/oauth2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s&prompt=consent";

	/**
	 * 授权后可获得用户userid
	 */
	public static final String OPENID = "openid";

	/**
	 * 授权后可获得用户id和登录过程中用户选择的组织id，空格分隔。注意url编码。
	 * <p>
	 * 与 {@link #OPENID} 同时使用
	 */
	public static final String CORPID = "corpid";

	private DingtalkProperties dingtalkProperties;

	private DingtalkService dingtalkService;

	/**
	 * 钉钉 dingtalk 授权前缀
	 */
	private String prefixUrl = PREFIX_URL;

	@Autowired
	public void setDingtalkProperties(DingtalkProperties dingtalkProperties) {
		this.dingtalkProperties = dingtalkProperties;
	}

	@Autowired
	public void setDingtalkService(DingtalkService dingtalkService) {
		this.dingtalkService = dingtalkService;
	}

	@Override
	protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String requestUri = request.getRequestURI();
		AntPathMatcher antPathMatcher = new AntPathMatcher();
		boolean match = antPathMatcher.match(prefixUrl + "/*", requestUri);
		if (match) {
			log.info("requestUri：{}", requestUri);

			String appid = requestUri.replace(prefixUrl + "/", "");

			String redirectUri = dingtalkService.getRedirectUriByAppid(appid);

			String binding = request.getParameter(OAuth2DingtalkParameterNames.BINDING);
			String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
			String scopeResult;
			if (scope == null) {
				scopeResult = OPENID;
			}
			else {
				List<String> scopeList = Splitter.on(" ").trimResults().splitToList(scope);
				List<String> legalList = Collections.singletonList(CORPID);
				Set<String> scopeResultSet = new HashSet<>();
				scopeResultSet.add(OPENID);
				for (String sc : scopeList) {
					if (legalList.contains(sc)) {
						scopeResultSet.add(sc);
					}
				}
				scopeResult = Joiner.on(" ").join(scopeResultSet);
			}

			String state = dingtalkService.stateGenerate(request, response, appid);
			dingtalkService.storeBinding(request, response, appid, state, binding);
			dingtalkService.storeUsers(request, response, appid, state, binding);

			String url = String.format(AUTHORIZE_URL, appid, redirectUri, scopeResult, state);

			log.info("redirectUrl：{}", url);

			response.sendRedirect(url);
			return;
		}

		super.doFilter(request, response, chain);
	}

}
