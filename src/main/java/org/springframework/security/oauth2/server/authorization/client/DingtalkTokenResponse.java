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

import lombok.Data;

import java.io.Serializable;

/**
 * 通过 code 换取网页授权 access_token 返回值
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@Data
public class DingtalkTokenResponse implements Serializable {

	private static final long serialVersionUID = 1L;

	private String accessToken;

	/**
	 * 所选企业corpId
	 */
	private String corpId;

	/**
	 * 超时时间
	 */
	private Long expireIn;

	private String refreshToken;

	/**
	 * 头像url
	 */
	private String avatarUrl;

	/**
	 * 个人邮箱
	 */
	private String email;

	/**
	 * 手机号
	 */
	private String mobile;

	/**
	 * 昵称
	 */
	private String nick;

	/**
	 * openId
	 */
	private String openId;

	/**
	 * 手机号对应的国家号
	 */
	private String stateCode;

	/**
	 * unionId
	 */
	private String unionId;

}
