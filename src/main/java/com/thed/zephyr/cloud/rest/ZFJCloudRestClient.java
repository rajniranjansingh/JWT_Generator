package com.thed.zephyr.cloud.rest;

import com.thed.zephyr.cloud.rest.client.*;
import com.thed.zephyr.cloud.rest.client.impl.*;
import com.thed.zephyr.cloud.rest.model.ZConfig;

public class ZFJCloudRestClient 
{
	private JwtGenerator jwtGenerator;

	private ZFJCloudRestClient() 
	{

	}

	public static Builder  restBuilder(String zephyrBaseUrl, String accessKey, String secretKey,  String accountId)
	{
		return new ZFJCloudRestClient().new Builder(zephyrBaseUrl, accessKey, secretKey, accountId);
	}

	public JwtGenerator getJwtGenerator()
	{
		return jwtGenerator;
	}

	public class Builder 
	{
		private String accessKey;
		private String secretKey;
		private String accountId;
		private String zephyrBaseUrl;

		private Builder(String zephyrBaseUrl, String accessKey, String secretKey, String accountId) 
		{
			this.zephyrBaseUrl = zephyrBaseUrl;
			this.accessKey = accessKey;
			this.secretKey = secretKey;
			this.accountId = accountId;
		}

		public ZFJCloudRestClient build() 
		{
			ZConfig zConfig = new ZConfig(accessKey, secretKey, accountId, zephyrBaseUrl);
			jwtGenerator = new JwtGeneratorImpl(zConfig);

			return ZFJCloudRestClient.this;
		}
	}
}
