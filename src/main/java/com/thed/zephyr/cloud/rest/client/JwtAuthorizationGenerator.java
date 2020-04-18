package com.thed.zephyr.cloud.rest.client;

import com.atlassian.connect.play.java.AC;
import com.atlassian.connect.play.java.AcHost;
import com.atlassian.connect.play.java.http.HttpMethod;
import com.atlassian.fugue.Option;
import com.atlassian.jwt.SigningAlgorithm;
import com.atlassian.jwt.core.TimeUtil;
import com.atlassian.jwt.core.writer.JsonSmartJwtJsonBuilder;
import com.atlassian.jwt.core.writer.JwtClaimsBuilder;
import com.atlassian.jwt.exception.JwtIssuerLacksSharedSecretException;
import com.atlassian.jwt.exception.JwtSigningException;
import com.atlassian.jwt.exception.JwtUnknownIssuerException;
import com.atlassian.jwt.httpclient.CanonicalHttpUriRequest;
import com.atlassian.jwt.writer.JwtJsonBuilder;
import com.atlassian.jwt.writer.JwtWriter;
import com.atlassian.jwt.writer.JwtWriterFactory;
import com.google.common.base.Function;
import com.google.common.base.Preconditions;
import com.google.common.collect.Maps;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicHeaderValueParser;
import org.apache.http.message.ParserCursor;
import org.apache.http.util.CharArrayBuffer;

public class JwtAuthorizationGenerator 
{
	private static final char[] QUERY_DELIMITERS = new char[]{'&'};
	private static final int JWT_EXPIRY_WINDOW_SECONDS_DEFAULT = 180;
	private final int jwtExpiryWindowSeconds;
	private final JwtWriterFactory jwtWriterFactory;

	public JwtAuthorizationGenerator(JwtWriterFactory jwtWriterFactory) 
	{
		this(jwtWriterFactory, JWT_EXPIRY_WINDOW_SECONDS_DEFAULT);
	}

	public JwtAuthorizationGenerator(JwtWriterFactory jwtWriterFactory, int jwtExpiryWindowSeconds) 
	{
		this.jwtWriterFactory = Preconditions.checkNotNull(jwtWriterFactory);
		this.jwtExpiryWindowSeconds = jwtExpiryWindowSeconds;
	}

	public Option<String> generate(String httpMethodStr, String url, Map<String, List<String>> parameters, AcHost acHost, Option<String> accountId) throws JwtIssuerLacksSharedSecretException, JwtUnknownIssuerException, URISyntaxException 
	{
		HttpMethod method = HttpMethod.valueOf(httpMethodStr);
		URI uri = new URI(url);
		String path = uri.getPath();
		URI baseUrl = new URI(acHost.getBaseUrl());
		String productContext = baseUrl.getPath();
		String pathWithoutProductContext = path.substring(productContext.length());
		URI uriWithoutProductContext = new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(), uri.getPort(), pathWithoutProductContext, uri.getQuery(), uri.getFragment());
		return this.generate(method, uriWithoutProductContext, parameters, acHost, accountId);
	}

	public Option<String> generate(HttpMethod httpMethod, URI url, Map<String, List<String>> parameters, AcHost acHost, Option<String> accountId) throws JwtIssuerLacksSharedSecretException, JwtUnknownIssuerException 
	{
		Preconditions.checkArgument(null != parameters, "Parameters Map argument cannot be null");
		Preconditions.checkNotNull(acHost);
		Map<String, String[]> paramsAsArrays = Maps.transformValues(parameters, new Function<List<String>, String[]>() 
		{
			@Override
			public String[] apply(List<String> input) 
			{
				return Preconditions.checkNotNull(input).toArray(new String[input.size()]);
			}
		});

		return Option.some("JWT " + this.encodeJwt(httpMethod, url, paramsAsArrays, accountId.getOrNull(), acHost));
	}

	private String encodeJwt(HttpMethod httpMethod, URI targetPath, Map<String, String[]> params, String accountId, AcHost acHost) throws JwtUnknownIssuerException, JwtIssuerLacksSharedSecretException 
	{
		Preconditions.checkArgument(null != httpMethod, "HttpMethod argument cannot be null");
		Preconditions.checkArgument(null != targetPath, "URI argument cannot be null");
		JwtJsonBuilder jsonBuilder = (new JsonSmartJwtJsonBuilder()).issuedAt(TimeUtil.currentTimeSeconds()).expirationTime(TimeUtil.currentTimePlusNSeconds((long)this.jwtExpiryWindowSeconds)).issuer(AC.PLUGIN_KEY).audience(acHost.getKey());
		if(null != accountId) 
		{
			jsonBuilder = jsonBuilder.subject(accountId);
		}

		Object completeParams = params;

		try 
		{
			if(!StringUtils.isEmpty(targetPath.getQuery())) 
			{
				completeParams = new HashMap<String, String[]>(params);
				((Map)completeParams).putAll(constructParameterMap(targetPath));
			}

			CanonicalHttpUriRequest e = new CanonicalHttpUriRequest(httpMethod.toString(), targetPath.getPath(), "", (Map<String, String[]>)completeParams);
			JwtClaimsBuilder.appendHttpRequestClaims(jsonBuilder, e);
		} 
		catch (UnsupportedEncodingException var9) 
		{
			throw new RuntimeException(var9);
		} 
		catch (NoSuchAlgorithmException var10) 
		{
			throw new RuntimeException(var10);
		}

		return this.issueJwt(jsonBuilder.build(), acHost);
	}

	private String issueJwt(String jsonPayload, AcHost acHost) throws JwtSigningException, JwtIssuerLacksSharedSecretException, JwtUnknownIssuerException 
	{
		return this.getJwtWriter(acHost).jsonToJwt(jsonPayload);
	}

	private JwtWriter getJwtWriter(AcHost acHost) throws JwtUnknownIssuerException, JwtIssuerLacksSharedSecretException 
	{
		return this.jwtWriterFactory.macSigningWriter(SigningAlgorithm.HS256, acHost.getSharedSecret());
	}

	private static Map<String, String[]> constructParameterMap(URI uri) throws UnsupportedEncodingException 
	{
		String query = uri.getQuery();
		if(query == null) 
		{
			return Collections.emptyMap();
		} 
		else 
		{
			HashMap<String, String[]> queryParams = new HashMap<String, String[]>();
			CharArrayBuffer buffer = new CharArrayBuffer(query.length());
			buffer.append(query);
			ParserCursor cursor = new ParserCursor(0, buffer.length());

			while(!cursor.atEnd()) 
			{
				NameValuePair nameValuePair = BasicHeaderValueParser.DEFAULT.parseNameValuePair(buffer, cursor, QUERY_DELIMITERS);
				if(!StringUtils.isEmpty(nameValuePair.getName())) 
				{
					String decodedName = urlDecode(nameValuePair.getName());
					String decodedValue = urlDecode(nameValuePair.getValue());
					String[] oldValues = queryParams.get(decodedName);
					String[] newValues = null == oldValues?new String[1]:Arrays.copyOf(oldValues, oldValues.length + 1);
					newValues[newValues.length - 1] = decodedValue;
					queryParams.put(decodedName, newValues);
				}
			}
			return queryParams;
		}
	}

	private static String urlDecode(String content) throws UnsupportedEncodingException 
	{
		return null == content?null: URLDecoder.decode(content, "UTF-8");
	}
}