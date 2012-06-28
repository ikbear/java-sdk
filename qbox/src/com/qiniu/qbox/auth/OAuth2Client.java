package com.qiniu.qbox.auth;

import java.io.UnsupportedEncodingException;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.http.HttpMessage;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONException;

import com.qiniu.qbox.Config;

public class OAuth2Client extends Client {

	private String authUrl;
	private String tokenUrl;
	private String clientId;
	private String clientSecret;
	private String accessToken;
	private String refreshToken;

	public OAuth2Client() {
		this.authUrl = Config.AUTHORIZATION_ENDPOINT;
		this.tokenUrl = Config.TOKEN_ENDPOINT;
		this.clientId = "a75604760c4da4caaa456c0c5895c061c3065c5a";
		this.clientSecret = "75df554a39f58accb7eb293b550fa59618674b7d";
	}

	public OAuth2Client(String authUrl, String tokenUrl, String clientId,
			String clientSecret) {

		this.authUrl = authUrl;
		this.tokenUrl = tokenUrl;
		this.clientId = clientId;
		this.clientSecret = clientSecret;
	}

	public String createAuthUrl(Collection<String> scope, String redirectUri,
			String state) {
		String scopeStr = "";
		if (scope.size() > 0) {
			for (Iterator<String> i = scope.iterator(); i.hasNext(); i.next()) {
				if (!scopeStr.isEmpty()) {
					scopeStr += " ";
				}
				scopeStr += i.toString();
			}
		}

		String url = "";
		try {
			url = String
					.format("%s?client_id=%s&redirect_uri=%s&scope=%s&response_type=code",
							this.authUrl,
							URLEncoder.encode(this.clientId, "UTF-8"),
							URLEncoder.encode(redirectUri, "UTF-8"),
							URLEncoder.encode(scopeStr, "UTF-8"));
			if (!state.isEmpty()) {
				url += String.format("&state=%s", state);
			}
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return url;
	}

	public AuthRet exchange(String code, String redirectUri) {
		
		List<NameValuePair> nvps = new ArrayList<NameValuePair>();
		nvps.add(new BasicNameValuePair("client_id", this.clientId));
		nvps.add(new BasicNameValuePair("client_secret", this.clientSecret));
		nvps.add(new BasicNameValuePair("code", code));
		nvps.add(new BasicNameValuePair("redirect_uri", redirectUri));
		nvps.add(new BasicNameValuePair("grant_type", "authorization_code"));

		return authPost(nvps);
	}

	public AuthRet exchangeByPassword(String userName, String password) {

		List<NameValuePair> nvps = new ArrayList<NameValuePair>();
		nvps.add(new BasicNameValuePair("client_id", this.clientId));
		nvps.add(new BasicNameValuePair("client_secret", this.clientSecret));
		nvps.add(new BasicNameValuePair("username", userName));
		nvps.add(new BasicNameValuePair("password", password));
		nvps.add(new BasicNameValuePair("grant_type", "password"));

		return authPost(nvps);
	}

	public AuthRet exchangeByRefreshToken(String token) {

		List<NameValuePair> nvps = new ArrayList<NameValuePair>();
		nvps.add(new BasicNameValuePair("client_id", this.clientId));
		nvps.add(new BasicNameValuePair("client_secret", this.clientSecret));
		nvps.add(new BasicNameValuePair("refresh_token", this.refreshToken));
		nvps.add(new BasicNameValuePair("grant_type", "refresh_token"));

		return authPost(nvps);
	}

	public String exchangeBySignature(String url, HashMap<String, String> params){
		String accessKey = Config.ACCESS_KEY;
		byte[] secretKey = Config.SECRET_KEY.getBytes();
		byte[] digestBase64 = {};
		String signature;
		
		try {
			URL aURL = new URL(url);
			signature = aURL.getPath();
			String query_string = aURL.getQuery();
			if (query_string != null) {
				signature += "?" + query_string;
			}
			signature += "\n";
			Iterator iter = params.entrySet().iterator(); 
			while (iter.hasNext()) { 
			    Map.Entry entry = (Map.Entry) iter.next(); 
			    String key = (String) entry.getKey(); 
			    String val = (String) entry.getValue(); 
			    signature += (key + "=" + val);
			    if (iter.hasNext()) {
			    	signature += "&";
			    }
			}
						
			Mac mac = Mac.getInstance("HmacSHA1");
			SecretKeySpec keySpec = new SecretKeySpec(secretKey, "HmacSHA1");
			mac.init(keySpec);
			
			byte[] signatureBase64 = Client.urlsafeEncodeBytes(signature.getBytes());
			byte[] digest = mac.doFinal(signatureBase64);
			digestBase64 = Client.urlsafeEncodeBytes(digest);
	
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (MalformedURLException e) {
			e.printStackTrace();
		} 
		
		String digest = new String(digestBase64);
		return accessKey + ":" + digest;
	}
	
	private AuthRet authPost(List<NameValuePair> nvps) {
		
		CallRet ret = call(this.tokenUrl, nvps);
		if (ret.ok()) {
			return handleResult(ret.getResponse());
		}
		return new AuthRet(ret);
	}

	private AuthRet handleResult(String responseBody) {
		
		AuthRet authRet = new AuthRet(new CallRet(200, responseBody));
		this.accessToken = authRet.getAccessToken();
		this.refreshToken = authRet.getRefreshToken();

		return authRet;
	}

	@Override
	public void setAuth(HttpMessage httpMessage) {
		if (this.accessToken != null) {
			httpMessage.setHeader("Authorization", "Bearer " + this.accessToken);
		}
	}
}
