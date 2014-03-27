package weibo;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpException;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.ParseException;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.params.CookiePolicy;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.protocol.HTTP;
import org.apache.http.util.EntityUtils;
import org.json.JSONException;
import org.json.JSONObject;

import bit.mirror.weibo.auth.LoginFailureException;

public class WeiboLogin {
	public final static String SINA_PKN = "EB2A38568661887FA180BDDB5CABD5F21C7BFD59C090CB2D24"
			+ "5A87AC253062882729293E5506350508E7F9AA3BB77F4333231490F915F6D63C55FE2F08A49B353F444AD39"
			+ "93CACC02DB784ABBB8E42A9B1BBFFFB38BE18D78E87A0E41B9B8F73A928EE0CCEE"
			+ "1F6739884B9777E4FE9E88A1BBE495927AC4A799B3181D6442443";
	public final static String SINA_PKE = "10001";

	//public final static String LOGIN_URL 	= "http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.5)"; 		//this is old by pre-author
	public final static String LOGIN_URL 	= "http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.11)";   	//this is new by Qinger
	public final static String GET_AJAX_URL = "http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack&sudaref=weibo.com";
	public final static String POST_AJAX_URL= "http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack";
	
	public final static String REDIRECTURL 	= "location.replace\\(\"(.*?)\"\\)";
	public final static String URLSTRING	= "http:(.*?)=0";
	
	private DefaultHttpClient dhc;
	private String nonce;
	private String servertime;
	private String sp;			//Post登录时，sp为加密后的password
	private String cookie;		// httpclient�����Ǳ����ύ�Ĳ����ʾ�Ѿ���¼��
	private String su;			//Post登录时，su为加密后的username
	private String account;		//初始账户
	private String password;	//初始密码

	public WeiboLogin(String account, String password) {
		this.account = account;
		this.password = password;
		this.cookie = null;
		this.su = encodeUserName(account);
	}

	public WeiboLogin(String account, String password, DefaultHttpClient dhc) {
		this.dhc = dhc;
		this.account = account;
		this.password = password;
		this.cookie = null;
		this.su = encodeUserName(account);
	}

	public void try2Login() throws HttpException, IOException, JSONException,
			LoginFailureException {
		dhc.getParams().setParameter("http.protocol.cookie-policy",
				CookiePolicy.BROWSER_COMPATIBILITY);
		dhc.getParams().setParameter(HttpConnectionParams.CONNECTION_TIMEOUT,
				5000);
		
		//首先get一次数据，用于后续的登录
		PreLoginInfo info = getPreLoginBean(dhc);
		
		//下面进行第三步，POST参数。重点在su和sp的加密是否正确，然后是返回结果是否正常
		if (0 != info.getRetcode()) {
			LoginFailureException failException = new LoginFailureException(
					"PreLogin fail!");
			throw failException;
		} else {
			nonce = info.getNonce();
			servertime = "" + info.getServertime();
			String pwdString = servertime + "\t" + nonce + "\n" + password;
			sp = SinaEncoder.RSAEncrypt(pwdString, SINA_PKN, SINA_PKE);
			HttpPost post = new HttpPost(LOGIN_URL);

			List<NameValuePair> nvps = new ArrayList<NameValuePair>();
			nvps.add(new BasicNameValuePair("entry", "weibo"));
			nvps.add(new BasicNameValuePair("gateway", "1"));
			nvps.add(new BasicNameValuePair("from", ""));
			nvps.add(new BasicNameValuePair("savestate", "7"));
			nvps.add(new BasicNameValuePair("useticket", "1"));
			nvps.add(new BasicNameValuePair("ssosimplelogin", "1"));
			nvps.add(new BasicNameValuePair("vsnf", "1"));
			nvps.add(new BasicNameValuePair("su", SinaEncoder
					.encodeAccount(account)));
			nvps.add(new BasicNameValuePair("service", "miniblog"));
			nvps.add(new BasicNameValuePair("servertime", servertime + ""));
			nvps.add(new BasicNameValuePair("nonce", nonce));
			nvps.add(new BasicNameValuePair("pwencode", "rsa2"));
			nvps.add(new BasicNameValuePair("rsakv", info.rsakv));
			nvps.add(new BasicNameValuePair("sp", sp));
			nvps.add(new BasicNameValuePair("encoding", "UTF-8"));
			nvps.add(new BasicNameValuePair("prelt", "115"));
			nvps.add(new BasicNameValuePair("returntype", "META"));
			nvps.add(new BasicNameValuePair("url", POST_AJAX_URL));

			post.setEntity(new UrlEncodedFormEntity(nvps, HTTP.UTF_8));
			HttpResponse response = dhc.execute(post);
			
			//I don't know why the preAuthor write it. And i guess that he wants to visit 
			 //the url with the cookies, but i don't know wwhether it's right or not cuz it's iregular on the Internet. 
			String cookiestr;
			cookie = "";
			for (int i = 0; i < response.getHeaders("Set-Cookie").length; i++) {
				cookiestr = response.getHeaders("Set-Cookie")[i].toString()
						.replace("Set-Cookie:", "").trim();
				cookie += cookiestr.substring(0, cookiestr.indexOf(";")) + ";";

			}
			if (!cookie.contains("SUE") || !cookie.contains("SUP")
					|| cookie.contains("SUE=deleted")
					|| cookie.contains("SUP=deleted")) {
				throw new LoginFailureException(
						"Login failed!Can't get cookie!Cookie:" + cookie);
			}
			//EntityUtils.toString(response.getEntity());
			//HttpGet getMethod = new HttpGet(GET_AJAX_URL);
			//getMethod.setHeader("cookie", cookie);
			//response = dhc.execute(getMethod);
			//EntityUtils.toString(response.getEntity());
		
			String loginUrl = getRedirectUrl(response);
			EntityUtils.toString(response.getEntity());
			HttpGet login = new HttpGet(loginUrl);
			login.setHeader("cookie", cookie);
			EntityUtils.toString(dhc.execute(login).getEntity());
		}

	}

	/**
	 * 
	 * @param response
	 * @return
	 * @throws IOException 
	 * @throws ParseException 
	 * @throws LoginFailureException 
	 */
	private String getRedirectUrl(HttpResponse response) throws ParseException, IOException, LoginFailureException {
		String text = EntityUtils.toString(response.getEntity());
		Pattern scrp = Pattern.compile(REDIRECTURL);
		Matcher scrm = scrp.matcher(text);
		String script = "";
		if(scrm.find())
			script = scrm.group(0);
		Pattern urlp = Pattern.compile(URLSTRING);
		Matcher urlm = urlp.matcher(script);
		if(urlm.find())
			return urlm.group(0);
		LoginFailureException failException = new LoginFailureException(
				"login RedirectUrl fail!");
		throw failException;
	}
	
	private PreLoginInfo getPreLoginBean(HttpClient client)
			throws HttpException, IOException, JSONException {

		/**
		 * 首先向新浪服务器GET数据，返回结果是一个JSON结构的字符串。从Json中取出这些数值
		 */
		String serverTime = getPreLoginInfo(client);
		JSONObject jsonInfo = new JSONObject(serverTime);
		
		
		PreLoginInfo info = new PreLoginInfo();
		info.nonce = jsonInfo.getString("nonce").trim();
		info.pcid = jsonInfo.getString("pcid").trim();
		info.pubkey = jsonInfo.getString("pubkey").trim();
		info.retcode = jsonInfo.getInt("retcode");
		info.rsakv = jsonInfo.getString("rsakv");
		info.servertime = jsonInfo.getLong("servertime");
		return info;
	}

	/**
	 * 
	 * @param client
	 * @return  返回的是Get会的Json结果的字符串，里面包含servertime和nonce等重要参数
	 * @throws ParseException
	 * @throws IOException
	 */
	private String getPreLoginInfo(HttpClient client) throws ParseException,
			IOException {
		//					  http://login.sina.com.cn/sso/prelogin.php?entry=weibo&
		//		   callback=sinaSSOController.preloginCallBack&su=
		//Y29tbWVudHN3ZWlibyU0MDE2My5jb20%3D&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.11)&_=1395664614805
		String preloginurl = "http://login.sina.com.cn/sso/prelogin.php?entry=weibo&"
				+ "callback=sinaSSOController.preloginCallBack&su="
				+ su
				+ "&rsakt=mod&client=ssologin.js(v1.4.11)"
				+ "&_="
				+ getCurrentTime();
	
		
		System.out.println("This is a test information" + su);

		HttpGet get = new HttpGet(preloginurl);

		HttpResponse response = client.execute(get);

		String getResp = EntityUtils.toString(response.getEntity());

		int firstLeftBracket = getResp.indexOf("(");
		int lastRightBracket = getResp.lastIndexOf(")");

		String jsonBody = getResp.substring(firstLeftBracket + 1,
				lastRightBracket);
	
		return jsonBody;

	}

	/**
	 * 对账户进行加密，得到Post参数su。。。username经过BASE64计算。
	 * @param email 账户
	 * @return 
	 */
	private String encodeUserName(String email) {
		email = email.replaceFirst("@", "%40");// MzM3MjQwNTUyJTQwcXEuY29t
		email = Base64.encodeBase64String(email.getBytes()).replaceAll("=",
				"%3D");
		return email;

	}

	private static String getCurrentTime() {
		long servertime = new Date().getTime();
		return String.valueOf(servertime);
	}

	public DefaultHttpClient getDhc() {
		return dhc;
	}

	public void setDhc(DefaultHttpClient dhc) {
		this.dhc = dhc;
	}

	public String getNonce() {
		return nonce;
	}

	public void setNonce(String nonce) {
		this.nonce = nonce;
	}

	public String getSu() {
		return su;
	}

	public void setSu(String su) {
		this.su = su;
	}

	public String getServertime() {
		return servertime;
	}

	public void setServertime(String servertime) {
		this.servertime = servertime;
	}

	public String getSp() {
		return sp;
	}

	public void setSp(String sp) {
		this.sp = sp;
	}

	public String getCookie() {
		return cookie;
	}

	public void setCookie(String cookie) {
		this.cookie = cookie;
	}

	public String getAccount() {
		return account;
	}

	public void setAccount(String account) {
		this.account = account;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public static void main(String[] args) throws HttpException, IOException,
			JSONException, LoginFailureException {
		DefaultHttpClient dhc = new DefaultHttpClient();
		WeiboLogin weiboLogin = new WeiboLogin("cnjswangheng66@yahoo.com.cn",
				"swarmhere", dhc);
		weiboLogin.try2Login();

		HttpResponse hr;
		try {
			//String uri = "http://weibo.com/u/2102235427";
			String uri = "http://weibo.com/u/3092799015";
			HttpGet get = new HttpGet(uri);
			get.addHeader("Cookie", weiboLogin.getCookie());
			hr = dhc.execute(get);
			HttpEntity httpEntity = hr.getEntity();
			InputStream inputStream = httpEntity.getContent();
			String tmp = EntityUtils.toString(httpEntity);
			FileWriter fw = new FileWriter(new File("resultLoginTest.html"));
			fw.write(tmp);
			fw.close();
			inputStream.close();
		} catch (ClientProtocolException e) {
			e.printStackTrace();
		} catch (IOException e) {
		}
	}


}
